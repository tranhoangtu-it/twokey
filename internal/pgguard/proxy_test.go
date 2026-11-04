package pgguard

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
)

// fakePostgres speaks just enough of the backend protocol and records the
// SQL it receives. Like Postgres, a statement it cannot parse (the guard's
// substitute for a denied one) is a syntax error, and after an error in an
// extended-protocol batch it skips messages until Sync.
type fakePostgres struct {
	ln     net.Listener
	mu     sync.Mutex
	sql    []string
	delay  time.Duration // before answering a simple query
	bigRow int           // "SELECT big" returns a DataRow of this size
}

func syntaxError(sql string) []byte {
	return errorResponse("ERROR", "42601", `syntax error at or near "`+sql+`"`, "")
}

func startFakePostgres(t *testing.T) *fakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePostgres{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePostgres) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(r, make([]byte, binary.BigEndian.Uint32(hdr[:])-4)); err != nil {
		return
	}
	authOK := encodeMessage('R', []byte{0, 0, 0, 0})
	_, _ = c.Write(append(authOK, readyForQuery('I')...))
	failed := false // extended protocol: skip until Sync after an error
	for {
		typ, payload, err := readMessage(r, maxClientMessage)
		if err != nil {
			return
		}
		if failed && typ != 'S' {
			continue
		}
		switch typ {
		case 'Q':
			time.Sleep(f.delay)
			sql := cstring(payload)
			if sql == deniedSQL {
				_, _ = c.Write(append(syntaxError(sql), readyForQuery('I')...))
				continue
			}
			f.record(sql)
			if sql == "SELECT big" && f.bigRow > 0 {
				f.writeBigRow(c)
			}
			_, _ = c.Write(append(encodeMessage('C', []byte("OK\x00")), readyForQuery('I')...))
		case 'P':
			_, rest, _ := strings.Cut(string(payload), "\x00")
			if sql := cstring([]byte(rest)); sql == deniedSQL {
				_, _ = c.Write(syntaxError(sql))
				failed = true
			} else {
				f.record(sql)
				_, _ = c.Write(encodeMessage('1', nil))
			}
		case 'B':
			_, _ = c.Write(encodeMessage('2', nil))
		case 'E':
			_, _ = c.Write(encodeMessage('C', []byte("OK\x00")))
		case 'S':
			failed = false
			_, _ = c.Write(readyForQuery('I'))
		case 'X':
			return
		}
	}
}

func (f *fakePostgres) writeBigRow(c net.Conn) {
	hdr := make([]byte, 5)
	hdr[0] = 'D'
	binary.BigEndian.PutUint32(hdr[1:], uint32(4+f.bigRow))
	_, _ = c.Write(hdr)
	chunk := make([]byte, 1<<20)
	for left := f.bigRow; left > 0; left -= len(chunk) {
		_, _ = c.Write(chunk[:min(len(chunk), left)])
	}
}

func (f *fakePostgres) record(sql string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sql = append(f.sql, sql)
}

func (f *fakePostgres) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sql...)
}

type denyAll struct{ b *approval.Broker }

func (d denyAll) Notify(r approval.Request) {
	d.b.Resolve(r.ID, approval.Decision{By: "test", Reason: "denied in test"})
}
func (denyAll) Closed(approval.Request, approval.Decision) {}

type pgClient struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func (p *pgClient) send(typ byte, payload string) {
	p.t.Helper()
	if _, err := p.c.Write(encodeMessage(typ, []byte(payload))); err != nil {
		p.t.Fatal(err)
	}
}

// until reads messages up to and including ReadyForQuery, returning types.
func (p *pgClient) until() string {
	p.t.Helper()
	var types []byte
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		typ, _, err := readMessage(p.r, maxClientMessage)
		if err != nil {
			p.t.Fatalf("read: %v (got %q so far)", err, types)
		}
		types = append(types, typ)
		if typ == 'Z' {
			return string(types)
		}
	}
}

func TestGuardHoldsDestructiveSQL(t *testing.T) {
	up := startFakePostgres(t)
	broker := approval.NewBroker(5 * time.Second)
	broker.AddNotifier(denyAll{broker})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go New(Options{Upstream: up.ln.Addr().String(), Broker: broker, Logf: t.Logf}).Serve(ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := &pgClient{t: t, c: c, r: bufio.NewReader(c)}

	// SSLRequest is refused on the local hop, then a normal startup.
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl[0:4], 8)
	binary.BigEndian.PutUint32(ssl[4:8], sslRequestCode)
	_, _ = c.Write(ssl)
	if b, _ := p.r.ReadByte(); b != 'N' {
		t.Fatalf("SSLRequest answer = %q, want N", b)
	}
	params := "user\x00agent\x00database\x00app\x00\x00"
	startup := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(startup[0:4], uint32(len(startup)))
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	copy(startup[8:], params)
	_, _ = c.Write(startup)
	if got := p.until(); got != "RZ" {
		t.Fatalf("startup = %q", got)
	}

	p.send('Q', "SELECT 1\x00")
	if got := p.until(); got != "CZ" {
		t.Fatalf("safe query = %q", got)
	}
	p.send('Q', "DROP TABLE users\x00")
	if got := p.until(); got != "EZ" {
		t.Fatalf("denied simple query = %q, want error + ready", got)
	}
	// Extended protocol: Parse/Bind/Execute/Sync of a DROP is swallowed.
	p.send('P', "\x00TRUNCATE sessions\x00\x00\x00")
	p.send('B', "\x00\x00\x00\x00\x00\x00\x00\x00")
	p.send('E', "\x00\x00\x00\x00\x00")
	p.send('S', "")
	if got := p.until(); got != "EZ" {
		t.Fatalf("denied extended query = %q, want error + ready", got)
	}
	p.send('Q', "SELECT 2\x00")
	if got := p.until(); got != "CZ" {
		t.Fatalf("session unusable after denial: %q", got)
	}

	for _, sql := range up.received() {
		if strings.Contains(sql, "DROP") || strings.Contains(sql, "TRUNCATE") {
			t.Fatalf("upstream received denied SQL: %q", sql)
		}
	}
	if got := up.received(); len(got) != 2 {
		t.Fatalf("upstream should have seen exactly the 2 safe queries, got %q", got)
	}
}
