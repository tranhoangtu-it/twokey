package pgguard

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
)

// startGuard runs a guard in front of up and returns its address.
func startGuard(t *testing.T, o Options) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if o.Logf == nil {
		o.Logf = t.Logf
	}
	srv := New(o)
	go func() { _ = srv.Serve(ln) }()
	return srv, ln.Addr().String()
}

// connect opens a client connection and completes the startup exchange.
func connect(t *testing.T, addr string) *pgClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := &pgClient{t: t, c: c, r: bufio.NewReader(c)}
	params := "user\x00agent\x00database\x00app\x00\x00"
	startup := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(startup[0:4], uint32(len(startup)))
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	copy(startup[8:], params)
	if _, err := c.Write(startup); err != nil {
		t.Fatal(err)
	}
	if got := p.until(); got != "RZ" {
		t.Fatalf("startup = %q", got)
	}
	return p
}

func denyingBroker() *approval.Broker {
	b := approval.NewBroker(5 * time.Second)
	b.AddNotifier(denyAll{b})
	return b
}

// TestReadMessageDoesNotTrustLength: a header claiming 60 MiB with no
// payload must not allocate 60 MiB.
func TestReadMessageDoesNotTrustLength(t *testing.T) {
	var hdr bytes.Buffer
	hdr.WriteByte('Q')
	_ = binary.Write(&hdr, binary.BigEndian, uint32(60<<20))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := readMessage(bufio.NewReader(&hdr), maxClientMessage)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated message must be an error")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes for a message that never arrived", grew)
	}
}

// TestDeniedParseKeepsBatchInOrder: a denied Parse in the middle of an
// extended-protocol batch must not desync the session: the server still
// sees the Sync, the client gets the earlier results, then the denial,
// then exactly one ReadyForQuery.
func TestDeniedParseKeepsBatchInOrder(t *testing.T) {
	up := startFakePostgres(t)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	p := connect(t, addr)

	p.send('P', "\x00SELECT 1\x00\x00\x00")
	p.send('B', "\x00\x00\x00\x00\x00\x00\x00\x00")
	p.send('E', "\x00\x00\x00\x00\x00")
	p.send('P', "\x00DROP TABLE users\x00\x00\x00")
	p.send('B', "\x00\x00\x00\x00\x00\x00\x00\x00")
	p.send('E', "\x00\x00\x00\x00\x00")
	p.send('S', "")
	if got := p.until(); got != "12CEZ" {
		t.Fatalf("batch with a denied Parse = %q, want 12CEZ", got)
	}
	p.send('Q', "SELECT 2\x00")
	if got := p.until(); got != "CZ" {
		t.Fatalf("session unusable after denial: %q", got)
	}
	for _, sql := range up.received() {
		if strings.Contains(sql, "DROP") {
			t.Fatalf("upstream received denied SQL %q", sql)
		}
	}
}

// TestDeniedQueryPipelinedKeepsOrder: a denied simple query pipelined
// behind a slow one is answered after it, not before.
func TestDeniedQueryPipelinedKeepsOrder(t *testing.T) {
	up := startFakePostgres(t)
	up.delay = 200 * time.Millisecond
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	p := connect(t, addr)

	p.send('Q', "SELECT slow\x00")
	p.send('Q', "DROP TABLE users\x00")
	if got := p.until() + p.until(); got != "CZEZ" {
		t.Fatalf("pipelined responses = %q, want CZEZ", got)
	}
}

type approveAll struct{ b *approval.Broker }

func (a approveAll) Notify(r approval.Request) {
	a.b.Resolve(r.ID, approval.Decision{Approved: true, By: "test", Reason: "approved in test"})
}
func (approveAll) Closed(approval.Request, approval.Decision) {}

// TestApprovedStatementRuns: after a human approves, the statement is
// forwarded unchanged and the session keeps working.
func TestApprovedStatementRuns(t *testing.T) {
	up := startFakePostgres(t)
	b := approval.NewBroker(5 * time.Second)
	b.AddNotifier(approveAll{b})
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: b})
	p := connect(t, addr)
	p.send('Q', "DROP TABLE users\x00")
	if got := p.until(); got != "CZ" {
		t.Fatalf("approved statement = %q, want CZ", got)
	}
	p.send('Q', "SELECT 1\x00")
	if got := p.until(); got != "CZ" {
		t.Fatalf("after approval: %q", got)
	}
	if got := up.received(); len(got) != 2 || got[0] != "DROP TABLE users" {
		t.Fatalf("upstream received %q", got)
	}
}

// closeRecorder never decides; it reports how holds ended.
type closeRecorder struct{ closed chan approval.Decision }

func (closeRecorder) Notify(approval.Request)                          {}
func (c closeRecorder) Closed(_ approval.Request, d approval.Decision) { c.closed <- d }

func TestHoldEndsWhenClientDisconnects(t *testing.T) {
	up := startFakePostgres(t)
	b := approval.NewBroker(time.Minute)
	rec := closeRecorder{closed: make(chan approval.Decision, 1)}
	b.AddNotifier(rec)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: b})
	p := connect(t, addr)
	p.send('Q', "DROP TABLE users\x00")
	time.Sleep(100 * time.Millisecond)
	p.c.Close()
	select {
	case d := <-rec.closed:
		if d.Approved || d.By != "client" {
			t.Fatalf("decision = %+v, want denied by client", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hold kept waiting for a human after the client left")
	}
}

// TestHandlerPanicDoesNotKillGuard: a crash in one connection (here a
// missing broker) closes that connection only.
func TestHandlerPanicDoesNotKillGuard(t *testing.T) {
	up := startFakePostgres(t)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: nil})
	p := connect(t, addr)
	p.send('Q', "DROP TABLE users\x00")
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.r.ReadByte(); err == nil {
		t.Fatal("crashed session should be closed")
	}
	q := connect(t, addr)
	q.send('Q', "SELECT 1\x00")
	if got := q.until(); got != "CZ" {
		t.Fatalf("guard unusable after a crashed session: %q", got)
	}
}

func TestIdleConnectionIsClosed(t *testing.T) {
	up := startFakePostgres(t)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker(), IdleTimeout: 200 * time.Millisecond})
	p := connect(t, addr)
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.r.ReadByte(); !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("idle connection was not closed")
		}
	}
}

func TestCloseEndsSessions(t *testing.T) {
	up := startFakePostgres(t)
	srv, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	p := connect(t, addr)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.r.ReadByte(); err == nil {
		t.Fatal("session survived Close")
	} else {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("session survived Close")
		}
	}
}

func TestStartupNegotiationIsBounded(t *testing.T) {
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl[0:4], 8)
	binary.BigEndian.PutUint32(ssl[4:8], sslRequestCode)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := client.Write(ssl); err != nil {
				return
			}
			if _, err := client.Read(make([]byte, 1)); err != nil {
				return
			}
		}
	}()
	if _, err := readStartup(server, bufio.NewReader(server)); err == nil {
		t.Fatal("endless SSLRequests must end the connection")
	}
	server.Close()
}

// TestLargeServerMessagePasses: Postgres sends rows up to 1 GiB; the
// client-side 64 MiB cap must not apply to them.
func TestLargeServerMessagePasses(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 65 MiB")
	}
	up := startFakePostgres(t)
	up.bigRow = maxClientMessage + 1<<20
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	p := connect(t, addr)
	p.send('Q', "SELECT big\x00")
	_ = p.c.SetReadDeadline(time.Now().Add(30 * time.Second))
	typ, err := p.r.ReadByte()
	if err != nil || typ != 'D' {
		t.Fatalf("first message %q, %v", typ, err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if n := int(binary.BigEndian.Uint32(hdr[:])) - 4; n != up.bigRow {
		t.Fatalf("row length %d, want %d", n, up.bigRow)
	}
	if _, err := io.CopyN(io.Discard, p.r, int64(up.bigRow)); err != nil {
		t.Fatal(err)
	}
	if got := p.until(); got != "CZ" {
		t.Fatalf("after the big row: %q", got)
	}
}
