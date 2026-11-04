package myguard

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
)

// greetingPacket is a v10 handshake advertising caps.
func greetingPacket(caps uint32) []byte {
	p := []byte{10}
	p = append(p, "9.6.0\x00"...)
	p = append(p, 1, 0, 0, 0)         // connection id
	p = append(p, make([]byte, 8)...) // auth data part 1
	p = append(p, 0)                  // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(caps))
	p = append(p, 0xff, 0x02, 0x00) // charset, status
	p = binary.LittleEndian.AppendUint16(p, uint16(caps>>16))
	p = append(p, 21)                  // auth data length
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, make([]byte, 13)...) // auth data part 2
	return append(p, "mysql_native_password\x00"...)
}

// handshakeResponse is a protocol-41 login with caps.
func handshakeResponse(caps uint32) []byte {
	p := binary.LittleEndian.AppendUint32(nil, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24) // max packet
	p = append(p, 0xff)                            // charset
	p = append(p, make([]byte, 23)...)
	p = append(p, "agent\x00"...)
	return append(p, 0)
}

func okPacket() []byte { return []byte{0x00, 0, 0, 2, 0, 0, 0} }

// fakeMySQL accepts logins and answers every command with OK, recording
// the login and the queries it receives.
type fakeMySQL struct {
	ln     net.Listener
	caps   uint32
	mu     sync.Mutex
	logins int
	sql    []string
}

func startFakeMySQL(t *testing.T, caps uint32) *fakeMySQL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMySQL{ln: ln, caps: caps}
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

func (f *fakeMySQL) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	if _, err := c.Write(packet(0, greetingPacket(f.caps))); err != nil {
		return
	}
	if _, _, err := readPacket(r); err != nil {
		return
	}
	f.mu.Lock()
	f.logins++
	f.mu.Unlock()
	_, _ = c.Write(packet(2, okPacket()))
	for {
		_, p, err := readPacket(r)
		if err != nil || len(p) == 0 || p[0] == comQuit {
			return
		}
		if p[0] == comQuery {
			f.mu.Lock()
			f.sql = append(f.sql, string(p[1:]))
			f.mu.Unlock()
		}
		_, _ = c.Write(packet(1, okPacket()))
	}
}

func (f *fakeMySQL) state() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, append([]string(nil), f.sql...)
}

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

type myClient struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func dialGuard(t *testing.T, addr string) (*myClient, uint32) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	m := &myClient{t: t, c: c, r: bufio.NewReader(c)}
	_, g := m.read()
	return m, greetingCaps(t, g)
}

func greetingCaps(t *testing.T, g []byte) uint32 {
	t.Helper()
	i := 1 + bytes.IndexByte(g[1:], 0) + 1 + 4 + 8 + 1
	return uint32(binary.LittleEndian.Uint16(g[i:])) | uint32(binary.LittleEndian.Uint16(g[i+5:]))<<16
}

func (m *myClient) read() (byte, []byte) {
	m.t.Helper()
	seq, p, err := readPacket(m.r)
	if err != nil {
		m.t.Fatalf("read: %v", err)
	}
	return seq, p
}

func (m *myClient) write(seq byte, p []byte) {
	m.t.Helper()
	if _, err := m.c.Write(packet(seq, p)); err != nil {
		m.t.Fatal(err)
	}
}

func (m *myClient) login() {
	m.t.Helper()
	m.write(1, handshakeResponse(clientProtocol41))
	if _, p := m.read(); p[0] != 0x00 {
		m.t.Fatalf("login answer %x", p)
	}
}

func (m *myClient) query(sql string) []byte {
	m.t.Helper()
	m.write(0, append([]byte{comQuery}, sql...))
	_, p := m.read()
	return p
}

func denyingBroker() *approval.Broker {
	b := approval.NewBroker(5 * time.Second)
	b.AddNotifier(denyAll{b})
	return b
}

type denyAll struct{ b *approval.Broker }

func (d denyAll) Notify(r approval.Request) {
	d.b.Resolve(r.ID, approval.Decision{By: "test", Reason: "denied in test"})
}
func (denyAll) Closed(approval.Request, approval.Decision) {}

// TestGreetingHidesCompressionAndTLS: compression would wrap every packet
// in a header the guard does not read, so the client must never see it
// offered (nor TLS, which would hide the SQL).
func TestGreetingHidesCompressionAndTLS(t *testing.T) {
	up := startFakeMySQL(t, 0xffffffff)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	_, caps := dialGuard(t, addr)
	for name, bit := range map[string]uint32{"CLIENT_SSL": clientSSL, "CLIENT_COMPRESS": clientCompress, "CLIENT_ZSTD_COMPRESSION_ALGORITHM": clientZstd} {
		if caps&bit != 0 {
			t.Errorf("greeting offers %s to the client", name)
		}
	}
	if caps&clientQueryAttributes == 0 {
		t.Error("other capabilities must pass through")
	}
}

// TestLoginRequestingCompressionOrTLSIsRefused: a client that asks for
// compression or TLS anyway is refused before the server sees the login.
func TestLoginRequestingCompressionOrTLSIsRefused(t *testing.T) {
	for name, bit := range map[string]uint32{"compress": clientCompress, "zstd": clientZstd, "ssl": clientSSL} {
		up := startFakeMySQL(t, 0xffffffff)
		_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
		m, _ := dialGuard(t, addr)
		m.write(1, handshakeResponse(clientProtocol41|bit))
		_, p := m.read()
		if p[0] != 0xff || !strings.Contains(string(p), "twokey") {
			t.Fatalf("%s: want a twokey ERR packet, got %q", name, p)
		}
		if _, _, err := readPacket(m.r); err == nil {
			t.Fatalf("%s: connection must be closed after the refusal", name)
		}
		if logins, _ := up.state(); logins != 0 {
			t.Fatalf("%s: the login reached the server", name)
		}
	}
}

func TestGuardHoldsDestructiveSQL(t *testing.T) {
	up := startFakeMySQL(t, 0xffffffff)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	m, _ := dialGuard(t, addr)
	m.login()
	if p := m.query("SELECT 1"); p[0] != 0x00 {
		t.Fatalf("safe query answer %x", p)
	}
	if p := m.query("/*!50000 DROP TABLE users */"); p[0] != 0xff {
		t.Fatalf("executable-comment DROP answer %x, want ERR", p)
	}
	if p := m.query("SELECT 2"); p[0] != 0x00 {
		t.Fatalf("session unusable after a denial: %x", p)
	}
	if _, sql := up.state(); len(sql) != 2 || strings.Contains(strings.Join(sql, " "), "DROP") {
		t.Fatalf("upstream received %q", sql)
	}
}

func TestReadPacketDoesNotTrustLength(t *testing.T) {
	hdr := []byte{0xff, 0xff, 0xff, 0}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := readPacket(bufio.NewReader(bytes.NewReader(hdr)))
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated packet must be an error")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes for a packet that never arrived", grew)
	}
}

type closeRecorder struct{ closed chan approval.Decision }

func (closeRecorder) Notify(approval.Request)                          {}
func (c closeRecorder) Closed(_ approval.Request, d approval.Decision) { c.closed <- d }

func TestHoldEndsWhenClientDisconnects(t *testing.T) {
	up := startFakeMySQL(t, 0xffffffff)
	b := approval.NewBroker(time.Minute)
	rec := closeRecorder{closed: make(chan approval.Decision, 1)}
	b.AddNotifier(rec)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: b})
	m, _ := dialGuard(t, addr)
	m.login()
	m.write(0, append([]byte{comQuery}, "TRUNCATE sessions"...))
	time.Sleep(100 * time.Millisecond)
	m.c.Close()
	select {
	case d := <-rec.closed:
		if d.Approved || d.By != "client" {
			t.Fatalf("decision = %+v, want denied by client", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hold kept waiting for a human after the client left")
	}
}

func TestHandlerPanicDoesNotKillGuard(t *testing.T) {
	up := startFakeMySQL(t, 0xffffffff)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: nil})
	m, _ := dialGuard(t, addr)
	m.login()
	m.write(0, append([]byte{comQuery}, "DROP TABLE users"...))
	if _, _, err := readPacket(m.r); err == nil {
		t.Fatal("crashed session should be closed")
	}
	n, _ := dialGuard(t, addr)
	n.login()
	if p := n.query("SELECT 1"); p[0] != 0x00 {
		t.Fatalf("guard unusable after a crashed session: %x", p)
	}
}

func TestIdleAndCloseEndSessions(t *testing.T) {
	up := startFakeMySQL(t, 0xffffffff)
	_, addr := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker(), IdleTimeout: 200 * time.Millisecond})
	m, _ := dialGuard(t, addr)
	m.login()
	if _, _, err := readPacket(m.r); err == nil || isTimeout(err) {
		t.Fatalf("idle session not closed: %v", err)
	}

	srv, addr2 := startGuard(t, Options{Upstream: up.ln.Addr().String(), Broker: denyingBroker()})
	n, _ := dialGuard(t, addr2)
	n.login()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(n.r); err == nil || isTimeout(err) {
		t.Fatalf("session survived Close: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() && !errors.Is(err, io.EOF)
}
