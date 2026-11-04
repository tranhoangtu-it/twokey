package pgguard

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/rules"
	"github.com/tranhoangtu-it/twokey/internal/sqlclass"
	"github.com/tranhoangtu-it/twokey/internal/sqlhold"
)

// Protocol constants (Postgres frontend/backend protocol v3).
const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102
	// maxClientMessage caps a message from the client (it is buffered to
	// be inspected); maxServerMessage is Postgres' own limit (streamed).
	maxClientMessage = 64 << 20
	maxServerMessage = 1 << 30
	// maxNegotiations bounds SSLRequest/GSSENCRequest rounds before startup.
	maxNegotiations  = 4
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 30 * time.Second
	// aliveProbe is how long we wait to see whether the client hung up.
	aliveProbe = 50 * time.Millisecond
	// DefaultIdleTimeout closes client connections that send nothing for
	// this long (MySQL's default wait_timeout).
	DefaultIdleTimeout = 8 * time.Hour
	// deniedSQL replaces a denied statement on its way upstream: the server
	// answers it with a syntax error in the right place of the response
	// stream (and handles Sync and transaction state itself), and the
	// guard rewrites that error into the denial.
	deniedSQL = "twokey_denied"
)

// Options configures a Server.
type Options struct {
	Upstream    string // host:port of the real Postgres
	UpstreamTLS bool   // negotiate TLS with the upstream (sslmode=require-like)
	Broker      *approval.Broker
	Audit       *audit.Log // optional
	Allow       []rules.Allow
	Logf        func(string, ...any)
	// TLSConfig overrides the upstream TLS config (tests).
	TLSConfig *tls.Config
	// IdleTimeout closes a client that sends nothing for this long
	// (DefaultIdleTimeout when zero).
	IdleTimeout time.Duration
}

// Server proxies client connections to Options.Upstream.
type Server struct {
	o     Options
	guard *sqlhold.Guard

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// New builds a Postgres guard.
func New(o Options) *Server {
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	return &Server{o: o, conns: map[net.Conn]struct{}{}, guard: &sqlhold.Guard{
		Provider: "postgres", Broker: o.Broker, Audit: o.Audit, Allow: o.Allow, Logf: o.Logf,
	}}
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// Close ends every open session (a held statement is then denied as
// "client went away"). Close the listener to stop Serve.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	return nil
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

// survive keeps a crash in one connection from killing the guard.
func (s *Server) survive() {
	if r := recover(); r != nil {
		s.o.Logf("postgres guard: connection closed after an internal error: %v", r)
	}
}

type session struct {
	s        *Server
	client   net.Conn
	cr       *bufio.Reader
	upstream net.Conn
	database string
	writeMu  sync.Mutex   // client writes: upstream copier + injected errors
	status   atomic.Value // last ReadyForQuery status byte ('I', 'T', 'E')

	// Denials in flight: the substituted statement's syntax error, in the
	// batch (Sync/Query) numbered batch, is replaced by msg. Batch 0 is the
	// startup exchange; batch k ends with the (k+1)-th ReadyForQuery.
	denyMu  sync.Mutex
	denials []denial
	sent    uint64 // number of the batch the client is sending, from 1
	ended   uint64 // ReadyForQuery messages seen from upstream
}

type denial struct {
	batch uint64
	msg   []byte
}

func (s *Server) handle(client net.Conn) {
	defer client.Close()
	defer s.survive()
	if !s.track(client) {
		return
	}
	defer s.untrack(client)
	cr := bufio.NewReader(client)
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	startup, err := readStartup(client, cr)
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	code := binary.BigEndian.Uint32(startup[4:8])
	up, err := s.dialUpstream()
	if err != nil {
		s.o.Logf("postgres upstream %s: %v", s.o.Upstream, err)
		_, _ = client.Write(errorResponse("FATAL", "08006", "twokey: cannot reach upstream Postgres: "+err.Error(), ""))
		return
	}
	defer up.Close()
	if _, err := up.Write(startup); err != nil || code == cancelRequestCode {
		return
	}
	sess := &session{s: s, client: client, cr: cr, upstream: up, database: startupParam(startup, "database"), sent: 1}
	sess.status.Store(byte('I'))
	go func() {
		defer s.survive()
		defer client.Close() // upstream gone: end the client side too
		sess.upstreamToClient(bufio.NewReader(up))
	}()
	sess.clientToUpstream()
}

// readStartup reads the first message, refusing SSL/GSS encryption on the
// local hop (the client connects to localhost) and returning the raw
// startup (or cancel) message to forward.
func readStartup(client net.Conn, r *bufio.Reader) ([]byte, error) {
	for round := 0; round <= maxNegotiations; round++ {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint32(hdr[:]))
		if n < 8 || n > 10000 {
			return nil, fmt.Errorf("bad startup length %d", n)
		}
		msg := make([]byte, n)
		copy(msg, hdr[:])
		if _, err := io.ReadFull(r, msg[4:]); err != nil {
			return nil, err
		}
		switch binary.BigEndian.Uint32(msg[4:8]) {
		case sslRequestCode, gssEncRequestCode:
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			continue
		}
		return msg, nil
	}
	return nil, errors.New("too many encryption requests before startup")
}

// startupParam extracts a parameter (e.g. "database") from a startup message.
func startupParam(msg []byte, key string) string {
	if len(msg) < 8 {
		return ""
	}
	parts := bytes.Split(msg[8:], []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		if string(parts[i]) == key {
			return string(parts[i+1])
		}
	}
	return ""
}

func (s *Server) dialUpstream() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", s.o.Upstream, dialTimeout)
	if err != nil || !s.o.UpstreamTLS {
		return conn, err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], sslRequestCode)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	var answer [1]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil || answer[0] != 'S' {
		conn.Close()
		return nil, errors.New("upstream does not accept TLS (drop --upstream-tls?)")
	}
	cfg := s.o.TLSConfig
	if cfg == nil {
		host, _, _ := net.SplitHostPort(s.o.Upstream)
		cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return tc, nil
}

// readHeader reads a message type and payload length (at most max).
func readHeader(r *bufio.Reader, max int) (byte, int, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 4 || n > max {
		return 0, 0, fmt.Errorf("bad message length %d", n)
	}
	return typ, n - 4, nil
}

// readMessage reads one typed protocol message: type, length, payload. The
// buffer grows with the bytes that actually arrive, never from the length
// field alone.
func readMessage(r *bufio.Reader, max int) (byte, []byte, error) {
	typ, n, err := readHeader(r, max)
	if err != nil {
		return 0, nil, err
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return 0, nil, err
	}
	return typ, buf.Bytes(), nil
}

func encodeMessage(typ byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func (ss *session) writeClient(b []byte) error {
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	_, err := ss.client.Write(b)
	return err
}

// upstreamToClient relays whole messages so injected errors never land in
// the middle of a server message, tracks the transaction status and turns
// the error for a substituted statement into the denial. Large messages
// (rows up to 1 GiB) are streamed, not buffered.
func (ss *session) upstreamToClient(r *bufio.Reader) {
	for {
		typ, n, err := readHeader(r, maxServerMessage)
		if err != nil {
			return
		}
		if typ == 'Z' || (typ == 'E' && n <= maxClientMessage) {
			var buf bytes.Buffer
			if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
				return
			}
			payload := buf.Bytes()
			if typ == 'Z' {
				if len(payload) == 1 {
					ss.status.Store(payload[0])
				}
				ss.batchEnded()
			} else if msg := ss.denialFor(payload); msg != nil {
				if ss.writeClient(msg) != nil {
					return
				}
				continue
			}
			if ss.writeClient(encodeMessage(typ, payload)) != nil {
				return
			}
			continue
		}
		if ss.stream(typ, n, r) != nil {
			return
		}
	}
}

// stream copies one message of n payload bytes to the client.
func (ss *session) stream(typ byte, n int, r io.Reader) error {
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(4+n))
	if _, err := ss.client.Write(hdr[:]); err != nil {
		return err
	}
	_, err := io.CopyN(ss.client, r, int64(n))
	return err
}

// denialFor returns the denial replacing an upstream ErrorResponse, or nil.
func (ss *session) denialFor(errPayload []byte) []byte {
	ss.denyMu.Lock()
	defer ss.denyMu.Unlock()
	if len(ss.denials) == 0 || ss.denials[0].batch != ss.ended || !bytes.Contains(errPayload, []byte(deniedSQL)) {
		return nil
	}
	msg := ss.denials[0].msg
	ss.denials = ss.denials[1:]
	return msg
}

// batchEnded records a ReadyForQuery and forgets denials of ended batches
// (a statement after an earlier error in its batch is never parsed).
func (ss *session) batchEnded() {
	ss.denyMu.Lock()
	defer ss.denyMu.Unlock()
	ss.ended++
	for len(ss.denials) > 0 && ss.denials[0].batch < ss.ended {
		ss.denials = ss.denials[1:]
	}
}

// deny records a denial for the current batch.
func (ss *session) deny(msg []byte) {
	ss.denyMu.Lock()
	defer ss.denyMu.Unlock()
	ss.denials = append(ss.denials, denial{batch: ss.sent, msg: msg})
}

func (ss *session) forwarded(typ byte) {
	if typ == 'Q' || typ == 'S' || typ == 'F' { // these end a batch with ReadyForQuery
		ss.denyMu.Lock()
		ss.sent++
		ss.denyMu.Unlock()
	}
}

func (ss *session) clientToUpstream() {
	for {
		_ = ss.client.SetReadDeadline(time.Now().Add(ss.s.o.IdleTimeout))
		typ, payload, err := readMessage(ss.cr, maxClientMessage)
		if err != nil {
			return
		}
		switch typ {
		case 'Q':
			if denied := ss.check(cstring(payload)); denied != nil {
				ss.deny(denied)
				payload = append([]byte(deniedSQL), 0)
			}
		case 'P':
			if name, rest, ok := bytes.Cut(payload, []byte{0}); ok {
				if denied := ss.check(cstring(rest)); denied != nil {
					ss.deny(denied)
					payload = append(append(append([]byte(nil), name...), 0), deniedSQL+"\x00\x00\x00"...)
				}
			}
		}
		if _, err := ss.upstream.Write(encodeMessage(typ, payload)); err != nil {
			return
		}
		ss.forwarded(typ)
		if typ == 'X' { // Terminate
			return
		}
	}
}

// check holds destructive SQL; it returns an ErrorResponse to send to the
// client when the statement must not run, or nil to forward it. While a
// statement is held the client connection is watched: if the client hangs
// up, the hold ends denied.
func (ss *session) check(sql string) []byte {
	findings := sqlclass.Classify(sql)
	if len(findings) == 0 {
		return nil
	}
	target := "postgres://" + ss.s.o.Upstream + "/" + ss.database
	ctx, stop := sqlhold.WatchClient(ss.client, ss.cr)
	defer stop()
	alive := func() bool {
		stop()
		return ctx.Err() == nil && ss.clientAlive()
	}
	msg := ss.s.guard.CheckContext(ctx, findings, target, alive)
	if msg == "" {
		return nil
	}
	return errorResponse("ERROR", "42501", msg, sqlhold.Hint)
}

// clientAlive reports whether the client is still connected (approving a
// statement for a client that already hung up must not run it).
func (ss *session) clientAlive() bool {
	_ = ss.client.SetReadDeadline(time.Now().Add(aliveProbe))
	_, err := ss.cr.Peek(1)
	_ = ss.client.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || (errors.As(err, &ne) && ne.Timeout())
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func readyForQuery(status byte) []byte { return encodeMessage('Z', []byte{status}) }

// errorResponse builds an ErrorResponse message.
func errorResponse(severity, code, message, hint string) []byte {
	var b bytes.Buffer
	field := func(t byte, v string) {
		b.WriteByte(t)
		b.WriteString(v)
		b.WriteByte(0)
	}
	field('S', severity)
	field('V', severity)
	field('C', code)
	field('M', message)
	if hint != "" {
		field('H', hint)
	}
	b.WriteByte(0)
	return encodeMessage('E', b.Bytes())
}
