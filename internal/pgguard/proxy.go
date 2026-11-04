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
	maxMessage        = 64 << 20
	dialTimeout       = 15 * time.Second
	// aliveProbe is how long we wait to see whether the client hung up.
	aliveProbe = 50 * time.Millisecond
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
}

// Server proxies client connections to Options.Upstream.
type Server struct {
	o     Options
	guard *sqlhold.Guard
}

// New builds a Postgres guard.
func New(o Options) *Server {
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	return &Server{o: o, guard: &sqlhold.Guard{
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

type session struct {
	s        *Server
	client   net.Conn
	cr       *bufio.Reader
	upstream net.Conn
	database string
	writeMu  sync.Mutex   // client writes: upstream copier + injected errors
	status   atomic.Value // last ReadyForQuery status byte ('I', 'T', 'E')
}

func (s *Server) handle(client net.Conn) {
	defer client.Close()
	cr := bufio.NewReader(client)
	startup, err := readStartup(client, cr)
	if err != nil {
		return
	}
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
	sess := &session{s: s, client: client, cr: cr, upstream: up, database: startupParam(startup, "database")}
	sess.status.Store(byte('I'))
	go func() {
		sess.upstreamToClient(bufio.NewReader(up))
		client.Close() // upstream gone: end the client side too
	}()
	sess.clientToUpstream()
}

// readStartup reads the first message, refusing SSL/GSS encryption on the
// local hop (the client connects to localhost) and returning the raw
// startup (or cancel) message to forward.
func readStartup(client net.Conn, r *bufio.Reader) ([]byte, error) {
	for {
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
	return tc, nil
}

// readMessage reads one typed protocol message: type, length, payload.
func readMessage(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 4 || n > maxMessage {
		return 0, nil, fmt.Errorf("bad message length %d", n)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
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
// the middle of a server message, and tracks the transaction status.
// It starts after the startup message, where everything is typed.
func (ss *session) upstreamToClient(r *bufio.Reader) {
	for {
		typ, payload, err := readMessage(r)
		if err != nil {
			return
		}
		if typ == 'Z' && len(payload) == 1 {
			ss.status.Store(payload[0])
		}
		if err := ss.writeClient(encodeMessage(typ, payload)); err != nil {
			return
		}
	}
}

func (ss *session) clientToUpstream() {
	skipUntilSync := false
	for {
		typ, payload, err := readMessage(ss.cr)
		if err != nil {
			return
		}
		if skipUntilSync {
			// Extended protocol after a denied Parse: the server never saw
			// it, so swallow the batch and end it like the server would.
			if typ == 'S' {
				skipUntilSync = false
				if ss.writeClient(readyForQuery(ss.status.Load().(byte))) != nil {
					return
				}
			}
			continue
		}
		var sql string
		switch typ {
		case 'Q':
			sql = cstring(payload)
		case 'P':
			if _, rest, ok := bytes.Cut(payload, []byte{0}); ok {
				sql = cstring(rest)
			}
		}
		if sql != "" {
			if denied := ss.check(sql); denied != nil {
				if ss.writeClient(denied) != nil {
					return
				}
				if typ == 'Q' {
					if ss.writeClient(readyForQuery(ss.status.Load().(byte))) != nil {
						return
					}
				} else {
					skipUntilSync = true
				}
				continue
			}
		}
		if _, err := ss.upstream.Write(encodeMessage(typ, payload)); err != nil {
			return
		}
		if typ == 'X' { // Terminate
			return
		}
	}
}

// check holds destructive SQL; it returns an ErrorResponse to send to the
// client when the statement must not run, or nil to forward it.
func (ss *session) check(sql string) []byte {
	target := "postgres://" + ss.s.o.Upstream + "/" + ss.database
	msg := ss.s.guard.Check(sqlclass.Classify(sql), target, ss.clientAlive)
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
