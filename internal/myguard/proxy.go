// Package myguard is a MySQL wire-protocol proxy that holds destructive SQL
// (DROP, TRUNCATE, DELETE/UPDATE without WHERE, ALTER … DROP) until a human
// approves it.
package myguard

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
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

const (
	comQuit        = 0x01
	comQuery       = 0x03
	comStmtPrepare = 0x16
	clientSSL      = 0x0800
	// clientQueryAttributes (MySQL 8.0.23+): COM_QUERY payloads then start
	// with a parameter count and parameter-set count before the SQL text.
	clientQueryAttributes = 1 << 27
	// maxPayload marks a packet continued in the next one (16 MiB - 1).
	maxPayload = 0xffffff
	// errSpecificAccessDenied is ER_SPECIFIC_ACCESS_DENIED_ERROR.
	errSpecificAccessDenied = 1227
	errConnectionFailed     = 2003
	dialTimeout             = 15 * time.Second
	aliveProbe              = 50 * time.Millisecond
)

// Options configures a Server.
type Options struct {
	Upstream string // host:port of the real MySQL
	Broker   *approval.Broker
	Audit    *audit.Log
	Allow    []rules.Allow
	Logf     func(string, ...any)
	// UpstreamTLS encrypts the hop to the real MySQL (the local hop to the
	// agent stays plaintext so it can be inspected).
	UpstreamTLS bool
	TLSConfig   *tls.Config // verification settings for UpstreamTLS
}

// Server proxies client connections to Options.Upstream.
type Server struct {
	o     Options
	guard *sqlhold.Guard
}

// New builds a MySQL guard.
func New(o Options) *Server {
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	return &Server{o: o, guard: &sqlhold.Guard{
		Provider: "mysql", Broker: o.Broker, Audit: o.Audit, Allow: o.Allow, Logf: o.Logf,
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
	s          *Server
	client     net.Conn
	cr         *bufio.Reader
	upstream   net.Conn
	writeMu    sync.Mutex
	serverCaps uint32
	queryAttrs bool // CLIENT_QUERY_ATTRIBUTES negotiated
	sawLogin   bool
	// authShift: with upstream TLS our SSLRequest consumed one sequence
	// number, so during authentication upstream seq = client seq + 1.
	authShift atomic.Bool
}

func (s *Server) handle(client net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", s.o.Upstream, dialTimeout)
	if err != nil {
		s.o.Logf("mysql upstream %s: %v", s.o.Upstream, err)
		_, _ = client.Write(packet(0, errPacket(errConnectionFailed, "HY000", "twokey: cannot reach upstream MySQL: "+err.Error())))
		return
	}
	defer up.Close()
	ur := bufio.NewReader(up)
	// The server speaks first. Hide CLIENT_SSL so the local hop stays
	// plaintext and every command can be inspected.
	seq, greeting, err := readPacket(ur)
	if err != nil {
		return
	}
	serverCaps := clearSSLCapability(greeting)
	if s.o.UpstreamTLS && serverCaps&clientSSL == 0 {
		_, _ = client.Write(packet(seq, errPacket(errConnectionFailed, "HY000", "twokey: upstream MySQL does not support TLS (drop --upstream-tls)")))
		return
	}
	if _, err := client.Write(packet(seq, greeting)); err != nil {
		return
	}
	ss := &session{s: s, client: client, cr: bufio.NewReader(client), upstream: up, serverCaps: serverCaps}
	if s.o.UpstreamTLS {
		tc, err := ss.upgradeUpstream(up)
		if err != nil {
			s.o.Logf("mysql upstream TLS: %v", err)
			_, _ = client.Write(packet(2, errPacket(errConnectionFailed, "HY000", "twokey: TLS to upstream MySQL failed: "+err.Error())))
			return
		}
		ss.upstream, ur = tc, bufio.NewReader(tc)
	}
	go func() {
		ss.upstreamToClient(ur)
		client.Close()
	}()
	ss.clientToUpstream()
}

// upgradeUpstream reads the client's handshake response, sends the server
// an SSLRequest, switches to TLS and forwards the response inside it.
func (ss *session) upgradeUpstream(up net.Conn) (*tls.Conn, error) {
	seq, resp, err := readPacket(ss.cr)
	if err != nil {
		return nil, err
	}
	if seq != 1 || len(resp) < 32 {
		return nil, errors.New("unexpected handshake response (pre-4.1 clients are not supported)")
	}
	ss.recordLogin(resp)
	caps := binary.LittleEndian.Uint32(resp) | clientSSL
	sslRequest := make([]byte, 32) // caps, max packet, charset, 23-byte filler
	copy(sslRequest, resp[:9])
	binary.LittleEndian.PutUint32(sslRequest, caps)
	if _, err := up.Write(packet(1, sslRequest)); err != nil {
		return nil, err
	}
	cfg := ss.s.o.TLSConfig
	if cfg == nil {
		host, _, _ := net.SplitHostPort(ss.s.o.Upstream)
		cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	tc := tls.Client(up, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(resp, caps)
	if _, err := tc.Write(packet(2, resp)); err != nil {
		return nil, err
	}
	ss.authShift.Store(true)
	return tc, nil
}

// recordLogin notes what client and server agreed on in the handshake.
func (ss *session) recordLogin(resp []byte) {
	ss.sawLogin = true
	clientCaps := binary.LittleEndian.Uint32(resp)
	ss.queryAttrs = clientCaps&ss.serverCaps&clientQueryAttributes != 0
}

// clearSSLCapability unsets CLIENT_SSL in a v10 handshake packet (what the
// client sees) and returns the server's original capability flags.
func clearSSLCapability(p []byte) uint32 {
	if len(p) == 0 || p[0] != 10 {
		return 0 // error packet or unknown protocol: leave untouched
	}
	end := bytes.IndexByte(p[1:], 0)
	if end < 0 {
		return 0
	}
	i := 1 + end + 1 + 4 + 8 + 1 // version\0, connection id, auth data part 1, filler
	if i+2 > len(p) {
		return 0
	}
	lower := binary.LittleEndian.Uint16(p[i:])
	binary.LittleEndian.PutUint16(p[i:], lower&^clientSSL)
	caps := uint32(lower)
	if j := i + 2 + 1 + 2; j+2 <= len(p) { // charset, status flags, then upper caps
		caps |= uint32(binary.LittleEndian.Uint16(p[j:])) << 16
	}
	return caps
}

// queryText extracts the SQL from a COM_QUERY payload (after the command
// byte). With query attributes negotiated the text is preceded by
// lenenc(param_count) and lenenc(param_set_count); attributes themselves
// (param_count > 0) are not parsed, so such queries fail closed.
func queryText(body []byte, attrs bool) (string, error) {
	if !attrs {
		return string(body), nil
	}
	count, n, ok := lenencInt(body)
	if !ok {
		return "", errors.New("malformed query attributes")
	}
	if count != 0 {
		return "", errors.New("queries carrying query attributes cannot be inspected")
	}
	_, m, ok := lenencInt(body[n:])
	if !ok {
		return "", errors.New("malformed query attributes")
	}
	return string(body[n+m:]), nil
}

// lenencInt decodes a MySQL length-encoded integer.
func lenencInt(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3, true
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint64(b[1:]), 9, true
	case 0xfb, 0xff:
		return 0, 0, false
	default:
		return uint64(b[0]), 1, true
	}
}

func readPacket(r *bufio.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

func packet(seq byte, payload []byte) []byte {
	n := len(payload)
	out := make([]byte, 4+n)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), seq
	copy(out[4:], payload)
	return out
}

// errPacket builds an ERR_Packet (CLIENT_PROTOCOL_41 format).
func errPacket(code uint16, sqlState, msg string) []byte {
	var b bytes.Buffer
	b.WriteByte(0xff)
	_ = binary.Write(&b, binary.LittleEndian, code)
	b.WriteByte('#')
	b.WriteString(sqlState)
	b.WriteString(msg)
	return b.Bytes()
}

func (ss *session) writeClient(b []byte) error {
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	_, err := ss.client.Write(b)
	return err
}

// upstreamToClient relays whole packets so an injected ERR never lands in
// the middle of a server packet.
func (ss *session) upstreamToClient(r *bufio.Reader) {
	for {
		seq, payload, err := readPacket(r)
		if err != nil {
			return
		}
		if ss.authShift.Load() && seq > 0 {
			seq-- // undo the sequence number our SSLRequest used
		}
		if ss.writeClient(packet(seq, payload)) != nil {
			return
		}
	}
}

func (ss *session) clientToUpstream() {
	for {
		seq, payload, err := readPacket(ss.cr)
		if err != nil {
			return
		}
		if !ss.sawLogin && seq == 1 && len(payload) >= 4 {
			ss.recordLogin(payload) // handshake response (plaintext upstream)
		}
		fwdSeq := seq
		if ss.authShift.Load() {
			if seq == 0 {
				ss.authShift.Store(false) // command phase: sequences reset per command
			} else {
				fwdSeq = seq + 1
			}
		}
		// Every command starts a new sequence at 0; auth-phase packets
		// (handshake response, auth switch) have seq >= 1 and pass through.
		if seq == 0 && len(payload) > 0 && (payload[0] == comQuery || payload[0] == comStmtPrepare) {
			if denial := ss.check(payload); denial != "" {
				if ss.writeClient(packet(1, errPacket(errSpecificAccessDenied, "42000", denial))) != nil {
					return
				}
				continue
			}
		}
		if _, err := ss.upstream.Write(packet(fwdSeq, payload)); err != nil {
			return
		}
		if seq == 0 && len(payload) > 0 && payload[0] == comQuit {
			return
		}
	}
}

// check returns "" to forward the command, or the error message to return.
func (ss *session) check(payload []byte) string {
	if len(payload) == maxPayload {
		// A multi-packet statement (>= 16 MiB) cannot be inspected whole:
		// fail closed and swallow its continuation packets.
		for {
			_, cont, err := readPacket(ss.cr)
			if err != nil || len(cont) < maxPayload {
				break
			}
		}
		return "twokey: statement too large to inspect (>= 16 MiB) — " + sqlhold.Hint
	}
	sql := string(payload[1:])
	if payload[0] == comQuery {
		text, err := queryText(payload[1:], ss.queryAttrs)
		if err != nil {
			return "twokey: " + err.Error() + " — " + sqlhold.Hint
		}
		sql = text
	}
	target := "mysql://" + ss.s.o.Upstream
	msg := ss.s.guard.Check(sqlclass.ClassifyMySQL(sql), target, ss.clientAlive)
	if msg == "" {
		return ""
	}
	return msg + " — " + sqlhold.Hint
}

func (ss *session) clientAlive() bool {
	_ = ss.client.SetReadDeadline(time.Now().Add(aliveProbe))
	_, err := ss.cr.Peek(1)
	_ = ss.client.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || (errors.As(err, &ne) && ne.Timeout())
}
