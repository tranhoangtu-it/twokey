// Package proxy is twokey's HTTP(S) forward proxy. Hosts without rules are
// tunneled byte-for-byte (LLM API traffic is never touched); hosts with rules
// are TLS-intercepted so each request can be inspected and, if destructive,
// held until a human decides.
package proxy

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

const (
	// HealthPath answers `twokey run` / `twokey doctor` liveness checks.
	HealthPath = "/_twokey/health"
	// maxInspectBody caps how much of a body is buffered for inspection.
	maxInspectBody   = 32 << 20
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 15 * time.Second
	// idleTimeout closes intercepted keep-alive connections nobody uses.
	idleTimeout = 5 * time.Minute
	// bodyIdleTimeout drops request bodies that stop arriving mid-upload.
	bodyIdleTimeout = time.Minute
)

// Options configures a Server.
type Options struct {
	Engine  *rules.Engine
	CA      *ca.Authority
	Broker  *approval.Broker
	Audit   *audit.Log // optional
	Logf    func(string, ...any)
	Version string
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
	// UpstreamTLS configures raw TLS dials for Upgrade (WebSocket) requests.
	// Defaults to the system roots.
	UpstreamTLS *tls.Config
	// Allow pre-approves matching operations (never uninspectable ones).
	Allow []rules.Allow
}

// Server implements http.Handler for forward-proxy traffic.
type Server struct {
	engine      *rules.Engine
	ca          *ca.Authority
	broker      *approval.Broker
	audit       *audit.Log
	logf        func(string, ...any)
	version     string
	transport   http.RoundTripper
	upstreamTLS *tls.Config
	allow       []rules.Allow
}

// New builds a proxy server.
func New(o Options) *Server {
	s := &Server{
		engine: o.Engine, ca: o.CA, broker: o.Broker, audit: o.Audit,
		logf: o.Logf, version: o.Version, transport: o.Transport, upstreamTLS: o.UpstreamTLS,
		allow: o.Allow,
	}
	if s.upstreamTLS == nil {
		s.upstreamTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if s.logf == nil {
		s.logf = log.Printf
	}
	if s.transport == nil {
		s.transport = &http.Transport{
			Proxy:                 nil, // never chain to another proxy (or ourselves)
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   handshakeTimeout,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: time.Second,
			DisableCompression:    true, // pass encodings through untouched
		}
	}
	return s
}

// ServeHTTP dispatches CONNECT tunnels, plain-HTTP proxying and local endpoints.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	case r.URL.Host == "":
		s.handleLocal(w, r)
	default:
		s.handlePlain(w, r)
	}
}

func (s *Server) handleLocal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != HealthPath {
		http.Error(w, "this is the twokey proxy; point HTTPS_PROXY at it (see `twokey run`)", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "name": "twokey", "version": s.version, "pending": len(s.broker.Pending()),
	})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		// No port; also handles bare IPv6 literals like "[::1]".
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	client := &bufferedConn{Conn: conn, r: buf.Reader}
	if s.engine.HostWatched(target) {
		s.intercept(client, target)
	} else {
		s.tunnel(client, target)
	}
}

// tunnel splices bytes between client and target without looking at them.
func (s *Server) tunnel(client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	splice(client, client, upstream)
}

// splice copies both directions until both are done. A clean EOF on one
// side is forwarded as a half-close (CloseWrite) so the other direction can
// finish — e.g. a client that sends its request and shuts its write side
// still gets the full response. Errors tear down both sides.
func splice(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst net.Conn, src io.Reader, srcConn net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			srcConn.Close()
			return
		}
		closeWrite(dst)
	}
	go pipe(upstream, clientReader, client)
	go pipe(client, upstream, upstream)
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if bc, ok := c.(*bufferedConn); ok {
		c = bc.Conn
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		return
	}
	c.Close()
}
