// Package proxy is twokey's HTTP(S) forward proxy. Hosts without rules are
// tunneled byte-for-byte (LLM API traffic is never touched); hosts with rules
// are TLS-intercepted so each request can be inspected and, if destructive,
// held until a human decides.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
}

// Server implements http.Handler for forward-proxy traffic.
type Server struct {
	engine    *rules.Engine
	ca        *ca.Authority
	broker    *approval.Broker
	audit     *audit.Log
	logf      func(string, ...any)
	version   string
	transport http.RoundTripper
}

// New builds a proxy server.
func New(o Options) *Server {
	s := &Server{
		engine: o.Engine, ca: o.CA, broker: o.Broker, audit: o.Audit,
		logf: o.Logf, version: o.Version, transport: o.Transport,
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
		target = net.JoinHostPort(target, "443")
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
	var once sync.Once
	done := make(chan struct{})
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		once.Do(func() { close(done) })
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}

// intercept terminates TLS with a twokey-minted certificate and serves the
// client's HTTP/1.1 requests one by one through handle().
func (s *Server) intercept(client net.Conn, target string) {
	defer client.Close()
	host, _, _ := net.SplitHostPort(target)
	leaf, err := s.ca.LeafFor(host)
	if err != nil {
		s.logf("mint certificate for %s: %v", host, err)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.logf("TLS handshake for %s failed: %v — does this program trust the twokey CA? run `twokey run -- twokey doctor`", host, err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = target // dial the CONNECT target, never a spoofed Host header
		resp := s.handle(req, host)
		keepAlive := !req.Close && !resp.Close
		err = writeResponse(tlsConn, req, resp)
		resp.Body.Close()
		if err != nil || !keepAlive {
			return
		}
	}
}

// handlePlain proxies absolute-form http:// requests.
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	resp := s.handle(r, r.URL.Hostname())
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(flushWriter{w}, resp.Body)
}

// handle inspects one request and returns the response to send back.
func (s *Server) handle(req *http.Request, host string) *http.Response {
	if !s.engine.HostWatched(host) {
		return s.forward(req)
	}
	var body []byte
	if s.engine.NeedsBody(host) && req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxInspectBody+1))
		req.Body.Close()
		if err != nil {
			return jsonResponse(req, http.StatusBadRequest, errorBody("twokey_error", "reading request body: "+err.Error()))
		}
		if len(b) > maxInspectBody {
			return jsonResponse(req, http.StatusRequestEntityTooLarge, errorBody("twokey_error", "request body too large for twokey to inspect"))
		}
		body = b
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.ContentLength = int64(len(b))
	}

	v := s.engine.Evaluate(rules.Request{
		Method: req.Method, Host: host, Path: req.URL.Path, Query: req.URL.RawQuery,
		Header: req.Header, Body: body,
	})
	if v.Hold() {
		held, d := s.broker.Decide(req.Context(), approval.Request{
			Method: req.Method, URL: displayURL(req), Matches: v.Matches, Uninspectable: v.Uninspectable,
		})
		if err := s.audit.Write(audit.Entry{
			Time: time.Now(), ID: held.ID, Method: held.Method, URL: held.URL, Matches: held.Matches,
			Uninspectable: held.Uninspectable, Approved: d.Approved, By: d.By, Reason: d.Reason,
		}); err != nil {
			s.logf("audit log write failed: %v", err)
		}
		if !d.Approved {
			return blockedResponse(req, held, d)
		}
	}
	return s.forward(req)
}

func (s *Server) forward(req *http.Request) *http.Response {
	out := req.Clone(req.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		return jsonResponse(req, http.StatusBadGateway, errorBody("twokey_upstream_error", err.Error()))
	}
	resp.Header.Set("X-Twokey", "inspected")
	return resp
}

// displayURL omits the query string, which may carry signatures or tokens.
func displayURL(req *http.Request) string {
	return req.URL.Scheme + "://" + req.URL.Hostname() + req.URL.EscapedPath()
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// writeResponse serializes resp as HTTP/1.1 on the intercepted connection,
// whatever protocol was used upstream (often HTTP/2).
func writeResponse(w io.Writer, req *http.Request, resp *http.Response) error {
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	removeHopHeaders(resp.Header)
	bodyAllowed := req.Method != http.MethodHead &&
		resp.StatusCode >= 200 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified
	resp.TransferEncoding = nil
	if bodyAllowed && resp.ContentLength < 0 {
		resp.TransferEncoding = []string{"chunked"} // stream (e.g. SSE) without closing
	}
	return resp.Write(w)
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// bufferedConn replays bytes the HTTP server already buffered after CONNECT
// (a client may send its TLS ClientHello without waiting for our 200).
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ---- agent-facing responses ------------------------------------------------

// agentInstructions is written for the LLM that will read the 403.
const agentInstructions = "Do not retry, rephrase, or work around this request (no other tool, endpoint, or credential). " +
	"Tell the user exactly what you tried to do and why, and ask them to approve it in the twokey window or run it themselves."

func blockedResponse(req *http.Request, held approval.Request, d approval.Decision) *http.Response {
	outcome := "denied by a human"
	if d.By == "timeout" {
		outcome = "not approved in time"
	}
	msg := fmt.Sprintf("twokey blocked a destructive request (%s): %s. %s", outcome, held.Summary(), agentInstructions)
	body := map[string]any{
		"error": map[string]any{
			"type":          "twokey_blocked",
			"message":       msg,
			"hold":          held.ID,
			"decided_by":    d.By,
			"reason":        d.Reason,
			"matches":       held.Matches,
			"uninspectable": held.Uninspectable,
		},
		// GraphQL clients (e.g. the Railway CLI) surface errors[].message.
		"errors": []map[string]string{{"message": msg}},
	}
	resp := jsonResponse(req, http.StatusForbidden, body)
	resp.Header.Set("X-Twokey", "blocked")
	return resp
}

func errorBody(kind, msg string) map[string]any {
	return map[string]any{"error": map[string]any{"type": kind, "message": "twokey: " + msg}}
}

func jsonResponse(req *http.Request, status int, v any) *http.Response {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte(`{"error":{"type":"twokey_error","message":"twokey: failed to encode response"}}`)
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		Request:       req,
	}
}
