package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
		_ = tlsConn.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = tlsConn.SetReadDeadline(time.Time{})
		req.URL.Scheme = "https"
		req.URL.Host = target // dial the CONNECT target, never a spoofed Host header
		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			// We need the body to inspect it; don't make the client wait.
			req.Header.Del("Expect")
			if _, err := io.WriteString(tlsConn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		req = req.WithContext(ctx)
		if isUpgrade(req) {
			s.upgrade(tlsConn, br, req, host, target, clientWatcher(tlsConn, br, cancel))
			cancel()
			return
		}
		var body *eofTracker
		if req.Body != nil && req.Body != http.NoBody {
			body = newEOFTracker(req.Body, tlsConn)
			req.Body = body
		}
		resp := s.handle(req, host, clientWatcher(tlsConn, br, cancel))
		mustClose, err := writeResponse(tlsConn, req, resp)
		resp.Body.Close()
		cancel()
		// If the upstream answered before consuming the whole request body
		// (early 401/413 on an upload), the rest of that body is still in br
		// — and the transport may still be reading it. Never reuse the
		// connection then, or the leftover bytes become the "next request".
		if body != nil && !body.done() {
			lingerClose(tlsConn, br, body)
			return
		}
		if err != nil || mustClose || req.Close || resp.Close {
			return
		}
	}
}

// clientWatcher returns a function that, while a request is held, watches
// the client connection and cancels the request if the client goes away.
// The returned stop function must be called before anything else reads br.
func clientWatcher(conn net.Conn, br *bufio.Reader, cancel context.CancelFunc) func() (stop func()) {
	return func() func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if _, err := br.Peek(1); err != nil && !isTimeout(err) {
				cancel() // EOF / reset: nobody is waiting for this response
			}
		}()
		return func() {
			_ = conn.SetReadDeadline(time.Now()) // unblock Peek
			<-done
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isUpgrade(req *http.Request) bool {
	return req.Header.Get("Upgrade") != "" && connectionTokens(req.Header)["upgrade"]
}

// connectionTokens returns the lowercase tokens of every Connection header.
func connectionTokens(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" {
				out[tok] = true
			}
		}
	}
	return out
}

// upgrade handles WebSocket (and other Upgrade) requests on intercepted
// hosts: rules are checked on the handshake, then bytes are spliced.
func (s *Server) upgrade(client net.Conn, br *bufio.Reader, req *http.Request, host, target string, watch func() func()) {
	if resp := s.check(req, host, nil, watch); resp != nil {
		_, _ = writeResponse(client, req, resp)
		return
	}
	cfg := s.upstreamTLS.Clone()
	cfg.ServerName = host
	cfg.NextProtos = []string{"http/1.1"}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: cfg}
	upstream, err := dialer.DialContext(req.Context(), "tcp", target)
	if err != nil {
		_, _ = writeResponse(client, req, jsonResponse(req, http.StatusBadGateway, errorBody("twokey_upstream_error", err.Error())))
		return
	}
	defer upstream.Close()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""} // don't inject Go's default UA
	}
	if err := req.Write(upstream); err != nil {
		return
	}
	splice(client, br, upstream)
}
