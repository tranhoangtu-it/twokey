package proxy

import (
	"bufio"
	"bytes"
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

	lim := &headerLimiter{r: tlsConn}
	br := bufio.NewReader(lim)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(idleTimeout))
		lim.limit(maxHeaderBytes + 4096) // + one bufio fill of read-ahead, like net/http
		req, err := http.ReadRequest(br)
		lim.unlimit()
		if err != nil {
			if lim.exceeded {
				rejectHeaderTooLarge(tlsConn, br)
			}
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
			keepServing := s.upgrade(tlsConn, br, req, host, target, clientWatcher(tlsConn, br, cancel))
			cancel()
			if !keepServing {
				return
			}
			continue
		}
		var body *eofTracker
		if req.Body != nil && req.Body != http.NoBody {
			body = newEOFTracker(req.Body, tlsConn, s.bodyIdle)
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

// errHeaderTooLarge ends a request head that exceeds maxHeaderBytes.
var errHeaderTooLarge = errors.New("request header too large")

// headerLimiter caps how much http.ReadRequest may read for one request
// head; http.ReadRequest itself has no limit (unlike http.Server).
type headerLimiter struct {
	r        io.Reader
	n        int64
	limited  bool
	exceeded bool
}

func (l *headerLimiter) limit(n int64) { l.n, l.limited, l.exceeded = n, true, false }
func (l *headerLimiter) unlimit()      { l.limited = false }

func (l *headerLimiter) Read(p []byte) (int, error) {
	if !l.limited {
		return l.r.Read(p)
	}
	if l.n <= 0 {
		l.exceeded = true
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// rejectHeaderTooLarge answers 431 and closes without forwarding anything,
// lingering briefly so the unread rest of the request does not reset the
// connection before the client has read the answer.
func rejectHeaderTooLarge(conn *tls.Conn, br *bufio.Reader) {
	resp := jsonResponse(nil, http.StatusRequestHeaderFieldsTooLarge,
		errorBody("twokey_error", "request headers larger than twokey inspects"))
	resp.Close = true
	if err := resp.Write(conn); err != nil {
		return
	}
	_ = conn.CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(lingerWait))
	_, _ = io.Copy(io.Discard, io.LimitReader(br, lingerMaxBytes))
}

// clientWatcher returns a function that, while a request is held, watches
// the client connection and cancels the request if the client goes away.
// The returned stop function must be called before anything else reads br.
func clientWatcher(conn net.Conn, br *bufio.Reader, cancel context.CancelFunc) func() (stop func()) {
	return func() func() {
		// The body has been read by now; drop the per-read body deadline so
		// a hold longer than it still notices the client leaving.
		_ = conn.SetReadDeadline(time.Time{})
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
// hosts. The handshake is checked like any request; on hosts whose rules
// need the body (GraphQL, AWS, JSON) it is held, because messages after the
// upgrade are never inspected. Bytes are spliced only once the upstream
// answers 101. Otherwise the answer is relayed and keepServing reports
// whether the connection is still plain HTTP, so the caller goes on
// inspecting the requests that follow.
func (s *Server) upgrade(client *tls.Conn, br *bufio.Reader, req *http.Request, host, target string, watch func() func()) (keepServing bool) {
	reason := ""
	if s.engine.NeedsBody(host) {
		reason = "connection upgrade (e.g. WebSocket) to " + host +
			": messages sent after the handshake cannot be inspected"
	}
	if resp := s.check(req, host, nil, reason, watch); resp != nil {
		_, _ = writeResponse(client, req, resp)
		resp.Body.Close()
		return false
	}
	cfg := s.upstreamTLS.Clone()
	cfg.ServerName = host
	cfg.NextProtos = []string{"http/1.1"}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: cfg}
	upstream, err := dialer.DialContext(req.Context(), "tcp", target)
	if err != nil {
		_, _ = writeResponse(client, req, jsonResponse(req, http.StatusBadGateway, errorBody("twokey_upstream_error", err.Error())))
		return false
	}
	defer upstream.Close()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""} // don't inject Go's default UA
	}
	if err := req.Write(upstream); err != nil {
		return false
	}
	ubr := bufio.NewReader(upstream)
	resp, err := readFinalResponse(ubr, req)
	if err != nil {
		_, _ = writeResponse(client, req, jsonResponse(req, http.StatusBadGateway, errorBody("twokey_upstream_error", err.Error())))
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if writeSwitchingProtocols(client, resp) == nil {
			splice(client, br, &bufferedConn{Conn: upstream, r: ubr})
		}
		return false
	}
	resp.Header.Set("X-Twokey", "inspected")
	mustClose, err := writeResponse(client, req, resp)
	resp.Body.Close()
	return err == nil && !mustClose && !req.Close && !resp.Close
}

// readFinalResponse skips informational answers (100 Continue, 103 Early
// Hints) other than 101, which ends the HTTP exchange.
func readFinalResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, err
		}
	}
}

// writeSwitchingProtocols relays the upstream's 101 with its headers
// untouched (Upgrade, Connection and Sec-WebSocket-* must reach the client).
func writeSwitchingProtocols(w io.Writer, resp *http.Response) error {
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 " + resp.Status + "\r\n")
	if err := resp.Header.Write(&b); err != nil {
		return err
	}
	b.WriteString("\r\n")
	_, err := w.Write(b.Bytes())
	return err
}
