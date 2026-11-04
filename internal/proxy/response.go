package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
)

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// removeHopHeaders strips hop-by-hop headers, including any header named in
// a Connection header (RFC 9110 §7.6.1).
func removeHopHeaders(h http.Header) {
	for tok := range connectionTokens(h) {
		h.Del(tok)
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// writeResponse serializes resp as HTTP/1.1 on the intercepted connection,
// whatever protocol was used upstream (often HTTP/2). mustClose reports that
// the connection cannot be reused after this response.
func writeResponse(w io.Writer, req *http.Request, resp *http.Response) (mustClose bool, err error) {
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	removeHopHeaders(resp.Header)
	resp.TransferEncoding = nil
	switch {
	case req.Method == http.MethodHead:
		// Content-Length (if known) is echoed, no body is sent. With an
		// unknown length Go announces "Connection: close"; honour it.
		mustClose = resp.ContentLength < 0
	case resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified:
		// These never carry a body, whatever Content-Length upstream sent.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		resp.Body = http.NoBody
		resp.ContentLength = 0
	case resp.ContentLength < 0:
		resp.TransferEncoding = []string{"chunked"} // stream (e.g. SSE) without closing
	}
	resp.Close = resp.Close || mustClose
	return resp.Close, resp.Write(w)
}

// eofTracker records whether a request body was read to the end, and when
// its consumer (the upstream transport) is finished with it.
type eofTracker struct {
	io.ReadCloser
	conn      net.Conn // optional: extended deadline per read (stalled uploads)
	idle      time.Duration
	eof       atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}
}

func newEOFTracker(rc io.ReadCloser, conn net.Conn, idle time.Duration) *eofTracker {
	return &eofTracker{ReadCloser: rc, conn: conn, idle: idle, closed: make(chan struct{})}
}

func (t *eofTracker) Read(p []byte) (int, error) {
	if t.conn != nil {
		// Activity-based: a long upload is fine, a silent one is dropped.
		_ = t.conn.SetReadDeadline(time.Now().Add(t.idle))
	}
	n, err := t.ReadCloser.Read(p)
	if err == io.EOF {
		t.eof.Store(true)
	}
	return n, err
}

// Close signals only after the underlying Close returns: for bodies from
// http.ReadRequest, Close itself drains the rest of the body from br, so
// nobody else may touch br until it is done.
func (t *eofTracker) Close() error {
	err := t.ReadCloser.Close()
	t.closeOnce.Do(func() { close(t.closed) })
	return err
}

func (t *eofTracker) done() bool { return t.eof.Load() }

const (
	lingerWait     = 2 * time.Second
	lingerMaxBytes = 16 << 20
)

// lingerClose ends a connection whose request body was not fully read
// without losing the response we just wrote: closing a socket with unread
// input makes the OS send RST, which can destroy the response in flight.
// So: wait until the transport is done with the body (it is the only other
// reader of br), half-close our side, then discard what's left for a while.
func lingerClose(conn *tls.Conn, br *bufio.Reader, body *eofTracker) {
	select {
	case <-body.closed:
	case <-time.After(lingerWait):
		return // transport still reading br: don't race it, just close
	}
	_ = conn.CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(lingerWait))
	_, _ = io.Copy(io.Discard, io.LimitReader(br, lingerMaxBytes))
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

// blockedOutcome says why a held request was not approved, so the agent
// (and its user) are not told a human denied what no human ever saw.
func blockedOutcome(d approval.Decision) string {
	switch d.By {
	case "timeout":
		return "not approved in time"
	case "overload":
		return "not queued for approval: too many requests are already waiting for a human"
	case "shutdown":
		return "twokey shut down before a human decided"
	case "client":
		return "the client disconnected before a human decided"
	default:
		return "denied by a human"
	}
}

func blockedResponse(req *http.Request, held approval.Request, d approval.Decision) *http.Response {
	msg := fmt.Sprintf("twokey blocked a destructive request (%s): %s. %s", blockedOutcome(d), held.Summary(), agentInstructions)
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
	// The request body may be unread; don't reuse the connection.
	resp.Close = true
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
