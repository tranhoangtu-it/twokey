package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// handlePlain proxies absolute-form http:// requests. net/http cancels
// r.Context() when the client disconnects, so no watcher is needed.
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	resp := s.handle(r, r.URL.Hostname(), nil)
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
// watch (optional) starts monitoring the client while a request is held.
func (s *Server) handle(req *http.Request, host string, watch func() func()) *http.Response {
	if !s.engine.HostWatched(host) {
		return s.forward(req)
	}
	var body []byte
	if s.engine.NeedsBody(host) {
		b, errResp := bufferBody(req)
		if errResp != nil {
			return errResp
		}
		body = b
	}
	if resp := s.check(req, host, body, "", watch); resp != nil {
		return resp
	}
	return s.forward(req)
}

// check evaluates req and, if it is destructive, holds it for a human.
// It returns nil when the request may proceed, else the response to send.
// uninspectable, when set, forces a hold for that reason (e.g. an upgrade
// whose later messages the rules cannot see).
func (s *Server) check(req *http.Request, host string, body []byte, uninspectable string, watch func() func()) *http.Response {
	evalBody, decErr := decodeForInspection(req.Header.Get("Content-Encoding"), body)
	v := s.engine.Evaluate(rules.Request{
		Method: req.Method, Host: host, Path: req.URL.Path, Query: req.URL.RawQuery,
		Header: req.Header, Body: evalBody,
	})
	if decErr != nil && s.engine.NeedsBody(host) {
		// Whatever else matched: the body rules never saw this body, so
		// neither an allow rule nor a grant may wave it through.
		uninspectable = "request body could not be decoded for inspection: " + decErr.Error()
	}
	if uninspectable != "" && v.Uninspectable == "" {
		v.Uninspectable = uninspectable
	}
	v, allowed := rules.ApplyAllow(v, s.allow)
	if len(allowed) > 0 {
		if err := s.audit.Write(audit.Entry{
			Time: time.Now(), Method: req.Method, URL: displayURL(req), Matches: allowed,
			Approved: true, By: "allowlist", Reason: "pre-approved by allow rules",
		}); err != nil {
			s.logf("audit log write failed: %v", err)
		}
	}
	if !v.Hold() {
		return nil
	}
	if body == nil {
		// Consume the body now so the client watcher is the only reader.
		b, errResp := bufferBody(req)
		if errResp != nil {
			return errResp
		}
		if evalBody, decErr = decodeForInspection(req.Header.Get("Content-Encoding"), b); decErr != nil {
			evalBody = b
		}
	}
	stop := func() {}
	if watch != nil {
		stop = watch()
	}
	held, d := s.broker.Decide(req.Context(), approval.Request{
		Method: req.Method, URL: displayURL(req), Matches: v.Matches, Uninspectable: v.Uninspectable,
		// Timed grants bind to the exact payload, not just method + URL.
		Fingerprint: approval.BodyFingerprint(evalBody, req.URL.RawQuery),
	})
	stop()
	if d.Approved && req.Context().Err() != nil {
		// Approved, but the requester is gone: never fire an orphaned request.
		d = approval.Decision{By: "client", Reason: "client disconnected before the decision"}
	}
	if err := s.audit.Write(audit.Entry{
		Time: time.Now(), ID: held.ID, Method: held.Method, URL: held.URL, Matches: held.Matches,
		Uninspectable: held.Uninspectable, Approved: d.Approved, By: d.By, Reason: d.Reason,
	}); err != nil {
		s.logf("audit log write failed: %v", err)
	}
	if !d.Approved {
		return blockedResponse(req, held, d)
	}
	return nil
}

// decodeForInspection undoes Content-Encoding so rules see the real body;
// the original bytes are what gets forwarded.
func decodeForInspection(encoding string, body []byte) ([]byte, error) {
	var r io.ReadCloser
	var err error
	if len(body) == 0 {
		return body, nil // nothing to decode (e.g. empty body with Content-Encoding)
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		r, err = zlib.NewReader(bytes.NewReader(body))
	default:
		return body, fmt.Errorf("unsupported Content-Encoding %q", encoding)
	}
	if err != nil {
		return body, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxInspectBody+1))
	if err != nil {
		return body, err
	}
	if len(out) > maxInspectBody {
		return body, errors.New("decoded body too large")
	}
	return out, nil
}

// bufferBody reads the whole request body (capped) and replaces it with an
// in-memory copy so it can be both inspected and forwarded.
func bufferBody(req *http.Request) ([]byte, *http.Response) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxInspectBody+1))
	req.Body.Close()
	if err != nil {
		return nil, jsonResponse(req, http.StatusBadRequest, errorBody("twokey_error", "reading request body: "+err.Error()))
	}
	if len(b) > maxInspectBody {
		return nil, jsonResponse(req, http.StatusRequestEntityTooLarge, errorBody("twokey_error", "request body too large for twokey to inspect"))
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.ContentLength = int64(len(b))
	return b, nil
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
