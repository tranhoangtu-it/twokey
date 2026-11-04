package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// autoDecider plays the human: approves or denies every hold immediately,
// or (manual mode) hands the hold to the test via the held channel.
type autoDecider struct {
	broker  *approval.Broker
	approve atomic.Bool
	manual  atomic.Bool
	holds   atomic.Int32
	held    chan approval.Request
}

func (a *autoDecider) Notify(r approval.Request) {
	a.holds.Add(1)
	if a.manual.Load() {
		a.held <- r
		return
	}
	a.broker.Resolve(r.ID, approval.Decision{Approved: a.approve.Load(), By: "test", Reason: "auto"})
}
func (a *autoDecider) Closed(approval.Request, approval.Decision) {}

type harness struct {
	upstream     *httptest.Server
	upstreamHits atomic.Int32
	proxyURL     *url.URL
	decider      *autoDecider
	broker       *approval.Broker
	roots        *x509.CertPool
}

// rawTLS opens CONNECT + TLS through the proxy by hand, like an agent's
// HTTP client would, and returns the encrypted stream to the upstream.
func (h *harness) rawTLS(t *testing.T) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	target := h.upstream.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %v", err, resp)
	}
	tc := tls.Client(conn, &tls.Config{RootCAs: h.roots, ServerName: "127.0.0.1"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS through proxy: %v", err)
	}
	t.Cleanup(func() { tc.Close() })
	return tc, bufio.NewReader(tc)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

const testPack = `
provider: test
rules:
  - id: test.repo.delete
    hosts: ["127.0.0.1"]
    methods: [DELETE]
    path: /repos/{owner}/{repo}
    resource: "{owner}/{repo}"
    severity: critical
  - id: test.volume.delete
    hosts: ["127.0.0.1"]
    path: /graphql
    graphql: { mutations: [volumeDelete] }
    resource: "{volumeId}"
    severity: critical
`

func newHarness(t *testing.T) *harness { return newHarnessWith(t, testPack) }

func newHarnessWith(t *testing.T, packYAML string) *harness {
	t.Helper()
	h := &harness{}
	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.upstreamHits.Add(1)
		switch r.URL.Path {
		case "/early": // reject an upload without reading it
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		case "/304":
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusNotModified)
			return
		case "/echo-x-foo":
			w.Header().Set("Got-X-Foo", r.Header.Get("X-Foo"))
			return
		}
		if r.Header.Get("Upgrade") == "websocket" {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_, _ = io.Copy(conn, buf) // echo
			return
		}
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "upstream says hi")
	}))
	h.upstream.EnableHTTP2 = false
	t.Cleanup(h.upstream.Close)

	pack, err := rules.ParsePack([]byte(packYAML))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.NewEngine([]rules.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	broker := approval.NewBroker(5 * time.Second)
	h.broker = broker
	h.decider = &autoDecider{broker: broker, held: make(chan approval.Request, 4)}
	broker.AddNotifier(h.decider)

	upstreamTransport := h.upstream.Client().Transport.(*http.Transport)
	srv := New(Options{
		Engine: engine, CA: authority, Broker: broker, Logf: t.Logf, Version: "test",
		Transport:   upstreamTransport, // trusts the upstream's test cert
		UpstreamTLS: upstreamTransport.TLSClientConfig,
	})
	front := httptest.NewServer(srv)
	t.Cleanup(front.Close)
	h.proxyURL, _ = url.Parse(front.URL)

	// The agent's view: trusts public roots (here: the upstream cert) + twokey CA.
	h.roots = x509.NewCertPool()
	h.roots.AppendCertsFromPEM(authority.CertPEM())
	h.roots.AddCert(h.upstream.Certificate())
	return h
}

func (h *harness) client(serverName string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(h.proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: h.roots, ServerName: serverName},
	}}
}

func (h *harness) do(t *testing.T, method, path, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, h.upstream.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client("").Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func TestSafeRequestPassesThroughInterception(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/repos/acme/api", "")
	if resp.StatusCode != 200 || body != "upstream says hi" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Twokey") != "inspected" {
		t.Fatal("watched host should be intercepted and marked inspected")
	}
	if h.decider.holds.Load() != 0 {
		t.Fatal("safe request must not be held")
	}
}

func TestDeniedDestructiveRequestNeverReachesUpstream(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "DELETE", "/repos/acme/api", "")
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Twokey") != "blocked" {
		t.Fatalf("want 403 blocked, got %d %v", resp.StatusCode, resp.Header)
	}
	if h.upstreamHits.Load() != 0 {
		t.Fatal("denied request reached upstream")
	}
	var parsed struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		Errors []struct{ Message string } `json:"errors"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("blocked body is not JSON: %v\n%s", err, body)
	}
	if parsed.Error.Type != "twokey_blocked" || !strings.Contains(parsed.Error.Message, "acme/api") ||
		len(parsed.Errors) != 1 || !strings.Contains(parsed.Error.Message, "Do not retry") {
		t.Fatalf("unexpected blocked body: %s", body)
	}
}

func TestPlainHTTPDestructiveRequestIsHeld(t *testing.T) {
	h := newHarness(t)
	target := "http://" + h.upstream.Listener.Addr().String() + "/repos/acme/api"
	req, _ := http.NewRequest("DELETE", target, nil)
	resp, err := h.client("").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Twokey") != "blocked" {
		t.Fatalf("want 403 blocked, got %d %v", resp.StatusCode, resp.Header)
	}
	if h.decider.holds.Load() != 1 || h.upstreamHits.Load() != 0 {
		t.Fatalf("holds=%d upstreamHits=%d", h.decider.holds.Load(), h.upstreamHits.Load())
	}
}

func TestApprovedDestructiveRequestIsForwarded(t *testing.T) {
	h := newHarness(t)
	h.decider.approve.Store(true)
	resp, body := h.do(t, "DELETE", "/repos/acme/api", "")
	if resp.StatusCode != 200 || body != "upstream says hi" || h.upstreamHits.Load() != 1 {
		t.Fatalf("got %d %q hits=%d", resp.StatusCode, body, h.upstreamHits.Load())
	}
	if h.decider.holds.Load() != 1 {
		t.Fatal("request should have been held exactly once")
	}
}

func TestGraphQLMutationIsHeld(t *testing.T) {
	h := newHarness(t)
	q := `{"query":"mutation($v: String!) { volumeDelete(volumeId: $v) }","variables":{"v":"pg-data-prod"}}`
	resp, body := h.do(t, "POST", "/graphql", q)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "pg-data-prod") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	resp, _ = h.do(t, "POST", "/graphql", `{"query":"query { me { id } }"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("read-only GraphQL should pass, got %d", resp.StatusCode)
	}
}

func TestUnwatchedHostIsTunneledNotIntercepted(t *testing.T) {
	h := newHarness(t)
	_, port, _ := net.SplitHostPort(h.upstream.Listener.Addr().String())
	// "localhost" has no rules → blind tunnel; the client sees the real
	// upstream certificate (issued for example.com by httptest).
	req, _ := http.NewRequest("DELETE", "https://localhost:"+port+"/repos/acme/api", nil)
	resp, err := h.client("example.com").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Twokey") != "" || h.decider.holds.Load() != 0 {
		t.Fatalf("tunnel should be transparent: status=%d header=%q holds=%d",
			resp.StatusCode, resp.Header.Get("X-Twokey"), h.decider.holds.Load())
	}
}

func TestClientDisconnectDuringHoldNeverForwards(t *testing.T) {
	h := newHarness(t)
	h.decider.manual.Store(true)
	tc, _ := h.rawTLS(t)
	fmt.Fprintf(tc, "DELETE /repos/acme/api HTTP/1.1\r\nHost: %s\r\n\r\n", h.upstream.Listener.Addr())

	held := <-h.decider.held
	tc.Close() // the agent gives up (e.g. its own HTTP timeout)
	waitFor(t, "hold to be cancelled", func() bool { return len(h.broker.Pending()) == 0 })

	if h.broker.Resolve(held.ID, approval.Decision{Approved: true, By: "test"}) {
		t.Fatal("approving after the client left must have no effect")
	}
	time.Sleep(100 * time.Millisecond)
	if n := h.upstreamHits.Load(); n != 0 {
		t.Fatalf("orphaned destructive request reached upstream (%d hits)", n)
	}
}

func TestExpectContinueDoesNotStall(t *testing.T) {
	h := newHarness(t)
	client := h.client("")
	client.Transport.(*http.Transport).ExpectContinueTimeout = 10 * time.Second
	req, _ := http.NewRequest("POST", h.upstream.URL+"/graphql", strings.NewReader(`{"query":"query { me { id } }"}`))
	req.Header.Set("Expect", "100-continue")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("client waited %s for 100-continue", took)
	}
}

func TestWebSocketUpgradeOnWatchedHost(t *testing.T) {
	h := newHarness(t)
	tc, br := h.rawTLS(t)
	fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", h.upstream.Listener.Addr())
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("want 101, got %v %v", err, resp)
	}
	_, _ = io.WriteString(tc, "ping")
	buf := make([]byte, 4)
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through upgraded connection failed: %q %v", buf, err)
	}
}

// restOnlyPack has no body rules, so uploads stream to the upstream instead
// of being buffered — the case where an early upstream answer matters.
const restOnlyPack = `
provider: test
rules:
  - id: test.repo.delete
    hosts: ["127.0.0.1"]
    methods: [DELETE]
    path: /repos/{owner}/{repo}
`

func TestEarlyUpstreamResponseClosesConnection(t *testing.T) {
	h := newHarnessWith(t, restOnlyPack)
	tc, br := h.rawTLS(t)
	const size = 4 << 20
	go func() {
		fmt.Fprintf(tc, "POST /early HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", h.upstream.Listener.Addr(), size)
		_, _ = tc.Write(make([]byte, size)) // may fail once the proxy closes
	}()
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", resp.StatusCode)
	}
	// The leftover upload must not be parsed as another request: the proxy
	// has to close the connection instead of reusing it.
	if _, err := http.ReadResponse(br, nil); err == nil {
		t.Fatal("connection was reused after an unread request body")
	}
}

func TestConnectionListedHeadersAreStripped(t *testing.T) {
	h := newHarness(t)
	tc, br := h.rawTLS(t)
	fmt.Fprintf(tc, "GET /echo-x-foo HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive, X-Foo\r\nX-Foo: secret\r\n\r\n", h.upstream.Listener.Addr())
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Got-X-Foo"); got != "" {
		t.Fatalf("hop-by-hop header named in Connection reached upstream: %q", got)
	}
}

func TestNoBodyResponsesKeepConnectionUsable(t *testing.T) {
	h := newHarness(t)
	client := h.client("")
	for _, step := range []struct{ method, path string }{
		{"GET", "/304"}, {"HEAD", "/repos/a/b"}, {"GET", "/repos/a/b"}, {"GET", "/304"}, {"GET", "/repos/a/b"},
	} {
		req, _ := http.NewRequest(step.method, h.upstream.URL+step.path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", step.method, step.path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
}

func TestGzippedGraphQLMutationIsHeld(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"query":"mutation { volumeDelete(volumeId: \"z1\") }"}`))
	zw.Close()
	req, _ := http.NewRequest("POST", h.upstream.URL+"/graphql", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := h.client("").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "z1") {
		t.Fatalf("gzip-encoded mutation must be held, got %d %s", resp.StatusCode, body)
	}
}

func TestSpliceForwardsHalfClose(t *testing.T) {
	// upstream: read everything until EOF, then answer.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		_, _ = io.WriteString(c, "got:"+string(data))
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	go func() {
		c, err := front.Accept()
		if err != nil {
			return
		}
		u, err := net.Dial("tcp", up.Addr().String())
		if err != nil {
			return
		}
		splice(c, c, u)
		c.Close()
		u.Close()
	}()

	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "hello")
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != "got:hello" {
		t.Fatalf("response lost after half-close: %q", got)
	}
}

func TestHealthEndpoint(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.proxyURL.String() + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["ok"] != true || got["name"] != "twokey" {
		t.Fatalf("unexpected health: %v", got)
	}
}
