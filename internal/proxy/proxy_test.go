package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// autoDecider plays the human: approves or denies every hold immediately.
type autoDecider struct {
	broker  *approval.Broker
	approve atomic.Bool
	holds   atomic.Int32
}

func (a *autoDecider) Notify(r approval.Request) {
	a.holds.Add(1)
	a.broker.Resolve(r.ID, approval.Decision{Approved: a.approve.Load(), By: "test", Reason: "auto"})
}
func (a *autoDecider) Closed(approval.Request, approval.Decision) {}

type harness struct {
	upstream     *httptest.Server
	upstreamHits atomic.Int32
	proxyURL     *url.URL
	decider      *autoDecider
	roots        *x509.CertPool
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

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.upstreamHits.Add(1)
		_, _ = io.WriteString(w, "upstream says hi")
	}))
	t.Cleanup(h.upstream.Close)

	pack, err := rules.ParsePack([]byte(testPack))
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
	h.decider = &autoDecider{broker: broker}
	broker.AddNotifier(h.decider)

	srv := New(Options{
		Engine: engine, CA: authority, Broker: broker, Logf: t.Logf, Version: "test",
		Transport: h.upstream.Client().Transport, // trusts the upstream's test cert
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
