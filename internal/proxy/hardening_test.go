package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

func TestUpgradeRefusedByUpstreamKeepsInspecting(t *testing.T) {
	h := newHarnessWith(t, restOnlyPack)
	tc, br := h.rawTLS(t)
	addr := h.upstream.Listener.Addr()
	fmt.Fprintf(tc, "GET /x HTTP/1.1\r\nHost: %s\r\nUpgrade: foo\r\nConnection: Upgrade\r\n\r\n", addr)
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want the upstream's 200, got %d", resp.StatusCode)
	}
	// No 101: the connection is still HTTP and the next request is inspected.
	fmt.Fprintf(tc, "DELETE /repos/acme/api HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || h.decider.holds.Load() != 1 {
		t.Fatalf("DELETE after a refused upgrade must be held: %d holds=%d", resp.StatusCode, h.decider.holds.Load())
	}
}

func TestUpgradeOnBodyRuleHostIsHeld(t *testing.T) {
	h := newHarness(t) // has a GraphQL rule: messages after the upgrade can't be inspected
	tc, br := h.rawTLS(t)
	fmt.Fprintf(tc, "GET /graphql HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", h.upstream.Listener.Addr())
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "uninspectable") || h.upstreamHits.Load() != 0 {
		t.Fatalf("upgrade on a body-rule host must be held: %d hits=%d %s", resp.StatusCode, h.upstreamHits.Load(), body)
	}
}

func TestUndecodableBodyIsHeldEvenWhenAllowed(t *testing.T) {
	h := newHarnessOpts(t, testPack, func(s *Server) {
		s.allow = []rules.Allow{{Rule: "test.repo.delete", Resource: "*"}}
	})
	h.decider.approve.Store(false)
	req, _ := http.NewRequest("DELETE", h.upstream.URL+"/repos/acme/api", strings.NewReader("not really brotli"))
	req.Header.Set("Content-Encoding", "br")
	resp, err := h.client("").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || h.upstreamHits.Load() != 0 {
		t.Fatalf("an allow rule must not launder an undecodable body: %d hits=%d", resp.StatusCode, h.upstreamHits.Load())
	}
}

func TestClientDisconnectNoticedAfterBodyIdleTimeout(t *testing.T) {
	h := newHarnessOpts(t, testPack, func(s *Server) { s.bodyIdle = 100 * time.Millisecond })
	h.decider.manual.Store(true)
	tc, _ := h.rawTLS(t)
	fmt.Fprintf(tc, "DELETE /repos/acme/api HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\n{}", h.upstream.Listener.Addr())

	held := <-h.decider.held
	time.Sleep(400 * time.Millisecond) // the hold outlives the body read deadline
	tc.Close()
	// Well before the broker's own 5s timeout would clear the hold.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for len(h.broker.Pending()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the client left but the hold is still pending")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.broker.Resolve(held.ID, approval.Decision{Approved: true, By: "test"}) {
		t.Fatal("approving after the client left must have no effect")
	}
	time.Sleep(100 * time.Millisecond)
	if n := h.upstreamHits.Load(); n != 0 {
		t.Fatalf("orphaned destructive request reached upstream (%d hits)", n)
	}
}

func TestOversizedRequestHeaderIsRejected(t *testing.T) {
	h := newHarness(t)
	tc, br := h.rawTLS(t)
	go func() {
		fmt.Fprintf(tc, "GET /repos/a/b HTTP/1.1\r\nHost: %s\r\nX-Big: %s\r\n\r\n",
			h.upstream.Listener.Addr(), strings.Repeat("a", 2*maxHeaderBytes))
	}()
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge || !strings.Contains(string(body), "twokey") || h.upstreamHits.Load() != 0 {
		t.Fatalf("want twokey's 431, got %d hits=%d %s", resp.StatusCode, h.upstreamHits.Load(), body)
	}
}

func TestTimedGrantIsBoundToTheBody(t *testing.T) {
	h := newHarness(t)
	grant := approval.Request{Method: "DELETE", URL: "https://127.0.0.1/repos/acme/api",
		Matches:     []rules.Match{{RuleID: "test.repo.delete", Resource: "acme/api"}},
		Fingerprint: approval.BodyFingerprint([]byte(`{"a":1}`), "")}
	if _, err := h.broker.Grants().AddFor(grant, time.Minute); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.do(t, "DELETE", "/repos/acme/api", `{"a":2}`); resp.StatusCode != http.StatusForbidden || h.decider.holds.Load() != 1 {
		t.Fatalf("a grant for one body must not cover another: %d holds=%d", resp.StatusCode, h.decider.holds.Load())
	}
	if resp, _ := h.do(t, "DELETE", "/repos/acme/api", `{"a":1}`); resp.StatusCode != 200 || h.decider.holds.Load() != 1 {
		t.Fatalf("the granted body must pass: %d holds=%d", resp.StatusCode, h.decider.holds.Load())
	}
}

func TestBlockedMessageFollowsTheDecision(t *testing.T) {
	req, _ := http.NewRequest("DELETE", "https://api.example.com/x", nil)
	for by, want := range map[string]string{
		"terminal": "denied by a human",
		"ntfy":     "denied by a human",
		"timeout":  "not approved in time",
		"overload": "too many requests are already waiting",
		"shutdown": "shut down before a human decided",
		"client":   "disconnected before a human decided",
	} {
		resp := blockedResponse(req, approval.Request{Method: "DELETE", URL: "https://api.example.com/x"}, approval.Decision{By: by})
		body, _ := io.ReadAll(resp.Body)
		msg := string(body)
		if !strings.Contains(msg, want) || !strings.Contains(msg, "Do not retry") || !strings.Contains(msg, `"type":"twokey_blocked"`) {
			t.Errorf("by=%s: %s", by, msg)
		}
		if by != "terminal" && by != "ntfy" && strings.Contains(msg, "denied by a human") {
			t.Errorf("by=%s claims a human denied it: %s", by, msg)
		}
	}
}

func TestIdleSpliceIsClosed(t *testing.T) {
	clientSide, client := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer clientSide.Close()
	defer upstreamSide.Close()
	done := make(chan struct{})
	go func() {
		spliceIdle(client, client, upstream, 100*time.Millisecond)
		close(done)
	}()
	// Some traffic first: activity postpones the idle timeout.
	go func() { _, _ = io.Copy(io.Discard, upstreamSide) }()
	for i := 0; i < 3; i++ {
		if _, err := clientSide.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle splice was never closed")
	}
}
