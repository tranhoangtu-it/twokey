package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

func held(rule, resource string) Request {
	return Request{Method: "DELETE", URL: "https://api.github.com/repos/" + resource,
		Matches: []rules.Match{{RuleID: rule, Provider: "github", Operation: "delete", Resource: resource}}}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestGrants() (*Grants, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	g := NewGrants()
	g.now = c.now
	return g, c
}

func TestGrantMatchesExactRuleAndResource(t *testing.T) {
	g, _ := newTestGrants()
	if _, err := g.AddFor(held("github.repo.delete", "acme/x"), 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if !g.Covers(held("github.repo.delete", "acme/x")) {
		t.Fatal("identical request must be covered")
	}
	for _, r := range []Request{
		held("github.repo.delete", "acme/y"),
		held("github.repo.delete", "acme/x2"),
		held("github.org.delete", "acme/x"),
	} {
		if g.Covers(r) {
			t.Fatalf("grant leaked to %+v", r.Matches)
		}
	}
	both := held("github.repo.delete", "acme/x")
	both.Matches = append(both.Matches, rules.Match{RuleID: "github.repo.delete", Resource: "acme/y"})
	if g.Covers(both) {
		t.Fatal("a request with an ungranted match must not be covered")
	}
}

func TestGrantExpires(t *testing.T) {
	g, c := newTestGrants()
	if _, err := g.AddFor(held("github.repo.delete", "acme/x"), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(5*time.Minute + time.Second)
	if g.Covers(held("github.repo.delete", "acme/x")) || len(g.List()) != 0 {
		t.Fatal("expired grant still applies")
	}
}

func TestGrantNeverCoversUninspectableOrUnknownResource(t *testing.T) {
	g, _ := newTestGrants()
	if _, err := g.AddFor(held("github.repo.delete", ""), time.Minute); err == nil {
		t.Fatal("granted an unknown resource")
	}
	un := Request{Method: "POST", URL: "https://backboard.railway.com/graphql/v2", Uninspectable: "persisted query"}
	if _, err := g.AddFor(un, time.Minute); err == nil {
		t.Fatal("granted an uninspectable request")
	}
	if _, err := g.AddFor(held("github.repo.delete", "acme/x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	r := held("github.repo.delete", "acme/x")
	r.Uninspectable = "also had an unreadable part"
	if g.Covers(r) {
		t.Fatal("uninspectable request covered by a grant")
	}
}

func TestGrantDurationBounds(t *testing.T) {
	g, _ := newTestGrants()
	for _, d := range []time.Duration{0, -time.Minute, MaxGrant + time.Second} {
		if _, err := g.AddFor(held("github.repo.delete", "acme/x"), d); err == nil {
			t.Fatalf("accepted duration %v", d)
		}
	}
}

func TestGrantRevoke(t *testing.T) {
	g, _ := newTestGrants()
	_, _ = g.AddFor(held("github.repo.delete", "acme/x"), time.Minute)
	if !g.Revoke(1) || g.Covers(held("github.repo.delete", "acme/x")) || g.Revoke(1) {
		t.Fatal("revoke failed")
	}
}

func TestBrokerAutoApprovesGrantedRequestWithoutPrompting(t *testing.T) {
	b := NewBroker(time.Hour)
	prompt := &countingNotifier{}
	b.AddNotifier(prompt)
	if _, err := b.Grants().AddFor(held("github.repo.delete", "acme/x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	_, d := b.Decide(context.Background(), held("github.repo.delete", "acme/x"))
	if !d.Approved || d.By != "grant" || prompt.notified != 0 {
		t.Fatalf("decision=%+v prompts=%d", d, prompt.notified)
	}
}

func TestTerminalApproveForCreatesGrant(t *testing.T) {
	b := NewBroker(time.Hour)
	term := NewTerminal(b, &strings.Builder{})
	done := make(chan Decision, 1)
	go func() { _, d := b.Decide(context.Background(), held("github.repo.delete", "acme/x")); done <- d }()
	waitPending(t, b)

	if msg := term.Handle("approve 1 acme/x --for 2h"); !strings.Contains(msg, "at most") {
		t.Fatalf("over-long grant accepted: %q", msg)
	}
	if msg := term.Handle("approve 1 acme/x --for 10m"); msg != "" && !strings.Contains(msg, "granted") {
		t.Fatalf("approve --for: %q", msg)
	}
	if d := <-done; !d.Approved {
		t.Fatalf("not approved: %+v", d)
	}
	if !b.Grants().Covers(held("github.repo.delete", "acme/x")) {
		t.Fatal("grant not recorded")
	}
	if out := term.Handle("grants"); !strings.Contains(out, "acme/x") {
		t.Fatalf("grants: %q", out)
	}
	term.Handle("revoke 1")
	if b.Grants().Covers(held("github.repo.delete", "acme/x")) {
		t.Fatal("revoke via terminal failed")
	}
}

func waitPending(t *testing.T, b *Broker) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(b.Pending()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("request never became pending")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
