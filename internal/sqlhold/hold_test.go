package sqlhold

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/rules"
	"github.com/tranhoangtu-it/twokey/internal/sqlclass"
)

// recorder remembers held requests and decisions; deny resolves at once.
type recorder struct {
	b      *approval.Broker
	deny   bool
	mu     sync.Mutex
	held   []approval.Request
	closed chan approval.Decision
}

func newRecorder(b *approval.Broker, deny bool) *recorder {
	r := &recorder{b: b, deny: deny, closed: make(chan approval.Decision, 8)}
	b.AddNotifier(r)
	return r
}

func (r *recorder) Notify(req approval.Request) {
	r.mu.Lock()
	r.held = append(r.held, req)
	r.mu.Unlock()
	if r.deny {
		r.b.Resolve(req.ID, approval.Decision{By: "test", Reason: "denied in test"})
	}
}

func (r *recorder) Closed(_ approval.Request, d approval.Decision) { r.closed <- d }

func (r *recorder) requests() []approval.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]approval.Request(nil), r.held...)
}

func mustAllow(t *testing.T, yaml string) []rules.Allow {
	t.Helper()
	a, err := rules.ParseAllow([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAllowMustCoverEveryTarget(t *testing.T) {
	b := approval.NewBroker(5 * time.Second)
	rec := newRecorder(b, true)
	g := &Guard{Provider: "postgres", Broker: b,
		Allow: mustAllow(t, "allow:\n  - rule: postgres.drop-table\n    resource: tmp_*\n")}

	if msg := g.Check(sqlclass.Classify("DROP TABLE tmp_a, tmp_b"), "postgres://db", nil); msg != "" {
		t.Fatalf("all targets allowed, want pass, got %q", msg)
	}
	if msg := g.Check(sqlclass.Classify("DROP TABLE tmp_a, prod_b"), "postgres://db", nil); msg == "" {
		t.Fatal("a statement that also drops prod_b passed on an allow rule for tmp_*")
	}
	held := rec.requests()
	if len(held) != 1 || len(held[0].Matches) != 2 {
		t.Fatalf("the hold must show every target, got %+v", held)
	}
}

func TestUninspectableIsNeverAllowed(t *testing.T) {
	b := approval.NewBroker(5 * time.Second)
	rec := newRecorder(b, true)
	g := &Guard{Provider: "postgres", Broker: b,
		Allow: mustAllow(t, "allow:\n  - rule: \"*\"\n    resource: \"*\"\n")}
	if msg := g.Check(sqlclass.Classify("CALL purge()"), "postgres://db", nil); msg == "" {
		t.Fatal("an uninspectable statement passed on an allow-everything rule")
	}
	held := rec.requests()
	if len(held) != 1 || !strings.Contains(held[0].Uninspectable, "CALL") {
		t.Fatalf("the hold must carry the uninspectable reason, got %+v", held)
	}
}

func TestHoldEndsWhenClientLeaves(t *testing.T) {
	b := approval.NewBroker(time.Minute)
	rec := newRecorder(b, false)
	g := &Guard{Provider: "postgres", Broker: b}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if msg := g.CheckContext(ctx, sqlclass.Classify("DROP TABLE users"), "postgres://db", nil); msg == "" {
		t.Fatal("statement ran although the client left")
	}
	if d := <-rec.closed; d.By != "client" || time.Since(start) > 5*time.Second {
		t.Fatalf("decision %+v after %s, want By=client promptly", d, time.Since(start))
	}
}
