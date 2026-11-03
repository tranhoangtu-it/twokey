package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

var volumeDelete = []rules.Match{{RuleID: "railway.volume.delete", Provider: "railway", Operation: "volumeDelete", Resource: "pg-data-prod"}}

// recorder captures notifications so tests can act on the pending request.
type recorder struct{ reqs chan Request }

func newRecorder() *recorder                 { return &recorder{reqs: make(chan Request, 8)} }
func (r *recorder) Notify(req Request)       { r.reqs <- req }
func (r *recorder) Closed(Request, Decision) {}

func decideAsync(b *Broker) <-chan Decision {
	out := make(chan Decision, 1)
	go func() {
		_, d := b.Decide(context.Background(), Request{Method: "POST", URL: "https://x", Matches: volumeDelete})
		out <- d
	}()
	return out
}

func TestTimeoutDenies(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	d := <-decideAsync(b)
	if d.Approved || d.By != "timeout" {
		t.Fatalf("want timeout denial, got %+v", d)
	}
	if len(b.Pending()) != 0 {
		t.Fatal("expired request still pending")
	}
}

func TestTerminalRequiresTypedConfirmation(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	term := NewTerminal(b, io.Discard)

	result := decideAsync(b)
	req := <-rec.reqs

	if msg := term.Handle("approve " + req.ID + " pg-data-staging"); !strings.Contains(msg, "not approved") {
		t.Fatalf("wrong confirmation must be rejected, got %q", msg)
	}
	if len(b.Pending()) != 1 {
		t.Fatal("request should still be pending after wrong confirmation")
	}
	if msg := term.Handle("approve " + req.ID + " pg-data-prod"); msg != "" {
		t.Fatalf("unexpected feedback: %q", msg)
	}
	if d := <-result; !d.Approved || d.By != "terminal" {
		t.Fatalf("want terminal approval, got %+v", d)
	}
}

func TestTerminalDenyWithoutIDWhenSinglePending(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	term := NewTerminal(b, io.Discard)

	result := decideAsync(b)
	<-rec.reqs
	term.Handle("deny")
	if d := <-result; d.Approved {
		t.Fatalf("want denial, got %+v", d)
	}
}

func TestBatchNeedsEveryResourceConfirmed(t *testing.T) {
	r := Request{Matches: []rules.Match{
		{Operation: "volumeDelete", Resource: "vol-a"},
		{Operation: "volumeDelete", Resource: "vol-b"},
		{Operation: "volumeDelete", Resource: "vol-a"},
		{Operation: "projectDelete"},
	}}
	if got := r.ConfirmText(); got != "vol-a vol-b projectDelete" {
		t.Fatalf("ConfirmText = %q", got)
	}

	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	term := NewTerminal(b, io.Discard)
	out := make(chan Decision, 1)
	go func() { _, d := b.Decide(context.Background(), r); out <- d }()
	held := <-rec.reqs
	if msg := term.Handle("approve " + held.ID + " vol-a"); !strings.Contains(msg, "not approved") {
		t.Fatalf("typing only the first resource must not approve a batch: %q", msg)
	}
	term.Handle("approve " + held.ID + " vol-a vol-b projectDelete")
	if d := <-out; !d.Approved {
		t.Fatalf("full confirmation should approve, got %+v", d)
	}
}

func TestPromptIsSanitizedAndWhitespaceTolerant(t *testing.T) {
	evil := "pg\x1b[2K\r   → approve 9 x\nprod  data"
	if got := Clean(evil); strings.ContainsAny(got, "\x1b\r\n") {
		t.Fatalf("control characters survived: %q", got)
	}
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	var out strings.Builder
	term := NewTerminal(b, &out)
	res := make(chan Decision, 1)
	go func() {
		_, d := b.Decide(context.Background(), Request{Matches: []rules.Match{{Operation: "volumeDelete", Resource: "my   volume"}}})
		res <- d
	}()
	held := <-rec.reqs
	term.Notify(held)
	term.Flush()
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("terminal output contains ESC")
	}
	if msg := term.Handle("approve " + held.ID + " my volume"); msg != "" {
		t.Fatalf("whitespace-normalized confirmation should approve, got %q", msg)
	}
	if d := <-res; !d.Approved {
		t.Fatalf("want approval, got %+v", d)
	}
}

func TestStaleIDDoesNotFallThrough(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	term := NewTerminal(b, io.Discard)
	res := decideAsync(b)
	held := <-rec.reqs
	if msg := term.Handle("deny 999"); !strings.Contains(msg, "no pending request #999") {
		t.Fatalf("stale id must be reported, got %q", msg)
	}
	if _, ok := b.Get(held.ID); !ok {
		t.Fatal("stale deny must not decide another request")
	}
	term.Handle("deny " + held.ID)
	<-res
}

func TestStalledConsoleNeverBlocksHolds(t *testing.T) {
	_, stalled := io.Pipe() // writes block forever: nobody reads
	b := NewBroker(100 * time.Millisecond)
	b.AddNotifier(NewTerminal(b, stalled))
	const n = outputQueue + 5 // overflow the output queue too
	done := make(chan Decision, n)
	for i := 0; i < n; i++ {
		go func() {
			_, d := b.Decide(context.Background(), Request{Matches: volumeDelete})
			done <- d
		}()
	}
	deadline := time.After(10 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case d := <-done:
			if d.By != "timeout" {
				t.Fatalf("want timeout, got %+v", d)
			}
		case <-deadline:
			t.Fatal("holds blocked behind a stalled console")
		}
	}
}

func TestDenyAllOnShutdown(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	r1, r2 := decideAsync(b), decideAsync(b)
	<-rec.reqs
	<-rec.reqs
	if n := b.DenyAll("bye"); n != 2 {
		t.Fatalf("denied %d, want 2", n)
	}
	for _, r := range []<-chan Decision{r1, r2} {
		if d := <-r; d.Approved || d.By != "shutdown" {
			t.Fatalf("want shutdown denial, got %+v", d)
		}
	}
}

func TestNonceMustMatch(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	result := decideAsync(b)
	req := <-rec.reqs

	if b.ResolveWithNonce(req.ID, "forged", Decision{Approved: true}) {
		t.Fatal("forged nonce must not resolve")
	}
	if !b.ResolveWithNonce(req.ID, req.Nonce, Decision{Approved: true, By: "ntfy"}) {
		t.Fatal("correct nonce must resolve")
	}
	if d := <-result; !d.Approved {
		t.Fatalf("want approval, got %+v", d)
	}
}

// TestNtfyRoundTrip runs publish + subscribe against a fake ntfy server: the
// "phone" taps Approve by posting the action body to the reply topic.
func TestNtfyRoundTrip(t *testing.T) {
	replies := make(chan string, 1)
	published := make(chan ntfyMessage, 1)
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/":
			var m ntfyMessage
			_ = json.NewDecoder(r.Body).Decode(&m)
			once.Do(func() {
				published <- m
				replies <- m.Actions[1].Body // tap "Approve"
			})
		case r.Method == http.MethodGet && r.URL.Path == "/secret-topic-reply/json":
			w.(http.Flusher).Flush()
			select {
			case body := <-replies:
				fmt.Fprintf(w, `{"event":"message","message":%q}`+"\n", body)
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	b := NewBroker(5 * time.Second)
	n := NewNtfy(srv.URL, "secret-topic", b)
	n.logf = t.Logf
	b.AddNotifier(n)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Listen(ctx)

	_, d := b.Decide(ctx, Request{Method: "POST", URL: "https://backboard.railway.com/graphql/v2", Matches: volumeDelete})
	if !d.Approved || d.By != "ntfy" {
		t.Fatalf("want ntfy approval, got %+v", d)
	}
	m := <-published
	if m.Topic != "secret-topic" || len(m.Actions) != 2 || m.Actions[0].Label != "Deny" {
		t.Fatalf("unexpected notification: %+v", m)
	}
}
