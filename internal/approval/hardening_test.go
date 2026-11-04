package approval

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// Invisible format characters let two resource names look identical, or put
// characters into the confirmation hint that a human cannot type.
func TestCleanNeutralizesZeroWidthAndTagCharacters(t *testing.T) {
	invisible := []rune{0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0x2061, 0x2064, 0xfeff, 0xad,
		0xe0000, 0xe0001, 0xe0041, 0xe007f}
	for _, r := range invisible {
		got := Clean("a" + string(r) + "b")
		if got != "a?b" {
			t.Errorf("U+%04X: Clean = %q, want %q", r, got, "a?b")
		}
	}
	for _, r := range Clean("prod" + string(rune(0x200b)) + "-db" + string(rune(0xe0041))) {
		if unicode.Is(unicode.Cf, r) || (r >= 0xe0000 && r <= 0xe007f) {
			t.Fatalf("format character U+%04X survived Clean", r)
		}
	}
	if got := Clean("café 名前 ✓"); got != "café 名前 ✓" {
		t.Fatalf("printable text must be kept: %q", got)
	}
}

// notify-send renders Pango markup in the body: a path must not become a link.
func TestNotifySendEscapesMarkup(t *testing.T) {
	r := Request{ID: "7", Method: "DELETE", URL: "https://api.github.com/x",
		Matches: []rules.Match{{Provider: "github", Operation: "delete", Resource: `<a href="http://evil">approve</a> & <b>x</b>`}}}
	argv, _ := desktopCommand("linux", r)
	body := argv[len(argv)-1]
	if strings.ContainsAny(body, "<>") || strings.Contains(body, "& ") {
		t.Fatalf("markup not escaped in notify-send body: %q", body)
	}
	if !strings.Contains(body, "&lt;a href=") || !strings.Contains(body, "&amp;") {
		t.Fatalf("expected entity-escaped markup: %q", body)
	}
	// Other platforms show plain text: no entities there.
	argv, _ = desktopCommand("darwin", r)
	if strings.Contains(argv[len(argv)-1], "&lt;") {
		t.Fatal("osascript text must not be entity-escaped")
	}
}

func holdResource(t *testing.T, b *Broker, rec *recorder, resource string) (Request, <-chan Decision) {
	t.Helper()
	out := make(chan Decision, 1)
	go func() {
		_, d := b.Decide(context.Background(), Request{Method: "DELETE", URL: "https://api.github.com/repos/a/b",
			Matches: []rules.Match{{RuleID: "github.repo.delete", Provider: "github", Operation: "delete", Resource: resource}}})
		out <- d
	}()
	return <-rec.reqs, out
}

// An agent-controlled resource name that ends in "--for <dur>" must stay
// approvable from the terminal (otherwise terminal approval is impossible).
func TestTerminalApprovesResourceEndingInForDuration(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	term := NewTerminal(b, io.Discard)

	req, result := holdResource(t, b, rec, "x --for 5m")
	if msg := term.Handle("approve " + req.ID + " x --for 5m"); msg != "" {
		t.Fatalf("typing the resource exactly must approve, got %q", msg)
	}
	if d := <-result; !d.Approved {
		t.Fatalf("want approval, got %+v", d)
	}
	if len(b.Grants().List()) != 0 {
		t.Fatal("an exact resource match is a one-time approval, not a grant")
	}

	// The same resource plus a real trailing --for creates a grant.
	req, result = holdResource(t, b, rec, "x --for 5m")
	if msg := term.Handle("approve " + req.ID + " x --for 5m --for 10m"); !strings.Contains(msg, "granted for 10m") {
		t.Fatalf("want a 10m grant, got %q", msg)
	}
	if d := <-result; !d.Approved {
		t.Fatalf("want approval, got %+v", d)
	}

	// A trailing pair that is not a valid duration is not a grant request.
	req, result = holdResource(t, b, rec, "y --for soon")
	if msg := term.Handle("approve " + req.ID + " y --for soon"); msg != "" {
		t.Fatalf("resource %q must be approvable, got %q", "y --for soon", msg)
	}
	<-result
}

// A flood of holds must not pin unbounded goroutines and prompts: beyond the
// cap, new holds are denied at once with a clear reason (fail closed).
func TestPendingHoldsAreCapped(t *testing.T) {
	b := NewBroker(5 * time.Second)
	b.SetMaxPending(2)
	rec := newRecorder()
	b.AddNotifier(rec)
	r1, d1 := holdResource(t, b, rec, "a")
	r2, d2 := holdResource(t, b, rec, "b")

	_, d := b.Decide(context.Background(), Request{Method: "DELETE", URL: "https://x", Matches: volumeDelete})
	if d.Approved || d.By != "overload" || !strings.Contains(d.Reason, "2 requests are already waiting") {
		t.Fatalf("want an immediate overload denial, got %+v", d)
	}
	select {
	case r := <-rec.reqs:
		t.Fatalf("an overload denial must not prompt the human: %+v", r)
	default:
	}
	b.Resolve(r1.ID, Decision{By: "terminal"})
	b.Resolve(r2.ID, Decision{By: "terminal"})
	<-d1
	<-d2
	if got := len(b.Pending()); got != 0 {
		t.Fatalf("pending = %d", got)
	}
}

func TestDefaultPendingCap(t *testing.T) {
	if MaxPending != 100 {
		t.Fatalf("MaxPending = %d, want 100", MaxPending)
	}
}

// Shutdown must not close the audit log while a denied hold is still on
// its way to being written: Drain waits for every Decide to return.
func TestDrainWaitsForInFlightDecisions(t *testing.T) {
	b := NewBroker(5 * time.Second)
	rec := newRecorder()
	b.AddNotifier(rec)
	go func() {
		_, _ = b.Decide(context.Background(), Request{Method: "DELETE", URL: "https://x", Matches: volumeDelete})
	}()
	<-rec.reqs
	if b.Drain(20 * time.Millisecond) {
		t.Fatal("Drain must report a pending hold that has not returned")
	}
	b.DenyAll("shutting down")
	if !b.Drain(2 * time.Second) {
		t.Fatal("Drain must return true once every Decide returned")
	}
}

func TestValidateNtfy(t *testing.T) {
	good := "twokey-0123456789abcdef01234567"
	for _, c := range []struct {
		server, topic string
		ok            bool
	}{
		{"https://ntfy.sh", good, true},
		{"https://ntfy.example.com/", good, true},
		{"http://localhost:8080", good, true},
		{"http://127.0.0.1:2586", good, true},
		{"http://[::1]:2586", good, true},
		{"http://ntfy.example.com", good, false},
		{"ntfy.example.com", good, false},
		{"ftp://ntfy.example.com", good, false},
		{"https://", good, false},
		{"https://user:pw@ntfy.example.com", good, false},
		{"https://ntfy.sh", "mytopic", false},
		{"https://ntfy.sh", "", false},
		{"https://ntfy.sh", "has spaces in the topic name", false},
		{"https://ntfy.sh", "slash/inside-a-long-topic", false},
		{"https://ntfy.sh", strings.Repeat("a", 65), false},
	} {
		err := ValidateNtfy(c.server, c.topic)
		if (err == nil) != c.ok {
			t.Errorf("ValidateNtfy(%q, %q) = %v, want ok=%v", c.server, c.topic, err, c.ok)
		}
		if err != nil && c.topic == good && strings.Contains(err.Error(), good) {
			t.Errorf("error leaks the topic: %v", err)
		}
	}
}

// Connection errors embed the full URL (and so the secret topic): they must
// be redacted before they reach a log file someone may paste into an issue.
func TestNtfyRedactsTopicFromLogs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // closed port: every request fails with a *url.Error

	const topic = "twokey-secret0123456789abcdef"
	b := NewBroker(time.Second)
	n := NewNtfy("http://"+addr, topic, b)
	var mu sync.Mutex
	var logs []string
	n.SetLogf(func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(f, a...))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	n.Listen(ctx)
	n.Notify(Request{ID: "1", Nonce: "n", Method: "DELETE", URL: "https://x", Matches: volumeDelete})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(logs)
		mu.Unlock()
		if count >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) < 2 {
		t.Fatalf("want subscribe and publish failures logged, got %q", logs)
	}
	for _, l := range logs {
		if strings.Contains(l, "secret0123456789") {
			t.Fatalf("topic leaked into log: %q", l)
		}
	}
	if got := RedactTopic(topic); strings.Contains(got, "secret") || !strings.HasSuffix(got, "cdef") {
		t.Fatalf("RedactTopic = %q", got)
	}
}

// A phone message has a size limit; an agent-sized URL must not make the
// publish fail (which would leave a phone-only user with an invisible hold).
func TestNtfyMessageIsBounded(t *testing.T) {
	r := Request{ID: "1", Nonce: "n", Method: "DELETE", URL: "https://x/" + strings.Repeat("a", 10000), Matches: volumeDelete}
	msg := holdMessage(r)
	if n := len(msg); n > maxNtfyMessage {
		t.Fatalf("message is %d bytes, cap %d", n, maxNtfyMessage)
	}
	if !strings.Contains(msg, "Hold #1") {
		t.Fatalf("hold id must survive truncation: %q", msg[len(msg)-40:])
	}
}

// A grant approved for one payload must not cover another with the same
// URL, rule and resource (e.g. SkipFinalSnapshot=false → true).
func TestGrantIsBoundToRequestFingerprint(t *testing.T) {
	g, _ := newTestGrants()
	r := held("aws.rds.delete", "orders-prod")
	r.Fingerprint = "sha256:aaaa"
	if _, err := g.AddFor(r, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if !g.Covers(r) {
		t.Fatal("the identical request must be covered")
	}
	other := r
	other.Fingerprint = "sha256:bbbb"
	if g.Covers(other) {
		t.Fatal("a different body must not be covered by the grant")
	}
	if fp := BodyFingerprint([]byte(`{"a":1}`), "x=1"); fp == BodyFingerprint([]byte(`{"a":2}`), "x=1") || fp == BodyFingerprint([]byte(`{"a":1}`), "x=2") {
		t.Fatal("fingerprint must change with body and query")
	}
}
