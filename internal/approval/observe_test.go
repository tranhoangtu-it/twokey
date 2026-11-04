package approval

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

type countingNotifier struct{ notified int }

func (c *countingNotifier) Notify(Request)           { c.notified++ }
func (c *countingNotifier) Closed(Request, Decision) {}

func TestObserveModeApprovesImmediatelyAndNeverPrompts(t *testing.T) {
	b := NewBroker(time.Hour)
	b.SetObserve(true)
	prompt := &countingNotifier{}
	b.AddNotifier(prompt)
	var out bytes.Buffer
	b.AddNotifier(NewObserveLog(&out))

	start := time.Now()
	req, d := b.Decide(context.Background(), Request{Method: "DELETE", URL: "https://api.github.com/repos/a/b",
		Matches: []rules.Match{{Provider: "github", Operation: "delete repository", Resource: "a/b"}}})
	if time.Since(start) > time.Second {
		t.Fatal("observe mode must not wait for a human")
	}
	if !d.Approved || d.By != "observe" || req.ID == "" {
		t.Fatalf("decision=%+v id=%q", d, req.ID)
	}
	if prompt.notified != 0 {
		t.Fatal("approval prompts must not fire in observe mode")
	}
	if !strings.Contains(out.String(), "WOULD HOLD") || !strings.Contains(out.String(), "NOT PROTECTED") ||
		!strings.Contains(out.String(), "a/b") {
		t.Fatalf("observe output: %q", out.String())
	}
	if len(b.Pending()) != 0 {
		t.Fatal("observed requests must not stay pending")
	}
}

func TestCleanDefusesTerminalAndBidiControls(t *testing.T) {
	for _, s := range []string{"\x1b[2J", "a\rb", "x‮y", "x y", "x⁦y"} {
		if c := Clean(s); c == s || strings.ContainsAny(c, "\x1b\r‮ ⁦") {
			t.Errorf("Clean(%q) = %q", s, c)
		}
	}
}

func TestTerminalCleansStatementText(t *testing.T) {
	var out strings.Builder
	b := NewBroker(time.Hour)
	term := NewTerminal(b, &out)
	term.Notify(Request{ID: "1", Method: "SQL", URL: "postgres db:5432", Matches: []rules.Match{{
		RuleID: "postgres.drop-table", Operation: "DROP TABLE", Resource: "x",
		Message: "DROP TABLE x; \x1b[2J\x1b[Hfake prompt"}}})
	term.Flush()
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("escape sequence reached the approver's terminal: %q", out.String())
	}
}

func TestObserveLogIgnoresRealHolds(t *testing.T) {
	var out bytes.Buffer
	l := NewObserveLog(&out)
	l.Notify(Request{ID: "1"})
	l.Closed(Request{ID: "1"}, Decision{})
	if out.Len() != 0 {
		t.Fatalf("observe log printed for a real hold: %q", out.String())
	}
}
