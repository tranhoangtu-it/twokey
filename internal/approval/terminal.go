package approval

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Terminal is the approval channel in the `twokey up` window. That window is
// separate from the agent's terminal, so the agent cannot type into it.
//
// Commands:
//
//	approve <id> <confirm>   confirm = resource name (typed confirmation)
//	deny <id>
//	list
//
// With exactly one pending request the id may be omitted.
type Terminal struct {
	broker *Broker
	out    io.Writer
	mu     sync.Mutex // serializes writes to out
}

// NewTerminal builds a terminal channel writing to out.
func NewTerminal(b *Broker, out io.Writer) *Terminal {
	return &Terminal{broker: b, out: out}
}

func (t *Terminal) printf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.out, format, args...)
}

// Notify prints a held request.
func (t *Terminal) Notify(r Request) {
	var b strings.Builder
	// Everything request-derived goes through Clean: no ANSI or newlines
	// that could fake a prompt line.
	fmt.Fprintf(&b, "\n⏸  HOLD #%s  %s %s\n", r.ID, Clean(r.Method), Clean(r.URL))
	for _, m := range r.Matches {
		res := m.Resource
		if res == "" {
			res = "(unknown)"
		}
		fmt.Fprintf(&b, "   %-8s %s  operation=%s  resource=%q\n", strings.ToUpper(m.Severity), m.RuleID, Clean(m.Operation), Clean(res))
		if m.Message != "" {
			fmt.Fprintf(&b, "            %s\n", m.Message)
		}
	}
	if r.Uninspectable != "" {
		fmt.Fprintf(&b, "   UNKNOWN  %s\n", Clean(r.Uninspectable))
	}
	fmt.Fprintf(&b, "   → approve %s %s     |     deny %s\n", r.ID, r.ConfirmText(), r.ID)
	t.printf("%s", b.String())
}

// Closed prints the outcome.
func (t *Terminal) Closed(r Request, d Decision) {
	verdict := "DENIED"
	if d.Approved {
		verdict = "APPROVED"
	}
	t.printf("   #%s %s by %s (%s)\n", r.ID, verdict, d.By, d.Reason)
}

// Run reads commands until in is exhausted.
func (t *Terminal) Run(in io.Reader) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), maxCommandLine)
	for {
		for sc.Scan() {
			if msg := t.Handle(sc.Text()); msg != "" {
				t.printf("   %s\n", msg)
			}
		}
		if !errors.Is(sc.Err(), bufio.ErrTooLong) {
			if err := sc.Err(); err != nil {
				t.printf("   approval input closed: %v (approve from your phone instead)\n", err)
			}
			return
		}
		// A giant paste must not silently kill approvals: report and resume.
		t.printf("   line too long, ignored\n")
		sc = bufio.NewScanner(in)
		sc.Buffer(make([]byte, 64*1024), maxCommandLine)
	}
}

// maxCommandLine caps one typed command (resource names can be long).
const maxCommandLine = 1 << 20

// Handle executes one command line and returns feedback for the user.
func (t *Terminal) Handle(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	verb, args := strings.ToLower(fields[0]), fields[1:]
	switch verb {
	case "list", "ls":
		return t.list()
	case "approve", "a", "deny", "d":
	default:
		return "commands: approve <id> <resource> | deny <id> | list"
	}

	req, rest, errMsg := t.target(args)
	if errMsg != "" {
		return errMsg
	}
	if verb == "deny" || verb == "d" {
		t.broker.Resolve(req.ID, Decision{Approved: false, By: "terminal", Reason: "denied by human"})
		return ""
	}
	want := req.ConfirmText()
	if NormalizeSpace(strings.Join(rest, " ")) != want {
		return fmt.Sprintf("not approved: type the resource name exactly → approve %s %s", req.ID, want)
	}
	t.broker.Resolve(req.ID, Decision{Approved: true, By: "terminal", Reason: "approved with typed confirmation"})
	return ""
}

// target picks the request an approve/deny refers to.
func (t *Terminal) target(args []string) (Request, []string, string) {
	if len(args) > 0 {
		if r, ok := t.broker.Get(args[0]); ok {
			return r, args[1:], ""
		}
		if isNumber(args[0]) {
			// A stale id must not silently fall through to another request.
			return Request{}, nil, fmt.Sprintf("no pending request #%s (see `list`)", args[0])
		}
	}
	pending := t.broker.Pending()
	switch len(pending) {
	case 0:
		return Request{}, nil, "nothing is pending"
	case 1:
		return pending[0], args, ""
	default:
		return Request{}, nil, "several requests pending; give the id (see `list`)"
	}
}

func isNumber(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func (t *Terminal) list() string {
	pending := t.broker.Pending()
	if len(pending) == 0 {
		return "nothing is pending"
	}
	var b strings.Builder
	for _, r := range pending {
		fmt.Fprintf(&b, "#%s  %s\n   ", r.ID, r.Summary())
	}
	return strings.TrimSpace(b.String())
}
