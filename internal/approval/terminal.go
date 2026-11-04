package approval

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
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
	lines  chan termLine
}

// termLine is queued output, or (flush != nil) a marker to signal when
// everything before it has been written.
type termLine struct {
	text  string
	flush chan struct{}
}

// outputQueue bounds buffered terminal output.
const outputQueue = 256

// NewTerminal builds a terminal channel writing to out. Writes happen on a
// dedicated goroutine: a stalled console (e.g. Windows QuickEdit selection)
// must never block the broker, the hold timeout or the phone channel.
func NewTerminal(b *Broker, out io.Writer) *Terminal {
	t := &Terminal{broker: b, lines: make(chan termLine, outputQueue)}
	go func() {
		for l := range t.lines {
			if l.flush != nil {
				close(l.flush)
				continue
			}
			_, _ = io.WriteString(out, l.text)
		}
	}()
	return t
}

func (t *Terminal) printf(format string, args ...any) {
	select {
	case t.lines <- termLine{text: fmt.Sprintf(format, args...)}:
	default: // console stalled and queue full: drop output, never block a hold
	}
}

// Flush waits until queued output has been written (tests, shutdown).
func (t *Terminal) Flush() {
	done := make(chan struct{})
	t.lines <- termLine{flush: done}
	<-done
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
	case "grants":
		return t.listGrants()
	case "revoke":
		return t.revoke(args)
	case "approve", "a", "deny", "d":
	default:
		return "commands: approve <id> <resource> [--for 15m] | deny <id> | list | grants | revoke <n>"
	}

	req, rest, errMsg := t.target(args)
	if errMsg != "" {
		return errMsg
	}
	if verb == "deny" || verb == "d" {
		t.broker.Resolve(req.ID, Decision{Approved: false, By: "terminal", Reason: "denied by human"})
		return ""
	}
	rest, grantFor, errMsg := splitFor(rest)
	if errMsg != "" {
		return errMsg
	}
	want := req.ConfirmText()
	if NormalizeSpace(strings.Join(rest, " ")) != want {
		return fmt.Sprintf("not approved: type the resource name exactly → approve %s %s", req.ID, want)
	}
	reason := "approved with typed confirmation"
	if grantFor > 0 {
		if _, err := t.broker.Grants().AddFor(req, grantFor); err != nil {
			return "not approved: " + err.Error()
		}
		reason += fmt.Sprintf("; same operation on the same resource pre-approved for %s", grantFor)
	}
	t.broker.Resolve(req.ID, Decision{Approved: true, By: "terminal", Reason: reason})
	if grantFor > 0 {
		return fmt.Sprintf("granted for %s: repeats of exactly this operation are auto-approved (see `grants`, `revoke`)", grantFor)
	}
	return ""
}

// splitFor removes a trailing "--for <duration>" from an approve command.
func splitFor(args []string) ([]string, time.Duration, string) {
	if len(args) < 2 || args[len(args)-2] != "--for" {
		return args, 0, ""
	}
	d, err := time.ParseDuration(args[len(args)-1])
	if err != nil || d <= 0 || d > MaxGrant {
		return nil, 0, fmt.Sprintf("--for takes a duration of at most %s, e.g. --for 15m", MaxGrant)
	}
	return args[:len(args)-2], d, ""
}

func (t *Terminal) listGrants() string {
	gs := t.broker.Grants().List()
	if len(gs) == 0 {
		return "no timed approvals"
	}
	var b strings.Builder
	for i, g := range gs {
		fmt.Fprintf(&b, "%d. %s on %q until %s\n   ", i+1, g.RuleID, Clean(g.Resource), g.Expires.Format(time.TimeOnly))
	}
	return strings.TrimSpace(b.String())
}

func (t *Terminal) revoke(args []string) string {
	if len(args) != 1 || !isNumber(args[0]) {
		return "usage: revoke <n> (see `grants`)"
	}
	n, _ := strconv.Atoi(args[0])
	if !t.broker.Grants().Revoke(n) {
		return "no such grant"
	}
	return "revoked"
}

// Granted prints a request decided by a timed approval.
func (t *Terminal) Granted(r Request, _ Decision) {
	t.printf("\n✓  #%s auto-approved by a timed approval: %s\n", r.ID, r.Summary())
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
