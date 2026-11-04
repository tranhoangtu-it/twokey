// Package approval holds destructive requests until a human decides, over
// channels the agent cannot answer itself (a separate terminal, a phone).
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// Request is a held HTTP request awaiting a decision.
type Request struct {
	ID            string
	Method        string
	URL           string
	Matches       []rules.Match
	Uninspectable string
	Created       time.Time
	// Nonce is embedded in out-of-band approval links so stale or forged
	// replies for a recycled ID cannot resolve a newer request.
	Nonce string
}

// ConfirmText is what a human must type in the terminal to approve: every
// distinct resource name (space-separated) so a batch of deletes cannot be
// approved by typing only the first; operation names stand in for unknown
// resources.
func (r Request) ConfirmText() string {
	seen := map[string]bool{}
	var parts []string
	for _, m := range r.Matches {
		token := NormalizeSpace(Clean(m.Resource))
		if token == "" { // unknown or blank resource: confirm the operation
			token = NormalizeSpace(Clean(m.Operation))
		}
		if token == "" {
			continue
		}
		if !seen[token] {
			seen[token] = true
			parts = append(parts, token)
		}
	}
	if len(parts) == 0 {
		return "yes"
	}
	return strings.Join(parts, " ")
}

// Clean replaces control characters (including ESC, so ANSI sequences are
// defused) in request-derived strings before they are shown to a human.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || isLayoutControl(r) {
			return '?'
		}
		return r
	}, s)
}

// isLayoutControl reports Unicode characters that reorder or break the
// displayed text (bidi overrides/isolates, line and paragraph separators),
// which could make a resource name look like something else.
func isLayoutControl(r rune) bool {
	switch {
	case r == 0x200e, r == 0x200f, r == 0x061c: // LRM, RLM, ALM
		return true
	case r >= 0x202a && r <= 0x202e: // embeddings and overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // isolates
		return true
	case r == 0x2028, r == 0x2029: // line / paragraph separator
		return true
	}
	return false
}

// NormalizeSpace collapses runs of whitespace to single spaces.
func NormalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// Summary is a one-line description for notifications and logs.
func (r Request) Summary() string {
	if len(r.Matches) == 0 {
		return Clean(fmt.Sprintf("uninspectable %s %s", r.Method, r.URL))
	}
	m := r.Matches[0]
	target := m.Resource
	if target == "" {
		target = "unknown resource"
	}
	s := Clean(fmt.Sprintf("%s %s on %s", m.Provider, m.Operation, target))
	if n := len(r.Matches) - 1; n > 0 {
		s += fmt.Sprintf(" (+%d more)", n)
	}
	return s
}

// Decision is the outcome of a hold.
type Decision struct {
	Approved bool   `json:"approved"`
	By       string `json:"by"`     // "terminal", "ntfy", "timeout"
	Reason   string `json:"reason"` // human-readable
}

// Notifier is an approval channel.
type Notifier interface {
	Notify(Request)
	// Closed tells the channel a request was decided (possibly elsewhere).
	Closed(Request, Decision)
}

type entry struct {
	req Request
	ch  chan Decision
}

// Broker tracks pending requests; the first decision from any channel wins.
type Broker struct {
	timeout   time.Duration
	seq       atomic.Uint64
	mu        sync.Mutex
	pending   map[string]*entry
	notifiers []Notifier
	observe   atomic.Bool
	grants    *Grants
}

// GrantObserver is told when a timed approval decided a request.
type GrantObserver interface {
	Granted(Request, Decision)
}

// Grants returns the broker's timed approvals.
func (b *Broker) Grants() *Grants { return b.grants }

// SetObserve switches observe mode: every request that would be held is
// approved at once (By "observe") and reported to Observer channels only.
// It is for trying twokey safely — nothing is protected while it is on.
func (b *Broker) SetObserve(on bool) { b.observe.Store(on) }

// Observing reports whether observe mode is on.
func (b *Broker) Observing() bool { return b.observe.Load() }

// NewBroker returns a broker that denies requests nobody answers in timeout.
func NewBroker(timeout time.Duration) *Broker {
	return &Broker{timeout: timeout, pending: map[string]*entry{}, grants: NewGrants()}
}

// AddNotifier registers an approval channel. Call before serving traffic.
func (b *Broker) AddNotifier(n Notifier) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.notifiers = append(b.notifiers, n)
}

// Decide blocks until the request is approved, denied, times out, or ctx ends.
// It returns the request as registered (with ID and timestamps) and the outcome.
func (b *Broker) Decide(ctx context.Context, req Request) (Request, Decision) {
	req.ID = strconv.FormatUint(b.seq.Add(1), 10)
	req.Nonce = randomNonce()
	req.Created = time.Now()
	if b.observe.Load() {
		return req, b.observed(req)
	}
	if g, ok := b.grants.Match(req); ok {
		return req, b.granted(req, g)
	}
	e := &entry{req: req, ch: make(chan Decision, 1)}

	b.mu.Lock()
	b.pending[req.ID] = e
	notifiers := append([]Notifier(nil), b.notifiers...)
	b.mu.Unlock()

	// Synchronous so the prompt always precedes the outcome; notifiers that
	// do network I/O must not block here (ntfy publishes in a goroutine).
	for _, n := range notifiers {
		n.Notify(req)
	}

	var d Decision
	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	select {
	case d = <-e.ch:
	case <-timer.C:
		d = b.expire(e, Decision{By: "timeout", Reason: fmt.Sprintf("no human decision within %s", b.timeout)})
	case <-ctx.Done():
		d = b.expire(e, Decision{By: "client", Reason: "client went away"})
	}
	for _, n := range notifiers {
		n.Closed(req, d)
	}
	return req, d
}

func (b *Broker) observed(req Request) Decision {
	b.mu.Lock()
	notifiers := append([]Notifier(nil), b.notifiers...)
	b.mu.Unlock()
	for _, n := range notifiers {
		if o, ok := n.(Observer); ok {
			o.Observed(req)
		}
	}
	return Decision{Approved: true, By: "observe", Reason: "observe mode: would have been held, forwarded unprotected"}
}

func (b *Broker) granted(req Request, g Grant) Decision {
	d := Decision{Approved: true, By: "grant",
		Reason: fmt.Sprintf("covered by timed approval #%d (until %s)", g.ID, g.Expires.Format(time.TimeOnly))}
	b.mu.Lock()
	notifiers := append([]Notifier(nil), b.notifiers...)
	b.mu.Unlock()
	for _, n := range notifiers {
		if o, ok := n.(GrantObserver); ok {
			o.Granted(req, d)
		}
	}
	return d
}

// expire removes e unless a decision raced in, which then wins.
func (b *Broker) expire(e *entry, d Decision) Decision {
	b.mu.Lock()
	_, still := b.pending[e.req.ID]
	delete(b.pending, e.req.ID)
	b.mu.Unlock()
	if !still {
		return <-e.ch
	}
	return d
}

// Resolve decides a pending request. It returns false if id is unknown or
// already decided.
func (b *Broker) Resolve(id string, d Decision) bool {
	return b.resolve(id, "", false, d)
}

// ResolveWithNonce is Resolve for out-of-band channels that echo the nonce.
func (b *Broker) ResolveWithNonce(id, nonce string, d Decision) bool {
	return b.resolve(id, nonce, true, d)
}

func (b *Broker) resolve(id, nonce string, checkNonce bool, d Decision) bool {
	b.mu.Lock()
	e, ok := b.pending[id]
	if ok && checkNonce && e.req.Nonce != nonce {
		ok = false
	}
	if ok {
		delete(b.pending, id)
	}
	b.mu.Unlock()
	if ok {
		e.ch <- d
	}
	return ok
}

// DenyAll denies every pending request (e.g. on shutdown) so waiting
// agents get a clear 403 instead of a dropped connection. It returns how
// many were denied.
func (b *Broker) DenyAll(reason string) int {
	n := 0
	for _, r := range b.Pending() {
		if b.Resolve(r.ID, Decision{By: "shutdown", Reason: reason}) {
			n++
		}
	}
	return n
}

// Get returns a pending request.
func (b *Broker) Get(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.pending[id]
	if !ok {
		return Request{}, false
	}
	return e.req, true
}

// Pending lists pending requests, oldest first.
func (b *Broker) Pending() []Request {
	b.mu.Lock()
	out := make([]Request, 0, len(b.pending))
	for _, e := range b.pending {
		out = append(out, e.req)
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func randomNonce() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
