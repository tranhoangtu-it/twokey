package approval

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// MaxGrant caps a timed approval: long enough for a cleanup task, short
// enough that a forgotten grant expires the same hour.
const MaxGrant = time.Hour

// Grant pre-approves one exact operation until Expires: same method and
// target (host/path or database), same rule, same resource and, for SQL,
// the same statement. Approving `UPDATE users SET last_seen=now()` must not
// pre-approve `UPDATE users SET password=NULL`, nor the same call on another
// host.
type Grant struct {
	ID        int
	Method    string
	URL       string
	RuleID    string
	Resource  string
	Statement string // the match message: the SQL text for database guards
	Expires   time.Time
}

// Grants holds timed approvals in memory only: they die with the process.
type Grants struct {
	mu   sync.Mutex
	list []Grant
	next int
	now  func() time.Time
}

// NewGrants returns an empty grant set.
func NewGrants() *Grants { return &Grants{now: time.Now} }

// Check reports why r cannot be granted for d, if it cannot. Requests twokey
// could not fully read, or whose resource is unknown, are never granted: a
// grant must name exactly what it covers.
func (g *Grants) Check(r Request, d time.Duration) error {
	if d <= 0 || d > MaxGrant {
		return fmt.Errorf("a timed approval lasts at most %s", MaxGrant)
	}
	if r.Uninspectable != "" || len(r.Matches) == 0 {
		return errors.New("cannot grant a request twokey could not inspect")
	}
	for _, m := range r.Matches {
		if m.Resource == "" {
			return errors.New("cannot grant an unknown resource; approve it once instead")
		}
	}
	return nil
}

// AddFor grants every match of r for d.
func (g *Grants) AddFor(r Request, d time.Duration) ([]Grant, error) {
	if err := g.Check(r, d); err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	exp := g.now().Add(d)
	var added []Grant
	for _, m := range r.Matches {
		g.next++
		gr := Grant{ID: g.next, Method: r.Method, URL: r.URL, RuleID: m.RuleID, Resource: m.Resource,
			Statement: m.Message, Expires: exp}
		g.list = append(g.list, gr)
		added = append(added, gr)
	}
	return added, nil
}

// Match returns the soonest-expiring grant among those covering r, if every
// match of r is covered by a live grant.
func (g *Grants) Match(r Request) (Grant, bool) {
	if r.Uninspectable != "" || len(r.Matches) == 0 {
		return Grant{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	var first Grant
	for i, m := range r.Matches {
		gr, ok := g.findLocked(r, m.RuleID, m.Resource, m.Message)
		if !ok || m.Resource == "" {
			return Grant{}, false
		}
		if i == 0 || gr.Expires.Before(first.Expires) {
			first = gr
		}
	}
	return first, true
}

// Covers reports whether every match of r is covered by a live grant.
func (g *Grants) Covers(r Request) bool {
	_, ok := g.Match(r)
	return ok
}

func (g *Grants) findLocked(r Request, rule, resource, statement string) (Grant, bool) {
	for _, gr := range g.list {
		if gr.Method == r.Method && gr.URL == r.URL && gr.RuleID == rule &&
			gr.Resource == resource && gr.Statement == statement {
			return gr, true
		}
	}
	return Grant{}, false
}

func (g *Grants) pruneLocked() {
	now := g.now()
	live := g.list[:0]
	for _, gr := range g.list {
		if now.Before(gr.Expires) {
			live = append(live, gr)
		}
	}
	g.list = live
}

// List returns live grants, oldest first.
func (g *Grants) List() []Grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	return append([]Grant(nil), g.list...)
}

// Revoke removes the grant with this ID (IDs are stable: expiry of other
// grants never renumbers them).
func (g *Grants) Revoke(id int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	for i, gr := range g.list {
		if gr.ID == id {
			g.list = append(g.list[:i], g.list[i+1:]...)
			return true
		}
	}
	return false
}
