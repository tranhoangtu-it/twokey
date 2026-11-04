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

// Grant pre-approves one exact (rule, resource) pair until Expires.
type Grant struct {
	RuleID   string
	Resource string
	Expires  time.Time
}

// Grants holds timed approvals in memory only: they die with the process.
type Grants struct {
	mu   sync.Mutex
	list []Grant
	now  func() time.Time
}

// NewGrants returns an empty grant set.
func NewGrants() *Grants { return &Grants{now: time.Now} }

// AddFor grants every match of r for d. Requests twokey could not fully
// read, or whose resource is unknown, can never be granted: a grant must
// name exactly what it covers.
func (g *Grants) AddFor(r Request, d time.Duration) ([]Grant, error) {
	if d <= 0 || d > MaxGrant {
		return nil, fmt.Errorf("a timed approval lasts at most %s", MaxGrant)
	}
	if r.Uninspectable != "" || len(r.Matches) == 0 {
		return nil, errors.New("cannot grant a request twokey could not inspect")
	}
	for _, m := range r.Matches {
		if m.Resource == "" {
			return nil, errors.New("cannot grant an unknown resource; approve it once instead")
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	exp := g.now().Add(d)
	var added []Grant
	for _, m := range r.Matches {
		gr := Grant{RuleID: m.RuleID, Resource: m.Resource, Expires: exp}
		g.list = append(g.list, gr)
		added = append(added, gr)
	}
	return added, nil
}

// Covers reports whether every match of r is covered by a live grant.
func (g *Grants) Covers(r Request) bool {
	if r.Uninspectable != "" || len(r.Matches) == 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	for _, m := range r.Matches {
		if m.Resource == "" || !g.hasLocked(m.RuleID, m.Resource) {
			return false
		}
	}
	return true
}

func (g *Grants) hasLocked(rule, resource string) bool {
	for _, gr := range g.list {
		if gr.RuleID == rule && gr.Resource == resource {
			return true
		}
	}
	return false
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

// Revoke removes the n-th live grant (1-based, as shown by List).
func (g *Grants) Revoke(n int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	if n < 1 || n > len(g.list) {
		return false
	}
	g.list = append(g.list[:n-1], g.list[n:]...)
	return true
}
