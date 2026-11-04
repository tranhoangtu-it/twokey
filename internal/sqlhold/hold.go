// Package sqlhold is the approval step shared by the database guards:
// classify a statement, apply allow rules, hold it for a human, audit it.
package sqlhold

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/rules"
	"github.com/tranhoangtu-it/twokey/internal/sqlclass"
)

// Hint is shown to the agent (as the database error hint/detail).
const Hint = "Do not retry or work around this statement. Tell the user what you tried to run and ask them to approve it in the twokey window or run it themselves."

// Guard holds destructive statements for one database guard.
type Guard struct {
	Provider string // "postgres" or "mysql": rule ids are <provider>.<kind-slug>
	Broker   *approval.Broker
	Audit    *audit.Log
	Allow    []rules.Allow
	Logf     func(string, ...any)
}

// Check is CheckContext without a client watch.
func (g *Guard) Check(findings []sqlclass.Finding, target string, alive func() bool) string {
	return g.CheckContext(context.Background(), findings, target, alive)
}

// CheckContext returns "" when the statement may run, else the message to
// send back to the client as a database error. A hold ends (denied) when
// ctx ends, e.g. because the client disconnected; alive reports whether the
// client is still connected once approved (an approved statement for a
// gone client is dropped).
//
// The whole message runs or nothing does, so allow rules apply all or
// nothing: unless every match is pre-approved, every match is held.
// Uninspectable findings are never pre-approved.
func (g *Guard) CheckContext(ctx context.Context, findings []sqlclass.Finding, target string, alive func() bool) string {
	if len(findings) == 0 {
		return ""
	}
	v := verdict(g.Provider, findings)
	if rest, allowed := rules.ApplyAllow(v, g.Allow); !rest.Hold() {
		g.write(audit.Entry{Time: time.Now(), Method: "SQL", URL: target, Matches: allowed,
			Approved: true, By: "allowlist", Reason: "pre-approved by allow rules"})
		return ""
	}
	held, d := g.Broker.Decide(ctx, approval.Request{Method: "SQL", URL: target, Matches: v.Matches, Uninspectable: v.Uninspectable})
	if d.Approved && alive != nil && !alive() {
		d = approval.Decision{By: "client", Reason: "client disconnected before the decision"}
	}
	g.write(audit.Entry{Time: time.Now(), ID: held.ID, Method: held.Method, URL: held.URL,
		Matches: held.Matches, Uninspectable: held.Uninspectable, Approved: d.Approved, By: d.By, Reason: d.Reason})
	if d.Approved {
		return ""
	}
	return fmt.Sprintf("twokey blocked a destructive statement (%s): %s", d.Reason, held.Summary())
}

// verdict turns findings into rule matches; uninspectable findings also set
// the verdict's Uninspectable reason, which allow rules and grants never
// cover.
func verdict(provider string, findings []sqlclass.Finding) rules.Verdict {
	v := rules.Verdict{}
	var reasons []string
	for _, f := range findings {
		v.Matches = append(v.Matches, rules.Match{
			RuleID: provider + "." + RuleSlug(f.Kind), Provider: provider, Severity: "critical",
			Operation: f.Kind, Resource: f.Target, Message: f.Statement,
		})
		if f.Kind == sqlclass.KindUninspectable {
			reasons = appendUnique(reasons, f.Reason)
		}
	}
	v.Uninspectable = strings.Join(reasons, "; ")
	return v
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func (g *Guard) write(e audit.Entry) {
	if err := g.Audit.Write(e); err != nil && g.Logf != nil {
		g.Logf("audit log write failed: %v", err)
	}
}

// RuleSlug turns a finding kind into a rule id suffix:
// "DROP TABLE" -> "drop-table", "ALTER TABLE … DROP" -> "alter-table-drop".
func RuleSlug(kind string) string {
	return strings.NewReplacer(" … ", "-", " ", "-").Replace(strings.ToLower(kind))
}

// WatchClient returns a context that ends when the client closes its side
// of conn while a statement is held. It reads (peeks) from r in the
// background, so the caller must not read from r until stop returns; stop
// (safe to call more than once) also clears the read deadline. Bytes the
// client sends meanwhile stay buffered in r. The context stays valid after
// stop, so ctx.Err() still tells whether the client left.
func WatchClient(conn net.Conn, r *bufio.Reader) (ctx context.Context, stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	stopping := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := r.Peek(1); err != nil {
			select {
			case <-stopping: // our own deadline below ended the peek
			default:
				cancel() // EOF or reset: the client is gone
			}
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			close(stopping)
			_ = conn.SetReadDeadline(time.Now())
			<-done
			_ = conn.SetReadDeadline(time.Time{})
		})
	}
}
