// Package sqlhold is the approval step shared by the database guards:
// classify a statement, apply allow rules, hold it for a human, audit it.
package sqlhold

import (
	"context"
	"fmt"
	"strings"
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

// Check returns "" when the statement may run, else the message to send
// back to the client as a database error. alive reports whether the client
// is still connected (an approved statement for a gone client is dropped).
func (g *Guard) Check(findings []sqlclass.Finding, target string, alive func() bool) string {
	if len(findings) == 0 {
		return ""
	}
	v := rules.Verdict{}
	for _, f := range findings {
		v.Matches = append(v.Matches, rules.Match{
			RuleID: g.Provider + "." + RuleSlug(f.Kind), Provider: g.Provider, Severity: "critical",
			Operation: f.Kind, Resource: f.Target, Message: f.Statement,
		})
	}
	v, allowed := rules.ApplyAllow(v, g.Allow)
	if len(allowed) > 0 {
		g.write(audit.Entry{Time: time.Now(), Method: "SQL", URL: target, Matches: allowed,
			Approved: true, By: "allowlist", Reason: "pre-approved by allow rules"})
	}
	if !v.Hold() {
		return ""
	}
	held, d := g.Broker.Decide(context.Background(), approval.Request{Method: "SQL", URL: target, Matches: v.Matches})
	if d.Approved && alive != nil && !alive() {
		d = approval.Decision{By: "client", Reason: "client disconnected before the decision"}
	}
	g.write(audit.Entry{Time: time.Now(), ID: held.ID, Method: held.Method, URL: held.URL,
		Matches: held.Matches, Approved: d.Approved, By: d.By, Reason: d.Reason})
	if d.Approved {
		return ""
	}
	return fmt.Sprintf("twokey blocked a destructive statement (%s): %s", d.Reason, held.Summary())
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
