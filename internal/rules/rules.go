// Package rules decides whether an outgoing HTTP request performs a
// destructive operation on a cloud provider API. Rules are grouped in
// provider "packs" (YAML) and understand three request shapes: plain REST
// (method + path template), GraphQL (mutation field names) and AWS
// (Query-protocol Action / JSON-protocol X-Amz-Target).
package rules

import (
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
)

// Rule describes one destructive operation. Every matcher that is set must
// match for the rule to fire.
type Rule struct {
	ID       string        `yaml:"id"`
	Hosts    []string      `yaml:"hosts"`
	Methods  []string      `yaml:"methods"`
	Path     string        `yaml:"path"`
	GraphQL  *GraphQLMatch `yaml:"graphql"`
	AWS      *AWSMatch     `yaml:"aws"`
	Resource string        `yaml:"resource"`
	Severity string        `yaml:"severity"`
	Message  string        `yaml:"message"`

	provider string
	tpl      *pathTemplate
}

// GraphQLMatch fires when any listed top-level mutation field is selected.
type GraphQLMatch struct {
	Mutations []string `yaml:"mutations"`
}

// AWSMatch fires when the AWS API action is one of Actions.
type AWSMatch struct {
	Actions []string `yaml:"actions"`
}

// Pack is the on-disk YAML unit: one provider, many rules.
type Pack struct {
	Provider string `yaml:"provider"`
	Docs     string `yaml:"docs"`
	Rules    []Rule `yaml:"rules"`
}

// Request is the subset of an HTTP request the engine inspects.
type Request struct {
	Method string
	Host   string // may include :port
	Path   string // URL path without query
	Query  string // raw query string
	Header http.Header
	Body   []byte
}

// Match is one rule that fired, with the operation and resource it targets.
type Match struct {
	RuleID    string `json:"rule"`
	Provider  string `json:"provider"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}

// Verdict is the outcome of evaluating a request. A request must be held for
// human approval when it has matches or is uninspectable.
type Verdict struct {
	Matches []Match `json:"matches,omitempty"`
	// Uninspectable explains why a request to a watched host could not be
	// parsed well enough to rule it safe (fail closed).
	Uninspectable string `json:"uninspectable,omitempty"`
}

// Hold reports whether the request needs a human decision.
func (v Verdict) Hold() bool { return len(v.Matches) > 0 || v.Uninspectable != "" }

// Engine evaluates requests against a fixed rule set.
type Engine struct {
	rules []*Rule
}

// NewEngine validates packs and builds an engine.
func NewEngine(packs []Pack) (*Engine, error) {
	e := &Engine{}
	seen := map[string]bool{}
	for _, p := range packs {
		for i := range p.Rules {
			r := p.Rules[i]
			if err := r.validate(); err != nil {
				return nil, fmt.Errorf("pack %q: %w", p.Provider, err)
			}
			if seen[r.ID] {
				return nil, fmt.Errorf("pack %q: duplicate rule id %q", p.Provider, r.ID)
			}
			seen[r.ID] = true
			r.provider = p.Provider
			if r.Path != "" {
				r.tpl = parsePathTemplate(r.Path)
			}
			methods := make([]string, len(r.Methods))
			for j, m := range r.Methods {
				methods[j] = strings.ToUpper(m)
			}
			r.Methods = methods
			e.rules = append(e.rules, &r)
		}
	}
	sort.SliceStable(e.rules, func(i, j int) bool { return e.rules[i].ID < e.rules[j].ID })
	return e, nil
}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule without id")
	}
	if len(r.Hosts) == 0 {
		return fmt.Errorf("rule %q: hosts is required", r.ID)
	}
	if r.Path == "" && r.GraphQL == nil && r.AWS == nil && len(r.Methods) == 0 {
		return fmt.Errorf("rule %q: needs at least one of methods, path, graphql, aws", r.ID)
	}
	if r.GraphQL != nil && len(r.GraphQL.Mutations) == 0 {
		return fmt.Errorf("rule %q: graphql.mutations is empty", r.ID)
	}
	if r.AWS != nil && len(r.AWS.Actions) == 0 {
		return fmt.Errorf("rule %q: aws.actions is empty", r.ID)
	}
	for _, h := range r.Hosts {
		if _, err := path.Match(h, "x"); err != nil {
			return fmt.Errorf("rule %q: bad host pattern %q", r.ID, h)
		}
	}
	return nil
}

// Rules returns copies of the loaded rules.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, *r)
	}
	return out
}

// Provider returns the pack a rule came from.
func (r Rule) Provider() string { return r.provider }

// HostWatched reports whether any rule targets host. Only watched hosts are
// TLS-intercepted; everything else is tunneled untouched.
func (e *Engine) HostWatched(host string) bool {
	h := normalizeHost(host)
	for _, r := range e.rules {
		if r.matchHost(h) {
			return true
		}
	}
	return false
}

// NeedsBody reports whether evaluating requests to host requires the request
// body (GraphQL or AWS rules). Path-only hosts can stream large uploads.
func (e *Engine) NeedsBody(host string) bool {
	h := normalizeHost(host)
	for _, r := range e.rules {
		if (r.GraphQL != nil || r.AWS != nil) && r.matchHost(h) {
			return true
		}
	}
	return false
}

// Evaluate returns every rule that fires for req.
func (e *Engine) Evaluate(req Request) Verdict {
	host := normalizeHost(req.Host)
	method := strings.ToUpper(req.Method)
	var v Verdict
	var gql *graphqlCalls // parsed lazily, at most once
	var gqlErr error
	var aws *awsCall

	for _, r := range e.rules {
		if !r.matchHost(host) {
			continue
		}
		if len(r.Methods) > 0 && !contains(r.Methods, method) {
			continue
		}
		vars := map[string]string{"host": host}
		if r.tpl != nil {
			captured, ok := r.tpl.match(req.Path)
			if !ok {
				continue
			}
			vars = mergeVars(vars, captured)
		}

		switch {
		case r.GraphQL != nil:
			if gql == nil && gqlErr == nil {
				gql, gqlErr = parseGraphQLBody(req)
			}
			if gqlErr != nil {
				if method == http.MethodPost && v.Uninspectable == "" {
					v.Uninspectable = fmt.Sprintf("GraphQL request to %s could not be inspected: %v", host, gqlErr)
				}
				continue
			}
			for _, call := range gql.mutations {
				if contains(r.GraphQL.Mutations, call.name) {
					v.Matches = append(v.Matches, r.toMatch(call.name, mergeVars(vars, call.args)))
				}
			}
		case r.AWS != nil:
			if aws == nil {
				aws = parseAWSCall(req)
			}
			if aws.action != "" && contains(r.AWS.Actions, aws.action) {
				v.Matches = append(v.Matches, r.toMatch(aws.action, mergeVars(vars, aws.params)))
			}
		default:
			v.Matches = append(v.Matches, r.toMatch(method+" "+r.Path, vars))
		}
	}
	return v
}

func (r *Rule) toMatch(op string, vars map[string]string) Match {
	return Match{
		RuleID:    r.ID,
		Provider:  r.provider,
		Severity:  defaultString(r.Severity, "high"),
		Message:   r.Message,
		Operation: op,
		Resource:  expandResource(r.Resource, vars),
	}
}

func (r *Rule) matchHost(host string) bool {
	for _, pattern := range r.Hosts {
		if ok, _ := path.Match(strings.ToLower(pattern), host); ok {
			return true
		}
	}
	return false
}

// expandResource fills "{name}" placeholders from vars; "{a|b}" takes the
// first non-empty of a and b. If any placeholder is unknown the result is
// empty so callers can show "unknown resource".
func expandResource(tpl string, vars map[string]string) string {
	var b strings.Builder
	rest := tpl
	for {
		start := strings.IndexByte(rest, '{')
		end := strings.IndexByte(rest, '}')
		if start < 0 || end < start {
			b.WriteString(rest)
			return b.String()
		}
		val := ""
		for _, key := range strings.Split(rest[start+1:end], "|") {
			if val = vars[key]; val != "" {
				break
			}
		}
		if val == "" {
			return ""
		}
		b.WriteString(rest[:start])
		b.WriteString(val)
		rest = rest[end+1:]
	}
}

// normalizeHost lowercases and strips any port.
func normalizeHost(host string) string {
	h := strings.ToLower(host)
	if strings.HasPrefix(h, "[") { // IPv6 literal
		if i := strings.LastIndex(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	// "api.github.com." is the same host as "api.github.com" (FQDN form).
	return strings.TrimRight(h, ".")
}

func mergeVars(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
