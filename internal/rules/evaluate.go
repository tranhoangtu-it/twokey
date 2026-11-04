package rules

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
)

// methodOverrideHeaders are honoured by many frameworks as "the real method"
// of a POST, so a rule for DELETE must also see a POST that asks for DELETE.
var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// Evaluate returns every rule that fires for req. The request is evaluated
// under every method it may be executed as (its own and any override) and
// against both the raw and the dot-segment-resolved path; a match on any of
// them holds.
func (e *Engine) Evaluate(req Request) Verdict {
	ev := &evaluation{req: req, host: normalizeHost(req.Host)}
	methods := effectiveMethods(req)
	paths := candidatePaths(req.Path)
	for _, r := range e.rules {
		if !r.matchHost(ev.host) {
			continue
		}
		if len(r.UnlessQuery) > 0 && hasAnyQueryKey(req.Query, r.UnlessQuery) {
			continue
		}
		for _, method := range methods {
			if len(r.Methods) > 0 && !contains(r.Methods, method) {
				continue
			}
			ev.evalPaths(r, method, paths)
			if len(r.Methods) == 0 {
				break // the method only labels the operation: one pass is enough
			}
		}
	}
	return ev.v
}

func (ev *evaluation) evalPaths(r *Rule, method string, paths []string) {
	for _, p := range paths {
		vars := queryVars(ev.req.Query)
		vars["host"] = ev.host
		if r.tpl == nil {
			ev.apply(r, method, vars)
			return // the path plays no part
		}
		captured, ok := r.tpl.match(p)
		if !ok {
			continue
		}
		ev.apply(r, method, mergeVars(vars, captured))
	}
}

// evaluation holds the per-request state of Evaluate: bodies are decoded
// lazily, at most once, and only for rules whose host and path matched.
type evaluation struct {
	req  Request
	host string
	v    Verdict

	gqlDone, awsDone, bodyDone bool
	gql                        *graphqlCalls
	aws                        *awsCall
	body                       map[string]string // flattened JSON body
	gqlErr, awsErr, bodyErr    error
}

func (ev *evaluation) uninspectable(format string, args ...any) {
	if ev.v.Uninspectable == "" {
		ev.v.Uninspectable = fmt.Sprintf(format, args...)
	}
}

func (ev *evaluation) apply(r *Rule, method string, vars map[string]string) {
	switch {
	case r.GraphQL != nil:
		if !ev.gqlDone {
			ev.gql, ev.gqlErr = parseGraphQLBody(ev.req)
			ev.gqlDone = true
		}
		if ev.gqlErr != nil {
			if !errors.Is(ev.gqlErr, errNoPayload) {
				ev.uninspectable("GraphQL request to %s could not be inspected: %v", ev.host, ev.gqlErr)
			}
			return
		}
		for _, call := range ev.gql.mutations {
			if contains(r.GraphQL.Mutations, call.name) {
				ev.add(r.toMatch(call.name, mergeVars(vars, call.args)))
			}
		}
	case r.AWS != nil:
		if !ev.awsDone {
			ev.aws, ev.awsErr = parseAWSCall(ev.req)
			ev.awsDone = true
		}
		if ev.awsErr != nil {
			ev.uninspectable("AWS request to %s could not be inspected: %v", ev.host, ev.awsErr)
			return
		}
		for _, action := range ev.aws.actions {
			if contains(r.AWS.Actions, action) {
				ev.add(r.toMatch(action, mergeVars(vars, ev.aws.params)))
			}
		}
	case r.JSON != nil:
		if !ev.bodyDone {
			ev.body, ev.bodyErr = flattenBody(ev.req.Body)
			ev.bodyDone = true
		}
		if ev.bodyErr != nil {
			ev.uninspectable("JSON body to %s could not be inspected: %v", ev.host, ev.bodyErr)
			return
		}
		if ev.body["json."+r.JSON.Field] == r.JSON.Equals {
			ev.add(r.toMatch(method+" "+r.Path, mergeVars(vars, ev.body)))
		}
	default:
		ev.add(r.toMatch(method+" "+r.Path, vars))
	}
}

// add records m once: the raw and the cleaned path often yield the same match.
func (ev *evaluation) add(m Match) {
	if !slices.Contains(ev.v.Matches, m) {
		ev.v.Matches = append(ev.v.Matches, m)
	}
}

// effectiveMethods returns the request method plus every method override
// it carries (headers and a "_method" query parameter), uppercased.
func effectiveMethods(req Request) []string {
	out := []string{strings.ToUpper(req.Method)}
	add := func(m string) {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" && !contains(out, m) {
			out = append(out, m)
		}
	}
	for _, h := range methodOverrideHeaders {
		for _, v := range req.Header.Values(h) {
			for _, m := range strings.Split(v, ",") {
				add(m)
			}
		}
	}
	for _, m := range lenientQueryValues(req.Query, "_method") {
		add(m)
	}
	return out
}

// lenientQueryValues returns every value of key in rawQuery, splitting on
// both '&' and ';' and keeping undecodable text as is: a malformed
// neighbour must not hide an override from the engine.
func lenientQueryValues(rawQuery, key string) []string {
	var out []string
	for _, pair := range strings.FieldsFunc(rawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(pair, "=")
		if lenientUnescape(k) == key {
			out = append(out, lenientUnescape(v))
		}
	}
	return out
}

func lenientUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// candidatePaths returns the raw path and, when it differs, the path with
// empty and dot segments resolved the way most servers normalise it.
// Request.Path is already percent-decoded (encoded dots and slashes are
// real ones here); it is never decoded again.
func candidatePaths(p string) []string {
	clean := cleanPath(p)
	if slices.Equal(splitPath(clean), splitPath(p)) {
		return []string{p}
	}
	return []string{p, clean}
}

// cleanPath resolves "." and ".." segments and collapses repeated slashes.
func cleanPath(p string) string { return path.Clean("/" + p) }
