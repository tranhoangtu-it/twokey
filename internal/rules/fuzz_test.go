package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// fixtureRequests returns every request of the builtin rule fixtures, the
// seed corpus of the fuzz targets below.
func fixtureRequests(f *testing.F) []Request {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*.http"))
	if err != nil || len(files) == 0 {
		f.Fatalf("no fixtures: %v", err)
	}
	var out []Request
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		fx, err := ParseFixture(strings.TrimSuffix(filepath.Base(name), ".http"), data)
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, fx.Held.Req)
		for _, s := range fx.Safe {
			out = append(out, s.Req)
		}
	}
	return out
}

func fuzzEngine(f *testing.F) *Engine {
	f.Helper()
	packs, err := BuiltinPacks()
	if err != nil {
		f.Fatal(err)
	}
	e, err := NewEngine(packs)
	if err != nil {
		f.Fatal(err)
	}
	return e
}

func ruleSet(v Verdict) map[string]bool {
	out := map[string]bool{}
	for _, m := range v.Matches {
		out[m.RuleID] = true
	}
	return out
}

func FuzzEvaluate(f *testing.F) {
	e := fuzzEngine(f)
	for _, r := range fixtureRequests(f) {
		f.Add(r.Method, r.Host, r.Path, r.Query, r.Header.Get("X-Amz-Target"), r.Body)
	}
	f.Add("POST", "api.github.com", "/repos/a/../b/c", "_method=DELETE", "", []byte(nil))
	f.Fuzz(func(t *testing.T, method, host, p, query, target string, body []byte) {
		h := http.Header{}
		if target != "" {
			h.Set("X-Amz-Target", target)
		}
		req := Request{Method: method, Host: host, Path: p, Query: query, Header: h, Body: body}
		v := e.Evaluate(req)

		// The cleaned path is never weaker than the raw one.
		cleaned := req
		cleaned.Path = cleanPath(p)
		cv := e.Evaluate(cleaned)
		if cv.Hold() && !v.Hold() {
			t.Fatalf("cleaned path %q is held but raw %q is not", cleaned.Path, p)
		}
		got := ruleSet(v)
		for id := range ruleSet(cv) {
			if !got[id] {
				t.Fatalf("rule %s fires on cleaned %q but not on raw %q", id, cleaned.Path, p)
			}
		}

		// Method case and host spelling do not change the verdict.
		alt := req
		alt.Method = strings.ToLower(method)
		alt.Host = strings.ToUpper(host)
		if !strings.Contains(host, ":") {
			alt.Host += "."
		}
		if av := e.Evaluate(alt); av.Hold() != v.Hold() {
			t.Fatalf("verdict depends on method case or host spelling: %+v vs %+v", v, av)
		}
	})
}

// directMutationFields lists the top-level fields of the mutations a server
// would run, without following fragments: an independent lower bound for
// what parseGraphQLBody must report.
func directMutationFields(p graphqlPayload) []string {
	doc, err := parser.ParseQuery(&ast.Source{Input: p.Query})
	if err != nil {
		return nil
	}
	var out []string
	for _, op := range doc.Operations {
		if op.Operation != ast.Mutation || (p.OperationName != "" && len(doc.Operations) > 1 && op.Name != p.OperationName) {
			continue
		}
		for _, sel := range op.SelectionSet {
			if fld, ok := sel.(*ast.Field); ok {
				out = append(out, fld.Name)
			}
		}
	}
	return out
}

func FuzzParseGraphQLBody(f *testing.F) {
	for _, r := range fixtureRequests(f) {
		if strings.Contains(string(r.Body), "query") || strings.Contains(r.Query, "query") {
			f.Add(r.Query, r.Body)
		}
	}
	f.Add("", []byte(`{"query":"mutation { ...F } fragment F on Mutation { a: projectDelete(id: \"p\") }"}`))
	f.Add("query=mutation%7BvolumeDelete(volumeId%3A%22v%22)%7D", []byte(nil))
	f.Add("", []byte(fanOutFragments(3, 3)))
	f.Fuzz(func(t *testing.T, query string, body []byte) {
		req := Request{Method: "POST", Host: "x", Path: "/graphql", Query: query, Body: body}
		calls, err := parseGraphQLBody(req)
		if errors.Is(err, errNoPayload) {
			if len(bytes.TrimSpace(body)) != 0 {
				t.Fatalf("errNoPayload with a body %q", body)
			}
			return
		}
		if err != nil {
			return // the engine holds it as uninspectable
		}
		payloads, perr := graphqlPayloads(req)
		if perr != nil {
			t.Fatalf("parse succeeded but payloads failed: %v", perr)
		}
		found := map[string]bool{}
		for _, c := range calls.mutations {
			found[c.name] = true
		}
		for _, p := range payloads {
			for _, name := range directMutationFields(p) {
				if !found[name] {
					t.Fatalf("mutation field %q missed in %q", name, p.Query)
				}
			}
		}
	})
}

func FuzzParseAWSCall(f *testing.F) {
	for _, r := range fixtureRequests(f) {
		if r.Header.Get("X-Amz-Target") != "" || strings.Contains(string(r.Body)+r.Query, "Action=") {
			f.Add(r.Query, r.Header.Get("X-Amz-Target"), r.Body)
		}
	}
	f.Add("", "", []byte("Action=DeleteDBInstance&DBInstanceIdentifier=prod&Note=a;b"))
	f.Add("Action=DescribeDBInstances", "", []byte("Action=DeleteDBInstance&x=%zz"))
	f.Fuzz(func(t *testing.T, query, target string, body []byte) {
		h := http.Header{}
		if target != "" {
			h.Set("X-Amz-Target", target)
		}
		call, err := parseAWSCall(Request{Query: query, Header: h, Body: body})
		_, qerr := url.ParseQuery(query)
		trimmed := bytes.TrimSpace(body)
		isForm := len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' && trimmed[0] != '<'
		form, ferr := url.ParseQuery(string(trimmed))
		if qerr != nil || (isForm && ferr != nil) {
			if err == nil {
				t.Fatalf("malformed query %q / body %q accepted", query, body)
			}
			return
		}
		if err != nil {
			t.Fatalf("well-formed input rejected: %v", err)
		}
		have := map[string]bool{}
		for _, a := range call.actions {
			have[a] = true
		}
		if isForm {
			for _, a := range form["Action"] {
				if a = strings.TrimSpace(a); a != "" && !have[a] {
					t.Fatalf("form Action %q missing from %v", a, call.actions)
				}
			}
		}
	})
}

func FuzzPathTemplateMatch(f *testing.F) {
	packs, err := BuiltinPacks()
	if err != nil {
		f.Fatal(err)
	}
	reqs := fixtureRequests(f)
	for _, p := range packs {
		for i, r := range p.Rules {
			if r.Path != "" {
				f.Add(r.Path, reqs[i%len(reqs)].Path)
			}
		}
	}
	f.Add("/v2/droplets/{droplet}", "/v2/x/../droplets/./1")
	f.Add("/repos/{owner}/{repo}/git/refs/{ref...}", "/repos/a/b/git/refs/heads/x")
	f.Fuzz(func(t *testing.T, tpl, p string) {
		pt := parsePathTemplate(tpl)
		vars, ok := pt.match(p)
		if ok {
			for k, v := range vars {
				if v == "" {
					t.Fatalf("empty capture %q for %q on %q", k, tpl, p)
				}
			}
		}
		// Whatever the cleaned path matches is reachable through candidatePaths.
		if _, cok := pt.match(cleanPath(p)); cok {
			reached := false
			for _, c := range candidatePaths(p) {
				if _, ok := pt.match(c); ok {
					reached = true
				}
			}
			if !reached {
				t.Fatalf("cleaned %q matches %q but no candidate of %q does", cleanPath(p), tpl, p)
			}
		}
		// Literal segments are case-insensitive.
		if !strings.Contains(tpl, "{") && isASCII(p) {
			_, uok := pt.match(strings.ToUpper(p))
			_, lok := pt.match(strings.ToLower(p))
			if uok != ok || lok != ok {
				t.Fatalf("case changes the match of %q on %q", tpl, p)
			}
		}
	})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func FuzzFlattenBody(f *testing.F) {
	for _, r := range fixtureRequests(f) {
		f.Add(r.Body)
	}
	f.Add([]byte(`{"data":{"attributes":{"is-destroy":true}}} trailing`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := flattenBody(raw)
		trimmed := bytes.TrimSpace(raw)
		if err == nil && len(trimmed) > 0 && !json.Valid(trimmed) {
			t.Fatalf("non-JSON body %q accepted: %v", raw, out)
		}
		if err == nil && out == nil {
			t.Fatal("nil map without error")
		}
	})
}

func FuzzAllow(f *testing.F) {
	f.Add([]byte("allow:\n  - rule: vercel.project.delete\n    resource: \"pr-*\"\n"), "vercel.project.delete", "pr-1")
	f.Add([]byte("allow:\n  - rule: \"*\"\n    resource: \"*\"\n"), "github.repo.delete", "")
	f.Add([]byte("allow:\n  - rule: a.*\n    resource: \"x\\ny*\"\n"), "a.b", "x\nyz")
	f.Fuzz(func(t *testing.T, data []byte, ruleID, resource string) {
		allows, err := ParseAllow(data)
		if err != nil {
			return
		}
		m := Match{RuleID: ruleID, Resource: resource}
		if _, ok := Allowed(Match{RuleID: ruleID}, allows); ok {
			t.Fatal("an unknown resource was allowed")
		}
		if v, _ := ApplyAllow(Verdict{Matches: []Match{m}, Uninspectable: "x"}, allows); !v.Hold() || v.Uninspectable != "x" {
			t.Fatalf("an uninspectable verdict was changed: %+v", v)
		}
		_, ok := Allowed(m, allows)
		v, allowed := ApplyAllow(Verdict{Matches: []Match{m}}, allows)
		if ok != (len(allowed) == 1) || ok == v.Hold() {
			t.Fatalf("Allowed=%v but ApplyAllow kept %+v allowed %+v", ok, v, allowed)
		}
	})
}
