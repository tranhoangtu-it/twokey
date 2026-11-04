package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// A Fixture pins a rule to real traffic: a request (taken from the
// provider's official API reference) that the rule must hold, and requests
// that must pass. Fixtures live in <rule-id>.http files:
//
//	# source: <official doc URL>
//	# resource: <expected resource>        (optional)
//	DELETE https://api.example.com/things/42
//	Header: value
//
//	optional body
//	###
//	# a request that must NOT be held
//	GET https://api.example.com/things/42
type Fixture struct {
	Name string // rule id
	Held FixtureCase
	Safe []FixtureCase
}

// FixtureCase is one request of a fixture plus its "# key: value" comments.
type FixtureCase struct {
	Req  Request
	Line string // "METHOD URL", for messages
	Meta map[string]string
}

// FixtureFailure is a rule whose fixture is missing or does not hold.
type FixtureFailure struct {
	Rule    string
	Problem string
}

// ParseFixture parses a .http fixture for rule name.
func ParseFixture(name string, data []byte) (Fixture, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var sections [][]string
	cur := []string{}
	for i, line := range lines {
		if strings.TrimSpace(line) == "###" {
			next, ok := nextNonEmpty(lines[i+1:])
			if !ok {
				break // trailing separator
			}
			if strings.HasPrefix(next, "#") || isRequestLine(next) {
				sections = append(sections, cur)
				cur = []string{}
				continue
			}
			// otherwise "###" is part of a body
		}
		cur = append(cur, line)
	}
	sections = append(sections, cur)

	f := Fixture{Name: name}
	for i, sec := range sections {
		c, err := parseCase(sec)
		if err != nil {
			return Fixture{}, fmt.Errorf("%s request %d: %w", name, i+1, err)
		}
		if i == 0 {
			f.Held = c
		} else {
			f.Safe = append(f.Safe, c)
		}
	}
	if f.Held.Meta["source"] == "" {
		return Fixture{}, fmt.Errorf("%s: first request needs a '# source: <official doc URL>' comment", name)
	}
	if len(f.Safe) == 0 {
		return Fixture{}, fmt.Errorf("%s: add at least one request after '###' that must not be held", name)
	}
	return f, nil
}

func nextNonEmpty(lines []string) (string, bool) {
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			return t, true
		}
	}
	return "", false
}

// isRequestLine reports "METHOD absolute-URL [HTTP/x]".
func isRequestLine(l string) bool {
	parts := strings.Fields(l)
	if len(parts) < 2 || len(parts) > 3 || parts[0] != strings.ToUpper(parts[0]) {
		return false
	}
	u, err := url.Parse(parts[1])
	return err == nil && u.Scheme != "" && u.Host != ""
}

func parseCase(lines []string) (FixtureCase, error) {
	c := FixtureCase{Meta: map[string]string{}}
	i := 0
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "#") {
			if k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(l, "#")), ":"); ok && !strings.Contains(k, " ") {
				c.Meta[strings.ToLower(k)] = strings.TrimSpace(v)
			}
			continue
		}
		break
	}
	if i == len(lines) {
		return c, errors.New("no request line")
	}
	parts := strings.Fields(lines[i])
	if len(parts) < 2 || len(parts) > 3 {
		return c, fmt.Errorf("want 'METHOD URL', got %q", lines[i])
	}
	u, err := url.Parse(parts[1])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return c, fmt.Errorf("need an absolute URL, got %q", parts[1])
	}
	c.Line = parts[0] + " " + parts[1]
	c.Req = Request{Method: strings.ToUpper(parts[0]), Host: u.Host, Path: u.Path, Query: u.RawQuery, Header: http.Header{}}
	i++
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			i++
			break
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return c, fmt.Errorf("bad header line %q", l)
		}
		c.Req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	if i < len(lines) {
		if body := strings.TrimSpace(strings.Join(lines[i:], "\n")); body != "" {
			c.Req.Body = []byte(body)
		}
	}
	return c, nil
}

// CheckFixture evaluates a fixture and returns what is wrong with it: the
// held request must match exactly rule f.Name (and the expected resource),
// and no safe request may be held.
func CheckFixture(e *Engine, f Fixture) []string {
	var probs []string
	v := e.Evaluate(f.Held.Req)
	if v.Uninspectable != "" {
		probs = append(probs, fmt.Sprintf("held request %q is uninspectable: %s", f.Held.Line, v.Uninspectable))
	}
	var got []string
	var match *Match
	for i := range v.Matches {
		got = append(got, v.Matches[i].RuleID)
		if v.Matches[i].RuleID == f.Name {
			match = &v.Matches[i]
		}
	}
	switch {
	case match == nil:
		probs = append(probs, fmt.Sprintf("%q is not held by this rule (matched: %v)", f.Held.Line, got))
	case f.Held.Meta["resource"] != "" && match.Resource != f.Held.Meta["resource"]:
		probs = append(probs, fmt.Sprintf("resource = %q, fixture expects %q", match.Resource, f.Held.Meta["resource"]))
	}
	for _, s := range f.Safe {
		if sv := e.Evaluate(s.Req); sv.Hold() {
			var ids []string
			for _, m := range sv.Matches {
				ids = append(ids, m.RuleID)
			}
			probs = append(probs, fmt.Sprintf("safe request %q is held (rules %v %s)", s.Line, ids, sv.Uninspectable))
		}
	}
	return probs
}

// CheckFixtureDir checks <id>.http in fsys for every rule id, and flags
// fixture files that belong to no rule.
func CheckFixtureDir(e *Engine, fsys fs.FS, ids []string) []FixtureFailure {
	var fails []FixtureFailure
	want := map[string]bool{}
	ids = slices.Sorted(slices.Values(ids)) // don't reorder the caller's slice
	for _, id := range ids {
		want[id] = true
		data, err := fs.ReadFile(fsys, id+".http")
		if err != nil {
			fails = append(fails, FixtureFailure{id, "no fixture (" + id + ".http): " + err.Error()})
			continue
		}
		f, err := ParseFixture(id, data)
		if err != nil {
			fails = append(fails, FixtureFailure{id, err.Error()})
			continue
		}
		for _, p := range CheckFixture(e, f) {
			fails = append(fails, FixtureFailure{id, p})
		}
	}
	files, err := fs.Glob(fsys, "*.http")
	if err != nil {
		fails = append(fails, FixtureFailure{"(fixtures)", err.Error()})
	}
	for _, name := range files {
		if id := strings.TrimSuffix(name, ".http"); !want[id] {
			fails = append(fails, FixtureFailure{id, "fixture for an unknown rule"})
		}
	}
	return fails
}
