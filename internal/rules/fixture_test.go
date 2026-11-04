package rules

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

const sampleFixture = `# source: https://docs.github.com/en/rest/repos/repos#delete-a-repository
# resource: acme/prod-api
DELETE https://api.github.com/repos/acme/prod-api
Accept: application/vnd.github+json

###
# reading a repo is safe
GET https://api.github.com/repos/acme/prod-api

###
POST https://api.github.com/repos/acme/prod-api/issues
Content-Type: application/json

{"title": "hi"}
`

func TestParseFixture(t *testing.T) {
	f, err := ParseFixture("github.repo.delete", []byte(sampleFixture))
	if err != nil {
		t.Fatal(err)
	}
	if f.Held.Req.Method != "DELETE" || f.Held.Req.Host != "api.github.com" || f.Held.Req.Path != "/repos/acme/prod-api" {
		t.Fatalf("held: %+v", f.Held.Req)
	}
	if f.Held.Meta["source"] == "" || f.Held.Meta["resource"] != "acme/prod-api" {
		t.Fatalf("meta: %v", f.Held.Meta)
	}
	if f.Held.Req.Header.Get("Accept") != "application/vnd.github+json" {
		t.Fatalf("headers: %v", f.Held.Req.Header)
	}
	if len(f.Safe) != 2 || f.Safe[1].Req.Method != "POST" || string(f.Safe[1].Req.Body) != `{"title": "hi"}` {
		t.Fatalf("safe: %+v", f.Safe)
	}
}

// "###" is a separator only when a request (or its comments) follows, so a
// body line that happens to be "###" stays in the body; a trailing "###" is
// ignored.
func TestParseFixtureSeparatorEdgeCases(t *testing.T) {
	src := "# source: x\nPOST https://api.github.com/graphql\n\nline one\n###\nline three\n###\n# safe\nGET https://api.github.com/x\n###\n"
	f, err := ParseFixture("github.graphql.delete", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Held.Req.Body) != "line one\n###\nline three" || len(f.Safe) != 1 {
		t.Fatalf("body=%q safe=%d", f.Held.Req.Body, len(f.Safe))
	}
}

func TestParseFixtureRejectsIncompleteFiles(t *testing.T) {
	cases := map[string]string{
		"no source":       "DELETE https://api.github.com/repos/a/b\n###\nGET https://api.github.com/repos/a/b\n",
		"no safe request": "# source: x\nDELETE https://api.github.com/repos/a/b\n",
		"bad first line":  "# source: x\nDELETE\n###\nGET https://api.github.com/repos/a/b\n",
		"relative url":    "# source: x\nDELETE /repos/a/b\n###\nGET https://api.github.com/repos/a/b\n",
		"bad header":      "# source: x\nDELETE https://api.github.com/repos/a/b\nnot-a-header\n\n###\nGET https://api.github.com/x\n",
	}
	for name, src := range cases {
		if _, err := ParseFixture("github.repo.delete", []byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckFixtureCatchesWrongRuleAndResource(t *testing.T) {
	e := builtinEngine(t)
	// The held request matches github.repo.delete, not github.org.delete.
	f, err := ParseFixture("github.org.delete", []byte(sampleFixture))
	if err != nil {
		t.Fatal(err)
	}
	if probs := CheckFixture(e, f); len(probs) == 0 {
		t.Fatal("fixture for the wrong rule passed")
	}
	wrongRes := strings.Replace(sampleFixture, "# resource: acme/prod-api", "# resource: acme/other", 1)
	f, _ = ParseFixture("github.repo.delete", []byte(wrongRes))
	if probs := CheckFixture(e, f); len(probs) == 0 {
		t.Fatal("wrong expected resource passed")
	}
	heldSafe := strings.Replace(sampleFixture, "GET https://api.github.com/repos/acme/prod-api", "DELETE https://api.github.com/repos/acme/x", 1)
	f, _ = ParseFixture("github.repo.delete", []byte(heldSafe))
	if probs := CheckFixture(e, f); len(probs) == 0 {
		t.Fatal("a 'safe' request that is held passed")
	}
}

// A query key repeated with different values must not let the approver see
// one target while the server acts on another.
func TestDuplicateQueryValuesMakeResourceUnknown(t *testing.T) {
	e := builtinEngine(t)
	v := e.Evaluate(Request{Method: "DELETE", Host: "api.digitalocean.com", Path: "/v2/droplets",
		Query: "tag_name=scratch&tag_name=prod"})
	if len(v.Matches) != 1 || v.Matches[0].Resource != "" {
		t.Fatalf("want held with unknown resource, got %+v", v)
	}
	v = e.Evaluate(Request{Method: "DELETE", Host: "api.digitalocean.com", Path: "/v2/droplets",
		Query: "tag_name=prod&tag_name=prod"})
	if len(v.Matches) != 1 || v.Matches[0].Resource != "tag:prod" {
		t.Fatalf("repeated identical values are unambiguous, got %+v", v)
	}
}

const destroyPack = `provider: acme
rules:
  - id: acme.run.destroy
    hosts: [api.acme.test]
    methods: [POST]
    path: /api/v2/runs
    json: { field: data.attributes.is-destroy, equals: "true" }
    resource: "{json.data.relationships.workspace.data.id}"
    severity: critical
`

func destroyEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := ParsePack([]byte(destroyPack))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine([]Pack{p})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func runReq(body string) Request {
	return Request{Method: "POST", Host: "api.acme.test", Path: "/api/v2/runs", Body: []byte(body)}
}

// Some destructive calls differ from routine ones only by a body field
// (Terraform Cloud: a run with "is-destroy": true).
func TestJSONFieldMatcher(t *testing.T) {
	e := destroyEngine(t)
	if !e.NeedsBody("api.acme.test") {
		t.Fatal("json rules need the request body buffered")
	}
	v := e.Evaluate(runReq(`{"data":{"attributes":{"is-destroy":true},"relationships":{"workspace":{"data":{"id":"ws-prod"}}}}}`))
	if len(v.Matches) != 1 || v.Matches[0].Resource != "ws-prod" {
		t.Fatalf("destroy run not held: %+v", v)
	}
	for _, safe := range []string{
		`{"data":{"attributes":{"is-destroy":false}}}`,
		`{"data":{"attributes":{"message":"plan"}}}`,
		``,
	} {
		if v := e.Evaluate(runReq(safe)); v.Hold() {
			t.Fatalf("held a normal run %q: %+v", safe, v)
		}
	}
	if v := e.Evaluate(runReq(`{"data": not json`)); v.Uninspectable == "" {
		t.Fatal("an unreadable body on a json rule must fail closed")
	}
}

func TestJSONMatcherRequiresField(t *testing.T) {
	bad := strings.Replace(destroyPack, "field: data.attributes.is-destroy, ", "", 1)
	p, err := ParsePack([]byte(bad))
	if err == nil {
		_, err = NewEngine([]Pack{p})
	}
	if err == nil {
		t.Fatal("json matcher without field accepted")
	}
}

// LoadDir once built "./x.yaml", which fs.FS rejects: --rules DIR loaded nothing.
func TestLoadDirReadsUserPacks(t *testing.T) {
	dir := t.TempDir()
	pack := "provider: acme\nrules:\n  - id: acme.x.delete\n    hosts: [api.acme.test]\n    methods: [DELETE]\n    path: /x/{id}\n"
	if err := os.WriteFile(dir+"/acme.yaml", []byte(pack), 0o600); err != nil {
		t.Fatal(err)
	}
	packs, err := LoadDir(dir)
	if err != nil || len(packs) != 1 || packs[0].Rules[0].ID != "acme.x.delete" {
		t.Fatalf("packs=%v err=%v", packs, err)
	}
}

func TestCheckFixtureDirReportsMissingFixtures(t *testing.T) {
	e := builtinEngine(t)
	fsys := fstest.MapFS{"github.repo.delete.http": {Data: []byte(sampleFixture)}}
	fails := CheckFixtureDir(e, fsys, []string{"github.repo.delete", "github.org.delete"})
	if len(fails) != 1 || fails[0].Rule != "github.org.delete" || !strings.Contains(fails[0].Problem, "no fixture") {
		t.Fatalf("fails=%+v", fails)
	}
}

// Every builtin rule must ship a fixture: a request taken from the
// provider's official API reference that the rule holds, plus requests that
// must pass. This catches wrong hosts, paths and mutation names.
func TestEveryBuiltinRuleHasPassingFixture(t *testing.T) {
	e := builtinEngine(t)
	var ids []string
	for _, r := range e.Rules() {
		ids = append(ids, r.ID)
	}
	for _, f := range CheckFixtureDir(e, os.DirFS("testdata"), ids) {
		t.Errorf("%s: %s", f.Rule, f.Problem)
	}
}
