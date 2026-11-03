package rules

import "testing"

func TestAllowRules(t *testing.T) {
	allows, err := ParseAllow([]byte(`
allow:
  - rule: vercel.project.delete
    resource: "pr-*-preview"
    reason: preview deployments are disposable
  - rule: "github.*"
    resource: "acme/sandbox-*"
  - rule: fly.machine.delete
    resource: "*"
`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		m    Match
		want bool
	}{
		{Match{RuleID: "vercel.project.delete", Resource: "pr-42-preview"}, true},
		{Match{RuleID: "vercel.project.delete", Resource: "prod"}, false},
		{Match{RuleID: "github.repo.delete", Resource: "acme/sandbox-x"}, true}, // '*' spans '/'
		{Match{RuleID: "github.repo.delete", Resource: "acme/api"}, false},
		{Match{RuleID: "github.repo.delete", Resource: ""}, false}, // unknown resource needs "*"
		{Match{RuleID: "fly.machine.delete", Resource: ""}, true},
		{Match{RuleID: "railway.volume.delete", Resource: "pr-1-preview"}, false},
	}
	for _, c := range cases {
		if _, got := Allowed(c.m, allows); got != c.want {
			t.Errorf("Allowed(%+v) = %v, want %v", c.m, got, c.want)
		}
	}

	v, allowed := ApplyAllow(Verdict{Matches: []Match{
		{RuleID: "vercel.project.delete", Resource: "pr-1-preview"},
		{RuleID: "vercel.project.delete", Resource: "prod"},
	}}, allows)
	if len(allowed) != 1 || len(v.Matches) != 1 || v.Matches[0].Resource != "prod" || !v.Hold() {
		t.Fatalf("mixed batch: allowed=%v remaining=%v", allowed, v)
	}
	if v, _ := ApplyAllow(Verdict{Uninspectable: "x"}, allows); !v.Hold() {
		t.Fatal("uninspectable requests must never be allowed")
	}
}

func TestParseAllowRequiresExplicitResource(t *testing.T) {
	if _, err := ParseAllow([]byte("allow:\n  - rule: github.repo.delete\n")); err == nil {
		t.Fatal("missing resource must be an error")
	}
	if _, err := ParseAllow([]byte("allow:\n  - rule: x\n    resource: y\n    resorce: typo\n")); err == nil {
		t.Fatal("unknown field must be an error")
	}
}
