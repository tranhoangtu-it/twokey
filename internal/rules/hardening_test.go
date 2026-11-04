package rules

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const rdsHost = "rds.us-east-1.amazonaws.com"

func formHdr() http.Header { return hdr("Content-Type", "application/x-www-form-urlencoded") }

func ruleIDs(v Verdict) []string {
	var ids []string
	for _, m := range v.Matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

func hasRule(v Verdict, id string) bool {
	for _, m := range v.Matches {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

func TestAWSMalformedFormIsUninspectable(t *testing.T) {
	e := builtinEngine(t)
	for _, tc := range []struct{ name, query, body string }{
		{"semicolon in body", "", "Action=DeleteDBInstance&DBInstanceIdentifier=prod&Note=a;b"},
		{"bad escape in body", "", "Action=DescribeDBInstances&x=%zz"},
		{"bad escape in query", "Action=DeleteDBInstance&x=%zz", ""},
		{"semicolon in query", "Action=DeleteDBInstance;x=1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := e.Evaluate(Request{Method: "POST", Host: rdsHost, Path: "/", Query: tc.query, Header: formHdr(), Body: []byte(tc.body)})
			if v.Uninspectable == "" {
				t.Fatalf("malformed AWS form must be uninspectable, got %+v", v)
			}
		})
	}
}

func TestAWSEveryActionValueIsEvaluated(t *testing.T) {
	e := builtinEngine(t)
	for _, tc := range []struct {
		name, host, query, body string
		header                  http.Header
		want                    string
	}{
		{"query and body disagree", rdsHost, "Action=DescribeDBInstances",
			"Action=DeleteDBInstance&DBInstanceIdentifier=prod", formHdr(), "aws.rds.delete"},
		{"body overrides nothing", rdsHost, "Action=DeleteDBInstance&DBInstanceIdentifier=prod",
			"Action=DescribeDBInstances", formHdr(), "aws.rds.delete"},
		{"repeated Action in body", rdsHost, "",
			"Action=DescribeDBInstances&Action=DeleteDBInstance&DBInstanceIdentifier=prod", formHdr(), "aws.rds.delete"},
		{"two X-Amz-Target values", "dynamodb.us-east-1.amazonaws.com", "", `{"TableName":"prod"}`,
			http.Header{"X-Amz-Target": {"DynamoDB_20120810.DescribeTable", "DynamoDB_20120810.DeleteTable"}}, "aws.dynamodb.delete"},
		{"target and form Action", rdsHost, "", "Action=DeleteDBInstance&DBInstanceIdentifier=prod",
			http.Header{"X-Amz-Target": {"AmazonRDSv19.DescribeDBInstances"}}, "aws.rds.delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := e.Evaluate(Request{Method: "POST", Host: tc.host, Path: "/", Query: tc.query, Header: tc.header, Body: []byte(tc.body)})
			if !hasRule(v, tc.want) {
				t.Fatalf("want %s, got %v %q", tc.want, ruleIDs(v), v.Uninspectable)
			}
		})
	}
}

func TestAWSAmbiguousParameterIsUnknownResource(t *testing.T) {
	e := builtinEngine(t)
	v := e.Evaluate(Request{Method: "POST", Host: rdsHost, Path: "/", Query: "DBInstanceIdentifier=scratch",
		Header: formHdr(), Body: []byte("Action=DeleteDBInstance&DBInstanceIdentifier=prod")})
	if !hasRule(v, "aws.rds.delete") || v.Matches[0].Resource != "" {
		t.Fatalf("two different identifiers must give an unknown resource, got %+v", v)
	}
}

func TestDotSegmentsAreResolved(t *testing.T) {
	e := builtinEngine(t)
	for _, p := range []string{
		"/v2/droplets/./1", "/v2/x/../droplets/1", "/v2//droplets/1", "/./v2/droplets/1/", "/v2/droplets/1/x/..",
	} {
		v := e.Evaluate(Request{Method: "DELETE", Host: "api.digitalocean.com", Path: p})
		if !hasRule(v, "digitalocean.droplet.delete") {
			t.Errorf("DELETE %s: want digitalocean.droplet.delete, got %v", p, ruleIDs(v))
			continue
		}
		for _, m := range v.Matches {
			if m.RuleID == "digitalocean.droplet.delete" && m.Resource != "1" {
				t.Errorf("DELETE %s: resource %q, want 1", p, m.Resource)
			}
		}
	}
}

func TestPathVariablesAreNotDecodedTwice(t *testing.T) {
	e := builtinEngine(t)
	// The proxy hands the engine an already-decoded path: the client sent
	// %252F, the server sees the literal text "%2F".
	v := e.Evaluate(Request{Method: "DELETE", Host: "api.github.com", Path: "/repos/acme/a%2Fb"})
	if !hasRule(v, "github.repo.delete") || v.Matches[0].Resource != "acme/a%2Fb" {
		t.Fatalf("got %+v", v)
	}
}

func TestMethodOverrideIsEvaluated(t *testing.T) {
	e := builtinEngine(t)
	for _, tc := range []struct {
		name   string
		header http.Header
		query  string
	}{
		{"X-HTTP-Method-Override", hdr("X-HTTP-Method-Override", "delete"), ""},
		{"X-HTTP-Method", hdr("X-HTTP-Method", "DELETE"), ""},
		{"X-Method-Override", hdr("X-Method-Override", "DELETE"), ""},
		{"_method query", http.Header{}, "_method=DELETE"},
		{"_method after junk", http.Header{}, "a=%zz&_method=DELETE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := e.Evaluate(Request{Method: "POST", Host: "api.github.com", Path: "/repos/acme/api", Query: tc.query, Header: tc.header})
			if !hasRule(v, "github.repo.delete") {
				t.Fatalf("method override to DELETE must be held, got %v", ruleIDs(v))
			}
		})
	}
	if v := e.Evaluate(Request{Method: "POST", Host: "api.github.com", Path: "/repos/acme/api", Header: hdr("X-HTTP-Method-Override", "PATCH")}); v.Hold() {
		t.Fatalf("override to PATCH is not destructive: %+v", v)
	}
}

// fanOutFragments builds F0..Fn where each Fi spreads F(i+1) width times.
func fanOutFragments(depth, width int) string {
	var b strings.Builder
	b.WriteString(`{"query":"mutation { ...F0 } `)
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "fragment F%d on Mutation { %s} ", i, strings.Repeat(fmt.Sprintf("...F%d ", i+1), width))
	}
	fmt.Fprintf(&b, `fragment F%d on Mutation { me } "}`, depth)
	return b.String()
}

func TestGraphQLFragmentFanOutIsBounded(t *testing.T) {
	e := builtinEngine(t)
	v := e.Evaluate(Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2",
		Header: hdr("Content-Type", "application/json"), Body: []byte(fanOutFragments(6, 10))})
	if v.Uninspectable == "" {
		t.Fatalf("fragment fan-out beyond the budget must be uninspectable, got %+v", v)
	}
	// One large variable referenced by many fields fans out the same way.
	ids := strings.TrimSuffix(strings.Repeat(`"x",`, 2000), ",")
	query := `mutation($v: [String!]) { ` + strings.Repeat(`me(ids: $v) `, 100) + `}`
	v = e.Evaluate(Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2",
		Header: hdr("Content-Type", "application/json"),
		Body:   []byte(`{"query":"` + query + `","variables":{"v":[` + ids + `]}}`)})
	if v.Uninspectable == "" {
		t.Fatalf("argument fan-out beyond the budget must be uninspectable, got %+v", v)
	}
}

func TestAllowGlobsSpanNewlinesAndNeverCoverUnknownResources(t *testing.T) {
	allows, err := ParseAllow([]byte("allow:\n  - rule: x.delete\n    resource: \"pr-*\"\n  - rule: y.delete\n    resource: \"*\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Allowed(Match{RuleID: "x.delete", Resource: "pr-1\nx"}, allows); !ok {
		t.Error("* must match across newlines")
	}
	if _, ok := Allowed(Match{RuleID: "y.delete", Resource: ""}, allows); ok {
		t.Error(`resource "*" must not cover an unknown resource`)
	}
	if _, ok := Allowed(Match{RuleID: "y.delete", Resource: ""}, []Allow{{Rule: "*", Resource: "*"}}); ok {
		t.Error(`an Allow built outside ParseAllow must not cover an unknown resource`)
	}
}
