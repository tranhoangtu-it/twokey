package rules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func builtinEngine(t *testing.T) *Engine {
	t.Helper()
	packs, err := BuiltinPacks()
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	e, err := NewEngine(packs)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestEvaluate(t *testing.T) {
	e := builtinEngine(t)
	jsonCT := hdr("Content-Type", "application/json")

	tests := []struct {
		name          string
		req           Request
		wantRule      string // "" means no match expected
		wantResource  string
		uninspectable bool
	}{
		{
			name: "PocketOS: railway volumeDelete with variables",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`{"query":"mutation volumeDelete($volumeId: String!) { volumeDelete(volumeId: $volumeId) }","variables":{"volumeId":"pg-data-prod"}}`)},
			wantRule: "railway.volume.delete", wantResource: "pg-data-prod",
		},
		{
			name: "alias does not hide the mutation",
			req: Request{Method: "POST", Host: "backboard.railway.app:443", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`{"query":"mutation { cleanup: volumeDelete(volumeId: \"v1\") }"}`)},
			wantRule: "railway.volume.delete", wantResource: "v1",
		},
		{
			name: "mutation hidden in a fragment inside a batch",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`[{"query":"query { me { id } }"},{"query":"mutation { ...F } fragment F on Mutation { projectDelete(id: \"p9\") }"}]`)},
			wantRule: "railway.project.delete", wantResource: "p9",
		},
		{
			name: "railway read-only query passes",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`{"query":"query { projects { edges { node { id } } } }"}`)},
		},
		{
			name: "unparseable GraphQL fails closed",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`{"extensions":{"persistedQuery":{"sha256Hash":"abc"}}}`)},
			uninspectable: true,
		},
		{
			name:     "github repo delete",
			req:      Request{Method: "DELETE", Host: "api.github.com", Path: "/repos/acme/billing"},
			wantRule: "github.repo.delete", wantResource: "acme/billing",
		},
		{
			name:     "github branch delete with slashes",
			req:      Request{Method: "DELETE", Host: "api.github.com", Path: "/repos/acme/web/git/refs/heads/feature/x"},
			wantRule: "github.ref.delete", wantResource: "acme/web:heads/feature/x",
		},
		{
			name: "github GET repo passes",
			req:  Request{Method: "GET", Host: "api.github.com", Path: "/repos/acme/billing"},
		},
		{
			name: "aws rds query protocol",
			req: Request{Method: "POST", Host: "rds.us-east-1.amazonaws.com", Path: "/",
				Header: hdr("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
				Body:   []byte("Action=DeleteDBInstance&DBInstanceIdentifier=orders-prod&SkipFinalSnapshot=true&Version=2014-10-31")},
			wantRule: "aws.rds.delete", wantResource: "orders-prod",
		},
		{
			name: "aws rds describe passes",
			req: Request{Method: "POST", Host: "rds.us-east-1.amazonaws.com", Path: "/",
				Header: hdr("Content-Type", "application/x-www-form-urlencoded"),
				Body:   []byte("Action=DescribeDBInstances&Version=2014-10-31")},
		},
		{
			name: "aws dynamodb json protocol",
			req: Request{Method: "POST", Host: "dynamodb.eu-west-1.amazonaws.com", Path: "/",
				Header: hdr("X-Amz-Target", "DynamoDB_20120810.DeleteTable", "Content-Type", "application/x-amz-json-1.0"),
				Body:   []byte(`{"TableName":"sessions"}`)},
			wantRule: "aws.dynamodb.delete", wantResource: "sessions",
		},
		{
			name:     "aws ec2 terminate via query string",
			req:      Request{Method: "GET", Host: "ec2.ap-southeast-1.amazonaws.com", Path: "/", Query: "Action=TerminateInstances&InstanceId.1=i-0abc"},
			wantRule: "aws.ec2.terminate", wantResource: "i-0abc",
		},
		{
			name:     "s3 virtual-hosted bucket delete",
			req:      Request{Method: "DELETE", Host: "my-backups.s3.us-east-2.amazonaws.com", Path: "/"},
			wantRule: "aws.s3.delete-bucket", wantResource: "my-backups.s3.us-east-2.amazonaws.com",
		},
		{
			name: "s3 object delete is not a bucket delete",
			req:  Request{Method: "DELETE", Host: "my-backups.s3.us-east-2.amazonaws.com", Path: "/tmp/file.txt"},
		},
		{
			name:     "neon nested database delete",
			req:      Request{Method: "DELETE", Host: "console.neon.tech", Path: "/api/v2/projects/p1/branches/main/databases/app"},
			wantRule: "neon.database.delete", wantResource: "p1/main/app",
		},
		{
			name:     "GraphQL mutation over GET query string",
			req:      Request{Method: "GET", Host: "backboard.railway.com", Path: "/graphql/v2", Query: url.Values{"query": {`mutation { volumeDelete(volumeId: "v7") }`}}.Encode()},
			wantRule: "railway.volume.delete", wantResource: "v7",
		},
		{
			name: "bare GET to GraphQL endpoint passes",
			req:  Request{Method: "GET", Host: "backboard.railway.com", Path: "/graphql/v2"},
		},
		{
			name: "empty POST to GraphQL endpoint passes",
			req:  Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2"},
		},
		{
			name: "fragments nested too deep fail closed",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Header: jsonCT,
				Body: []byte(`{"query":"mutation { ...F0 } ` + deepFragments(12) + `"}`)},
			uninspectable: true,
		},
		{
			name:     "trailing-dot FQDN host is still matched",
			req:      Request{Method: "DELETE", Host: "api.github.com.:443", Path: "/repos/acme/api"},
			wantRule: "github.repo.delete", wantResource: "acme/api",
		},
		{
			name: "railway dashboard endpoint /graphql/internal",
			req: Request{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/internal", Header: jsonCT,
				Body: []byte(`{"query":"mutation { projectDelete(id: \"p1\") }"}`)},
			wantRule: "railway.project.delete", wantResource: "p1",
		},
		{
			name: "dynamodb account-based endpoint",
			req: Request{Method: "POST", Host: "123456789012.ddb.us-east-1.amazonaws.com", Path: "/",
				Header: hdr("X-Amz-Target", "DynamoDB_20120810.DeleteTable"), Body: []byte(`{"TableName":"orders"}`)},
			wantRule: "aws.dynamodb.delete", wantResource: "orders",
		},
		{
			name:     "s3 legacy dash-region host",
			req:      Request{Method: "DELETE", Host: "b.s3-us-west-2.amazonaws.com", Path: "/"},
			wantRule: "aws.s3.delete-bucket", wantResource: "b.s3-us-west-2.amazonaws.com",
		},
		{
			name:     "s3 legacy path-style host",
			req:      Request{Method: "DELETE", Host: "s3-us-west-2.amazonaws.com", Path: "/b"},
			wantRule: "aws.s3.delete-bucket-path-style", wantResource: "b",
		},
		{
			name: "s3 bucket policy delete is not a bucket delete",
			req:  Request{Method: "DELETE", Host: "b.s3.amazonaws.com", Path: "/", Query: "policy"},
		},
		{
			name:     "s3 bucket delete with SDK x-id param is still held",
			req:      Request{Method: "DELETE", Host: "b.s3.amazonaws.com", Path: "/", Query: "x-id=DeleteBucket"},
			wantRule: "aws.s3.delete-bucket", wantResource: "b.s3.amazonaws.com",
		},
		{
			name:     "aws query form without content-type",
			req:      Request{Method: "POST", Host: "rds.eu-west-1.amazonaws.com", Path: "/", Body: []byte("Action=DeleteDBCluster&DBClusterIdentifier=c1")},
			wantRule: "aws.rds.delete", wantResource: "c1",
		},
		{
			name: "github deleteIssue resource",
			req: Request{Method: "POST", Host: "api.github.com", Path: "/graphql", Header: jsonCT,
				Body: []byte(`{"query":"mutation($i: DeleteIssueInput!) { deleteIssue(input: $i) { clientMutationId } }","variables":{"i":{"issueId":"I_1"}}}`)},
			wantRule: "github.graphql.delete", wantResource: "I_1",
		},
		{
			name:     "azure resource group delete (SDK casing)",
			req:      Request{Method: "DELETE", Host: "management.azure.com", Path: "/subscriptions/s1/resourceGroups/prod-rg", Query: "api-version=2021-04-01"},
			wantRule: "azure.resource-group.delete", wantResource: "prod-rg",
		},
		{
			name:     "gcp bucket delete",
			req:      Request{Method: "DELETE", Host: "storage.googleapis.com", Path: "/storage/v1/b/backups"},
			wantRule: "gcp.storage.delete-bucket", wantResource: "backups",
		},
		{
			name:     "heroku app delete",
			req:      Request{Method: "DELETE", Host: "api.heroku.com", Path: "/apps/shop-prod"},
			wantRule: "heroku.app.delete", wantResource: "shop-prod",
		},
		{
			name: "gcp object delete is not a bucket delete",
			req:  Request{Method: "DELETE", Host: "storage.googleapis.com", Path: "/storage/v1/b/backups/o/file.txt"},
		},
		{
			name: "unwatched host passes",
			req:  Request{Method: "DELETE", Host: "example.com", Path: "/repos/a/b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := e.Evaluate(tc.req)
			if tc.uninspectable {
				if v.Uninspectable == "" || !v.Hold() {
					t.Fatalf("want uninspectable hold, got %+v", v)
				}
				return
			}
			if tc.wantRule == "" {
				if v.Hold() {
					t.Fatalf("want no hold, got %+v", v)
				}
				return
			}
			if len(v.Matches) != 1 {
				t.Fatalf("want exactly 1 match, got %+v", v)
			}
			m := v.Matches[0]
			if m.RuleID != tc.wantRule || m.Resource != tc.wantResource {
				t.Fatalf("got rule=%q resource=%q, want %q %q", m.RuleID, m.Resource, tc.wantRule, tc.wantResource)
			}
		})
	}
}

// deepFragments builds F0 -> F1 -> ... -> Fn, with a volumeDelete at the bottom.
func deepFragments(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "fragment F%d on Mutation { ...F%d } ", i, i+1)
	}
	fmt.Fprintf(&b, `fragment F%d on Mutation { volumeDelete(volumeId: \"deep\") }`, n)
	return b.String()
}

func TestHostWatched(t *testing.T) {
	e := builtinEngine(t)
	for host, want := range map[string]bool{
		"api.github.com:443":          true,
		"backboard.railway.com":       true,
		"rds.us-west-2.amazonaws.com": true,
		"api.anthropic.com:443":       false,
		"github.com":                  false,
	} {
		if got := e.HostWatched(host); got != want {
			t.Errorf("HostWatched(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParsePackRejectsUnknownFields(t *testing.T) {
	_, err := ParsePack([]byte("provider: x\nrules:\n  - id: a\n    hosts: [h]\n    methods: [DELETE]\n    mutation: typo\n"))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestNewEngineRejectsDuplicateIDs(t *testing.T) {
	r := Rule{ID: "dup", Hosts: []string{"h"}, Methods: []string{"DELETE"}}
	if _, err := NewEngine([]Pack{{Provider: "a", Rules: []Rule{r}}, {Provider: "b", Rules: []Rule{r}}}); err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestExpandResource(t *testing.T) {
	vars := map[string]string{"a": "1", "c": "3"}
	cases := map[string]string{
		"{a}/{c}":   "1/3",
		"{b|c}":     "3",
		"{missing}": "",
		"plain":     "plain",
	}
	for tpl, want := range cases {
		if got := expandResource(tpl, vars); got != want {
			t.Errorf("expandResource(%q) = %q, want %q", tpl, got, want)
		}
	}
}
