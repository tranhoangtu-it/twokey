package rules

import (
	"net/http"
	"testing"
)

// Benchmarks for the per-request cost the proxy adds on watched hosts, with
// all builtin packs loaded. Run: go test ./internal/rules -run '^$' -bench . -benchmem
func benchEngine(b *testing.B) *Engine {
	b.Helper()
	packs, err := BuiltinPacks()
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngine(packs)
	if err != nil {
		b.Fatal(err)
	}
	return e
}

func BenchmarkEvaluateREST(b *testing.B) {
	e := benchEngine(b)
	req := Request{Method: "DELETE", Host: "api.github.com", Path: "/repos/acme/prod-api", Header: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		if v := e.Evaluate(req); len(v.Matches) == 0 {
			b.Fatal("expected a hold")
		}
	}
}

func BenchmarkEvaluateGraphQL(b *testing.B) {
	e := benchEngine(b)
	req := Request{
		Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2",
		Header: http.Header{"Content-Type": {"application/json"}},
		Body:   []byte(`{"query":"mutation volumeDelete($volumeId: String!) { volumeDelete(volumeId: $volumeId) }","variables":{"volumeId":"pg-data-prod"}}`),
	}
	b.ReportAllocs()
	for b.Loop() {
		if v := e.Evaluate(req); len(v.Matches) == 0 {
			b.Fatal("expected a hold")
		}
	}
}

func BenchmarkEvaluateAWS(b *testing.B) {
	e := benchEngine(b)
	req := Request{
		Method: "POST", Host: "rds.us-east-1.amazonaws.com", Path: "/",
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   []byte("Action=DeleteDBInstance&DBInstanceIdentifier=orders-prod&SkipFinalSnapshot=true&Version=2014-10-31"),
	}
	b.ReportAllocs()
	for b.Loop() {
		if v := e.Evaluate(req); len(v.Matches) == 0 {
			b.Fatal("expected a hold")
		}
	}
}

func BenchmarkEvaluatePassThrough(b *testing.B) {
	e := benchEngine(b)
	req := Request{Method: "GET", Host: "api.github.com", Path: "/repos/acme/prod-api/pulls", Header: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		if v := e.Evaluate(req); len(v.Matches) != 0 {
			b.Fatal("expected no hold")
		}
	}
}
