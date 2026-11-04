package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userPack = `provider: acme
rules:
  - id: acme.db.delete
    hosts: ["api.acme.test"]
    methods: [DELETE]
    path: /v1/dbs/{db}
    resource: "{db}"
    severity: critical
`

const userFixture = `# source: https://docs.acme.test/api#delete-db
# resource: prod
DELETE https://api.acme.test/v1/dbs/prod
###
GET https://api.acme.test/v1/dbs/prod
`

func writeUserRules(t *testing.T, fixture string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(userPack), 0o600); err != nil {
		t.Fatal(err)
	}
	if fixture != "" {
		if err := os.WriteFile(filepath.Join(dir, "acme.db.delete.http"), []byte(fixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRulesTestPassesWithGoodFixture(t *testing.T) {
	dir := writeUserRules(t, userFixture)
	var out bytes.Buffer
	if err := rulesTest(&out, dir, dir); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "1/1") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestRulesTestFailsOnMissingOrWrongFixture(t *testing.T) {
	var out bytes.Buffer
	if err := rulesTest(&out, writeUserRules(t, ""), ""); err == nil {
		t.Fatal("missing fixture passed")
	}
	wrong := strings.Replace(userFixture, "/v1/dbs/prod\n###", "/v2/dbs/prod\n###", 1)
	out.Reset()
	if err := rulesTest(&out, writeUserRules(t, wrong), ""); err == nil || !strings.Contains(out.String(), "acme.db.delete") {
		t.Fatalf("wrong fixture passed: %v\n%s", err, out.String())
	}
}
