package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const sampleAudit = `{"time":"2026-11-01T10:00:00Z","id":"1","method":"POST","url":"https://backboard.railway.com/graphql/v2","matches":[{"rule":"railway.volume.delete","provider":"railway","operation":"volumeDelete","resource":"pg-data-prod"}],"approved":false,"by":"terminal","reason":"denied by human"}
not json
{"time":"2026-11-03T10:00:00Z","id":"2","method":"DELETE","url":"https://api.github.com/repos/acme/old","matches":[{"rule":"github.repo.delete","provider":"github","operation":"delete repository","resource":"acme/old"}],"approved":true,"by":"ntfy","reason":"approved on phone"}
{"time":"2026-11-04T09:00:00Z","id":"3","method":"SQL","url":"postgres db:5432","matches":[{"rule":"postgres.drop-table","provider":"postgres","operation":"DROP TABLE","resource":"users"},{"rule":"postgres.drop-table","provider":"postgres","operation":"DROP TABLE","resource":"orders"}],"approved":true,"by":"observe","reason":"observe mode"}
{"time":"2026-11-04T09:30:00Z","id":"4","method":"DELETE","url":"https://api.github.com/repos/acme/x","matches":[{"rule":"github.repo.delete","provider":"github","operation":"delete repository","resource":"acme/x"}],"approved":false,"by":"timeout","reason":"no human decision within 2m0s"}
`

var logNow = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func runLog(t *testing.T, o logOptions) string {
	t.Helper()
	o.now = logNow
	var out bytes.Buffer
	if err := printLog(&out, strings.NewReader(sampleAudit), o); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestLogShowsNewestLastWithDecisions(t *testing.T) {
	out := runLog(t, logOptions{n: 20})
	for _, want := range []string{"DENIED", "APPROVED", "OBSERVED", "pg-data-prod", "users (+1 more)", "timeout", "1 malformed line"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "pg-data-prod") > strings.Index(out, "acme/x") {
		t.Error("entries must be oldest first, newest last")
	}
}

func TestLogFilters(t *testing.T) {
	if out := runLog(t, logOptions{n: 1}); !strings.Contains(out, "acme/x") || strings.Contains(out, "users") {
		t.Errorf("-n 1:\n%s", out)
	}
	if out := runLog(t, logOptions{n: 20, denied: true}); strings.Contains(out, "acme/old") || !strings.Contains(out, "acme/x") || !strings.Contains(out, "pg-data-prod") {
		t.Errorf("--denied:\n%s", out)
	}
	if out := runLog(t, logOptions{n: 20, provider: "GitHub"}); strings.Contains(out, "pg-data-prod") || !strings.Contains(out, "acme/old") {
		t.Errorf("--provider:\n%s", out)
	}
	if out := runLog(t, logOptions{n: 20, since: 2 * time.Hour}); strings.Contains(out, "acme/old") || !strings.Contains(out, "users") {
		t.Errorf("--since:\n%s", out)
	}
}

// One huge entry (a long URL from the agent) must not make the log unreadable.
func TestLogSurvivesOversizedLines(t *testing.T) {
	huge := `{"time":"2026-11-04T09:59:00Z","id":"9","method":"DELETE","url":"https://api.github.com/` +
		strings.Repeat("a", maxAuditLine+10) + `","approved":false,"by":"timeout","reason":"x"}`
	var out bytes.Buffer
	err := printLog(&out, strings.NewReader(sampleAudit+huge+"\n"), logOptions{n: 20, now: logNow})
	if err != nil || !strings.Contains(out.String(), "acme/x") {
		t.Fatalf("err=%v out=%s", err, out.String())
	}
}

func TestLogJSONEscapesControlCharacters(t *testing.T) {
	tampered := `{"time":"2026-11-04T09:59:00Z","id":"9","method":"DELETE","url":"x` + "\x1b" + `[2J","approved":false,"by":"timeout","reason":"x"}` + "\n"
	var out bytes.Buffer
	if err := printLog(&out, strings.NewReader(tampered), logOptions{n: 20, json: true, now: logNow}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("raw escape reached the terminal: %q", out.String())
	}
}

func TestLogJSONRoundTrips(t *testing.T) {
	out := runLog(t, logOptions{n: 20, json: true, provider: "github"})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 JSON lines, got:\n%s", out)
	}
	for _, l := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
	}
}
