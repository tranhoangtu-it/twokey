//go:build e2e

// Package e2e runs the real twokey binary the way a user does: `twokey up`
// in one process, an agent (Python) through `twokey run` in another, and a
// human answering in the up window. Unit tests could not catch failures
// that only show up across processes and real OS behavior; these do.
//
// The destructive call is DELETE https://api.github.com/repos/<nonexistent>
// with no credentials: if it ever got through, GitHub answers 401/404.
//
//	go test -tags e2e ./e2e/
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const target = "https://api.github.com/repos/twokey-e2e-nonexistent-org/nope"

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "twokey-e2e-bin")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "twokey")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "../cmd/twokey")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic("build twokey: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// env is the environment for every twokey process in one test.
func env(t *testing.T, home string) []string {
	t.Helper()
	var out []string
	for _, kv := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.HasPrefix(k, "TWOKEY_") || strings.Contains(k, "PROXY") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TWOKEY_HOME="+home)
}

func python() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
}

// probe is the "agent": one destructive request, then report what came back.
const probe = `
import json, urllib.request, urllib.error
req = urllib.request.Request(%q, method="DELETE")
try:
    r = urllib.request.urlopen(req, timeout=60)
    print(json.dumps({"status": r.status, "x_twokey": r.headers.get("X-Twokey"), "body": r.read().decode()}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "x_twokey": e.headers.get("X-Twokey"), "body": e.read().decode()}))
`

type probeResult struct {
	Status  int    `json:"status"`
	XTwokey string `json:"x_twokey"`
	Body    string `json:"body"`
}

func writeProbe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probe.py")
	src := strings.Replace(probe, "%q", `"`+target+`"`, 1)
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func parseProbe(t *testing.T, out []byte) probeResult {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var r probeResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		t.Fatalf("probe output not JSON: %v\n%s", err, out)
	}
	return r
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// auditEntries reads the audit trail through `twokey log --json`.
func auditEntries(t *testing.T, home string) []map[string]any {
	t.Helper()
	cmd := exec.Command(bin, "log", "--json", "-n", "100")
	cmd.Env = env(t, home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("twokey log: %v\n%s", err, out)
	}
	var entries []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(l), &e) == nil {
			entries = append(entries, e)
		}
	}
	return entries
}

// A held request is denied by the human in the `twokey up` window: the agent
// gets the 403 written for models, nothing reaches GitHub, and it is audited.
func TestHoldAndDenyThroughTheUpWindow(t *testing.T) {
	home := t.TempDir()
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	up := exec.CommandContext(ctx, bin, "up", "--addr", addr, "--timeout", "90s", "--no-desktop")
	up.Env = env(t, home)
	stdin, err := up.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := up.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	up.Stderr = io.Discard
	if err := up.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Process.Kill(); _ = up.Wait() }()

	ready := make(chan struct{})
	held := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		readySent := false
		for sc.Scan() {
			line := sc.Text()
			if !readySent && strings.Contains(line, "proxy on http://") {
				close(ready)
				readySent = true
			}
			if i := strings.Index(line, "HOLD #"); i >= 0 {
				held <- strings.Fields(line[i+len("HOLD #"):])[0]
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("twokey up never started")
	}

	agent := exec.CommandContext(ctx, bin, "run", "--addr", addr, "--", python(), writeProbe(t))
	agent.Env = env(t, home)
	agentOut := make(chan []byte, 1)
	go func() {
		out, _ := agent.CombinedOutput()
		agentOut <- out
	}()

	var id string
	select {
	case id = <-held:
	case <-ctx.Done():
		t.Fatal("the DELETE was never held")
	}
	if _, err := io.WriteString(stdin, "deny "+id+"\n"); err != nil {
		t.Fatal(err)
	}

	var out []byte
	select {
	case out = <-agentOut:
	case <-ctx.Done():
		t.Fatal("agent never finished")
	}
	r := parseProbe(t, out)
	if r.Status != 403 || r.XTwokey != "blocked" || !strings.Contains(r.Body, "twokey_blocked") {
		t.Fatalf("agent should get the twokey 403, got %+v\n%s", r, out)
	}

	entries := auditEntries(t, home)
	if len(entries) == 0 || entries[len(entries)-1]["approved"] != false || entries[len(entries)-1]["by"] != "terminal" {
		t.Fatalf("denial not audited: %v", entries)
	}
}

// Observe mode lets the call through (GitHub answers, unauthenticated) and
// audits that it would have been held.
func TestObserveForwardsAndAudits(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	agent := exec.CommandContext(ctx, bin, "run", "--observe", "--no-desktop", "--", python(), writeProbe(t))
	agent.Env = env(t, home)
	out, err := agent.CombinedOutput()
	if err != nil {
		t.Fatalf("run --observe: %v\n%s", err, out)
	}
	r := parseProbe(t, out)
	if r.XTwokey != "inspected" || r.Status == 403 && strings.Contains(r.Body, "twokey_blocked") {
		t.Fatalf("observe must forward through the inspecting proxy, got %+v", r)
	}
	if r.Status != 401 && r.Status != 404 {
		t.Fatalf("expected GitHub to answer the unauthenticated DELETE, got %+v", r)
	}
	entries := auditEntries(t, home)
	if len(entries) != 1 || entries[0]["by"] != "observe" {
		t.Fatalf("observed call not audited: %v", entries)
	}
}

// The Postgres guard holds a real DROP TABLE from psql; the human denies it
// and the table survives. Needs TWOKEY_E2E_PG=host:port of a disposable
// server with user postgres (no password) and psql on PATH.
func TestPostgresGuardHoldsDropTable(t *testing.T) {
	upstream := os.Getenv("TWOKEY_E2E_PG")
	if upstream == "" {
		t.Skip("set TWOKEY_E2E_PG=host:port to run against a real Postgres")
	}
	home := t.TempDir()
	listen := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	host, port, _ := net.SplitHostPort(upstream)
	lhost, lport, _ := net.SplitHostPort(listen)
	psql := func(target, port, sql string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "psql", "-h", target, "-p", port, "-U", "postgres", "-d", "postgres",
			"-v", "ON_ERROR_STOP=1", "-tAc", sql)
		cmd.Env = append(env(t, home), "PGPASSWORD=postgres", "PGCONNECT_TIMEOUT=10", "PGSSLMODE=disable")
		return cmd.CombinedOutput()
	}
	if out, err := psql(host, port, "DROP TABLE IF EXISTS twokey_e2e; CREATE TABLE twokey_e2e(id int)"); err != nil {
		t.Fatalf("setup table: %v\n%s", err, out)
	}

	guard := exec.CommandContext(ctx, bin, "pg", "--upstream", upstream, "--listen", listen, "--timeout", "90s", "--no-desktop")
	guard.Env = env(t, home)
	stdin, _ := guard.StdinPipe()
	stdout, _ := guard.StdoutPipe()
	guard.Stderr = io.Discard
	if err := guard.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Process.Kill(); _ = guard.Wait() }()
	ready := make(chan struct{})
	held := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		readySent := false
		for sc.Scan() {
			line := sc.Text()
			if !readySent && strings.Contains(line, "guard on") {
				close(ready)
				readySent = true
			}
			if i := strings.Index(line, "HOLD #"); i >= 0 {
				held <- strings.Fields(line[i+len("HOLD #"):])[0]
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("twokey pg never started")
	}

	result := make(chan []byte, 1)
	go func() {
		out, _ := psql(lhost, lport, "DROP TABLE twokey_e2e")
		result <- out
	}()
	select {
	case id := <-held:
		_, _ = io.WriteString(stdin, "deny "+id+"\n")
	case <-ctx.Done():
		t.Fatal("DROP TABLE was never held")
	}
	if out := <-result; !strings.Contains(string(out), "twokey blocked") {
		t.Fatalf("psql should see the twokey error, got:\n%s", out)
	}
	if out, err := psql(host, port, "SELECT count(*) FROM twokey_e2e"); err != nil || strings.TrimSpace(string(out)) != "0" {
		t.Fatalf("table must survive the denied DROP: %v\n%s", err, out)
	}
}

// uninstall --purge leaves nothing twokey wrote behind.
func TestUninstallPurgeCleansHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".twokey")
	for _, args := range [][]string{{"ca", "init"}, {"uninstall", "--purge"}} {
		cmd := exec.Command(bin, args...)
		cmd.Env = env(t, home)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("twokey %v: %v\n%s", args, err, out)
		}
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(home)
		t.Fatalf("home not removed (left: %v)", entries)
	}
}
