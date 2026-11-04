package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAllowFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const allowEverything = "allow:\n  - rule: \"*\"\n    resource: \"*\"\n"

// An agent can write ./.twokey-allow.yaml in its own project directory: the
// file must be ignored until the human trusts this exact content.
func TestProjectAllowFileNeedsTrust(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	t.Chdir(proj)
	writeAllowFile(t, defaultAllowFile, allowEverything)

	got, err := loadProjectAllow(home, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.allows) != 0 || !strings.Contains(got.warning, "twokey allow trust") {
		t.Fatalf("untrusted file must be ignored with a warning, got %+v", got)
	}

	if _, err := trustAllow(home, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ = loadProjectAllow(home, ""); len(got.allows) != 1 || got.warning != "" {
		t.Fatalf("trusted file must be used, got %+v", got)
	}
	if runtimeIsUnix() {
		if st, err := os.Stat(filepath.Join(home, allowTrustFile)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("trust store must be 0600: %v %v", st, err)
		}
	}

	// The agent edits the trusted file: it is ignored again.
	writeAllowFile(t, defaultAllowFile, allowEverything+"  - rule: \"github.*\"\n    resource: \"*\"\n")
	if got, _ = loadProjectAllow(home, ""); len(got.allows) != 0 || !strings.Contains(got.warning, "changed") {
		t.Fatalf("modified file must be ignored, got %+v", got)
	}

	if _, err := trustAllow(home, ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := revokeAllow(home, ""); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if got, _ = loadProjectAllow(home, ""); len(got.allows) != 0 {
		t.Fatalf("revoked file must be ignored, got %+v", got)
	}
}

// --allow FILE is the human naming the file on the command line: trusted.
func TestExplicitAllowFlagCountsAsTrust(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, "team-allow.yaml")
	writeAllowFile(t, path, allowEverything)
	got, err := loadProjectAllow(home, path)
	if err != nil || len(got.allows) != 1 || got.warning != "" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := loadProjectAllow(home, filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("an explicit missing file is an error")
	}
	t.Chdir(t.TempDir())
	if got, err := loadProjectAllow(home, ""); err != nil || len(got.allows) != 0 || got.warning != "" {
		t.Fatalf("no file: nothing to do, got %+v %v", got, err)
	}
}

func TestTrustRejectsInvalidAllowFile(t *testing.T) {
	home := t.TempDir()
	t.Chdir(t.TempDir())
	writeAllowFile(t, defaultAllowFile, "allow:\n  - rule: x\n")
	if _, err := trustAllow(home, ""); err == nil {
		t.Fatal("an allow file that does not parse must not be trusted")
	}
}

// The proxy itself must not use an untrusted project file.
func TestStartProxyIgnoresUntrustedAllowFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWOKEY_HOME", home)
	t.Chdir(t.TempDir())
	writeAllowFile(t, defaultAllowFile, allowEverything)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := startProxy(ctx, proxyConfig{addr: "127.0.0.1:0", timeout: time.Minute, observe: true,
		logTo: io.Discard, noDesktop: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.summary, "pre-approved operation") || !strings.Contains(p.summary, "twokey allow trust") {
		t.Fatalf("untrusted allow file was used or not reported:\n%s", p.summary)
	}
	cancel()
	<-p.done
}

func runtimeIsUnix() bool { return os.PathSeparator == '/' }

// An empty topic file (crash between create and write) used to recurse
// until the stack overflowed.
func TestPhoneTopicRecoversFromEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, phoneTopicFile)
	writeAllowFile(t, path, "  \n")
	topic, err := phoneTopic(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) != topic || len(topic) < 16 {
		t.Fatalf("topic %q not persisted (%q)", topic, data)
	}
	again, _ := phoneTopic(dir, false)
	if again != topic {
		t.Fatal("topic must be stable after repair")
	}

	writeAllowFile(t, path, "short\n")
	if _, err := phoneTopic(dir, false); err == nil || !strings.Contains(err.Error(), "--rotate") {
		t.Fatalf("a corrupt topic must be a clear error, got %v", err)
	}
	if _, err := phoneTopic(dir, true); err != nil {
		t.Fatalf("--rotate repairs it: %v", err)
	}
}

func TestSetupApprovalsValidatesNtfy(t *testing.T) {
	home := t.TempDir()
	logger := log.New(io.Discard, "", 0)
	good := "twokey-0123456789abcdef01234567"
	for _, c := range []struct{ server, topic string }{
		{"http://ntfy.example.com", good},
		{"ntfy.example.com", good},
		{"https://ntfy.sh", "mytopic"},
	} {
		_, _, err := setupApprovals(context.Background(), proxyConfig{timeout: time.Minute, ntfyServer: c.server,
			ntfyTopic: c.topic, noDesktop: true}, home, logger)
		if err == nil {
			t.Errorf("server %q topic %q: want an error", c.server, c.topic)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, channels, err := setupApprovals(ctx, proxyConfig{timeout: time.Minute, ntfyServer: "https://ntfy.sh",
		ntfyTopic: good, noDesktop: true}, home, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range channels {
		if strings.Contains(ch, good) {
			t.Fatalf("banner shows the secret topic: %q", ch)
		}
	}
}

func TestTimeoutAndPortValidation(t *testing.T) {
	for d, ok := range map[time.Duration]bool{0: false, -time.Second: false, 2 * time.Hour: false,
		time.Second: true, 2 * time.Minute: true, time.Hour: true} {
		if err := validateTimeout(d); (err == nil) != ok {
			t.Errorf("validateTimeout(%s) = %v, want ok=%v", d, err, ok)
		}
	}
	for _, addr := range []string{"127.0.0.1:99999", "127.0.0.1:abc", "127.0.0.1:-1", "127.0.0.1:"} {
		if err := requireLoopback(addr); err == nil {
			t.Errorf("requireLoopback(%q) must reject the port", addr)
		}
	}
	if err := cmdUp([]string{"--timeout", "0"}); err == nil || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("up --timeout 0: %v", err)
	}
	var code exitCode
	if err := cmdRun([]string{"--phone", "--timeout", "-1s", "--", "agent"}); !errors.As(err, &code) || code != setupExitCode {
		t.Fatalf("run with a bad --timeout must exit %d, got %v", setupExitCode, err)
	}
	if err := cmdPG([]string{"--upstream", "db:5432", "--timeout", "3h"}); err == nil || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("pg --timeout 3h: %v", err)
	}
	if err := cmdLog([]string{"-n", "-1"}); err == nil {
		t.Fatal("log -n -1 must be rejected")
	}
	if err := cmdLog([]string{"--since", "-1h"}); err == nil {
		t.Fatal("log --since -1h must be rejected")
	}
}

// --since must see entries that were rotated into audit.jsonl.1.
func TestLogReadsRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lines := strings.SplitAfter(sampleAudit, "\n")
	writeAllowFile(t, path+".1", strings.Join(lines[:3], ""))
	writeAllowFile(t, path, strings.Join(lines[3:], ""))
	var out bytes.Buffer
	if err := printLogFiles(&out, []string{path + ".1", path}, logOptions{n: 20, since: 30 * time.Hour, now: logNow}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"acme/old", "users (+1 more)", "acme/x"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Index(out.String(), "acme/old") > strings.Index(out.String(), "acme/x") {
		t.Error("rotated (older) entries come first")
	}
}

// A file without a trailing newline must not glue its last line to the
// first line of the next file.
func TestLogFilesAreLineSeparated(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	lines := strings.SplitAfter(sampleAudit, "\n")
	writeAllowFile(t, a, strings.TrimSuffix(lines[0], "\n"))
	writeAllowFile(t, b, lines[2])
	var out bytes.Buffer
	if err := printLogFiles(&out, []string{a, b}, logOptions{n: 20, now: logNow}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "pg-data-prod") || !strings.Contains(out.String(), "acme/old") || strings.Contains(out.String(), "malformed") {
		t.Fatalf("got:\n%s", out.String())
	}
}

func TestStrictGatewayIsPinnedAndAllowFileReadOnly(t *testing.T) {
	if !strings.Contains(gatewayImage, "@sha256:") {
		t.Fatalf("gateway image must be pinned by digest: %s", gatewayImage)
	}
	wd := t.TempDir()
	writeAllowFile(t, filepath.Join(wd, defaultAllowFile), allowEverything)
	args := strings.Join(strictRunArgs("node:22", wd, "/h/.twokey", "twokey-gw-1", true, false, []string{"claude"}), " ")
	if !strings.Contains(args, filepath.Join(wd, defaultAllowFile)+":/work/"+defaultAllowFile+":ro") {
		t.Fatalf("project allow file must be mounted read-only: %s", args)
	}
	if a, b := newGatewayName("7171"), newGatewayName("7171"); a == b || !strings.HasPrefix(a, "twokey-gw-7171-") {
		t.Fatalf("gateways must be per run: %q %q", a, b)
	}
	run := strings.Join(gatewayRunArgs("twokey-gw-x", "7171"), " ")
	if strings.Contains(run, "--restart") || !strings.Contains(run, gatewayImage) {
		t.Fatalf("per-run gateway must not restart itself: %s", run)
	}
}

// A user curlrc with proxy settings would let curl bypass twokey.
func TestCurlHomeDropsProxySettings(t *testing.T) {
	user := t.TempDir()
	rc := "user-agent = \"me\"\nnoproxy = \".amazonaws.com\"\n--proxy http://elsewhere:3128\nproxy-user = a:b\n-k\ninsecure\n  socks5 = 1.2.3.4\n"
	writeAllowFile(t, filepath.Join(user, ".curlrc"), rc)
	t.Setenv("CURL_HOME", user)
	dir, err := curlHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".curlrc"))
	got := string(data)
	if !strings.Contains(got, `user-agent = "me"`) {
		t.Fatalf("unrelated options must be kept:\n%s", got)
	}
	for _, bad := range []string{"noproxy", "elsewhere", "proxy-user", "\n-k", "\ninsecure", "socks5"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q must be dropped:\n%s", bad, got)
		}
	}
}
