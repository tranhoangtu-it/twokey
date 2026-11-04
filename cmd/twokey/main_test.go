package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryReplayScenarioIsHeld(t *testing.T) {
	engine, err := loadEngine("")
	if err != nil {
		t.Fatal(err)
	}
	for name, sc := range scenarios {
		err := explain(io.Discard, engine, sc.method, sc.url, sc.header, []byte(sc.body))
		if !errors.Is(err, errHeld) {
			t.Errorf("scenario %q is not held (err=%v)", name, err)
		}
	}
}

func TestExplainPassesSafeRequests(t *testing.T) {
	engine, err := loadEngine("")
	if err != nil {
		t.Fatal(err)
	}
	if err := explain(io.Discard, engine, "GET", "https://api.github.com/repos/a/b", nil, nil); err != nil {
		t.Fatalf("safe GET should pass, got %v", err)
	}
	if err := explain(io.Discard, engine, "GET", "not a url", nil, nil); err == nil || errors.Is(err, errHeld) {
		t.Fatalf("bad URL must be a usage error, got %v", err)
	}
}

func TestRequireLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:7171": true, "localhost:1": true, "[::1]:7171": true,
		"0.0.0.0:7171": false, ":7171": false, "192.168.1.5:7171": false, "nope": false,
	} {
		if err := requireLoopback(addr); (err == nil) != ok {
			t.Errorf("requireLoopback(%q) err=%v, want ok=%v", addr, err, ok)
		}
	}
}

func TestCurlHomeKeepsUserConfigAndAddsRevokeBestEffort(t *testing.T) {
	user := t.TempDir()
	if err := os.WriteFile(filepath.Join(user, ".curlrc"), []byte("user-agent = \"me\"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CURL_HOME", user)
	dir, err := curlHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".curlrc"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.HasPrefix(got, "user-agent = \"me\"\n") || !strings.HasSuffix(got, "ssl-revoke-best-effort\n") {
		t.Fatalf("unexpected curlrc:\n%s", got)
	}
}

func TestStrictRunArgs(t *testing.T) {
	args := strings.Join(strictRunArgs("node:22", "/proj", "/h/.twokey", "7171", true, false,
		[]string{"claude", "--yes"}), " ")
	for _, want := range []string{
		"--network " + strictNetwork, "-i", "/proj:/work", "-w /work",
		"HTTPS_PROXY=http://twokey-gw-7171:7171", "/twokey/ca.pem:ro", "node:22 claude --yes",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in: %s", want, args)
		}
	}
	for _, secret := range []string{"ca-key.pem", "ntfy-topic"} {
		if strings.Contains(args, secret) {
			t.Fatalf("%s must never be mounted into the agent container: %s", secret, args)
		}
	}
	if strings.Contains(args, " -t ") {
		t.Error("no TTY flag when not attached to a terminal")
	}
}

func TestPhoneTopicIsPersistentAndPrivate(t *testing.T) {
	dir := t.TempDir()
	t1, err := phoneTopic(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := phoneTopic(dir, false)
	if t1 != t2 || len(t1) < 16 {
		t.Fatalf("topic must be stable and long: %q %q", t1, t2)
	}
	t3, _ := phoneTopic(dir, true)
	if t3 == t1 {
		t.Fatal("rotate must produce a new topic")
	}
	if _, err := os.Stat(filepath.Join(dir, phoneTopicFile)); err != nil {
		t.Fatal(err)
	}
}
