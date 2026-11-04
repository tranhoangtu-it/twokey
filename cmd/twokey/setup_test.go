package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tranhoangtu-it/twokey/internal/ca"
)

type setupFakes struct {
	trusted []string
	doctors []string
}

func (f *setupFakes) deps() setupDeps {
	return setupDeps{
		trust:  func(p string) error { f.trusted = append(f.trusted, p); return nil },
		doctor: func(addr string) error { f.doctors = append(f.doctors, addr); return nil },
	}
}

func TestSetupNonInteractiveCreatesCAAndTopicWithoutTrusting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWOKEY_HOME", home)
	f := &setupFakes{}
	var out bytes.Buffer
	err := runSetup(&out, strings.NewReader(""), setupOptions{yes: true, goos: "windows", server: "https://ntfy.sh"}, f.deps())
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, name := range []string{"ca.pem", "ntfy-topic"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Errorf("%s not created: %v", name, err)
		}
	}
	if len(f.trusted) != 0 {
		t.Fatal("--yes without --trust must not change the OS trust store")
	}
	if len(f.doctors) != 1 || !strings.HasPrefix(f.doctors[0], "127.0.0.1:") {
		t.Fatalf("doctor should run against a temporary local proxy, got %v", f.doctors)
	}
	topic, _ := os.ReadFile(filepath.Join(home, "ntfy-topic"))
	if !strings.Contains(out.String(), "https://ntfy.sh/"+strings.TrimSpace(string(topic))) {
		t.Fatalf("subscribe URL missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "twokey run") {
		t.Fatal("setup must end with the next command to run")
	}
}

func TestSetupPromptsBeforeTrusting(t *testing.T) {
	t.Setenv("TWOKEY_HOME", t.TempDir())
	f := &setupFakes{}
	var out bytes.Buffer
	o := setupOptions{interactive: true, goos: "windows", noPhone: true, noDoctor: true}
	if err := runSetup(&out, strings.NewReader("y\n"), o, f.deps()); err != nil {
		t.Fatal(err)
	}
	if len(f.trusted) != 1 || !strings.HasSuffix(f.trusted[0], "ca.pem") {
		t.Fatalf("answering y must trust ca.pem, got %v", f.trusted)
	}
	f.trusted = nil
	if err := runSetup(&out, strings.NewReader("\n"), o, f.deps()); err != nil {
		t.Fatal(err)
	}
	if len(f.trusted) != 0 {
		t.Fatal("the default answer must be no")
	}
}

func TestSetupTrustShowsStepAndSuggestsRetiringOldCAs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TWOKEY_HOME", home)
	if _, _, err := ca.LoadOrCreate(home); err != nil {
		t.Fatal(err)
	}
	if err := ca.Rotate(home); err != nil { // as an upgrade would
		t.Fatal(err)
	}
	f := &setupFakes{}
	var out bytes.Buffer
	o := setupOptions{trust: true, yes: true, goos: "windows", noPhone: true, noDoctor: true}
	if err := runSetup(&out, strings.NewReader(""), o, f.deps()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2. OS trust") {
		t.Fatalf("step 2 label missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "twokey ca untrust --retired") {
		t.Fatalf("retired CAs not mentioned:\n%s", out.String())
	}
}

func TestSetupNeverPromptsOnLinux(t *testing.T) {
	t.Setenv("TWOKEY_HOME", t.TempDir())
	f := &setupFakes{}
	var out bytes.Buffer
	o := setupOptions{interactive: true, goos: "linux", noPhone: true, noDoctor: true}
	if err := runSetup(&out, strings.NewReader("y\n"), o, f.deps()); err != nil {
		t.Fatal(err)
	}
	if len(f.trusted) != 0 || strings.Contains(out.String(), "[y/N]") {
		t.Fatalf("linux needs no trust change; trusted=%v out=%s", f.trusted, out.String())
	}
}

func TestRenderQRIsSquareBlocks(t *testing.T) {
	var out bytes.Buffer
	if err := renderQR(&out, "https://ntfy.sh/twokey-abc"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) < 10 || !strings.ContainsAny(out.String(), "█▀▄") {
		t.Fatalf("unexpected QR rendering:\n%s", out.String())
	}
}
