package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tranhoangtu-it/twokey/internal/ca"
)

// fakeRunner records commands and answers from a script keyed by the
// command line prefix.
type fakeRunner struct {
	calls   []string
	answers map[string]string // prefix -> output
	fail    map[string]bool   // prefix -> return error
}

func (f *fakeRunner) run(name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	for p := range f.fail {
		if strings.HasPrefix(line, p) {
			return nil, errors.New("failed")
		}
	}
	for p, out := range f.answers {
		if strings.HasPrefix(line, p) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

const tpA = "D2E293BFEC06FDB1A8A0924AB662B1DFCE6EF3A0"

func TestUntrustWindowsUsesExactThumbprintPath(t *testing.T) {
	f := &fakeRunner{answers: map[string]string{"powershell": "removed"}}
	u := uninstaller{goos: "windows", run: f.run, out: &bytes.Buffer{}}
	n, err := u.untrust([]string{tpA})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(f.calls) != 1 || !strings.Contains(f.calls[0], `Cert:\CurrentUser\Root\`+tpA) {
		t.Fatalf("calls=%v", f.calls)
	}
	if strings.Contains(f.calls[0], "certutil") {
		t.Fatal("certutil -delstore treats numeric ids as indexes; must not be used")
	}
}

func TestUntrustRejectsMalformedThumbprint(t *testing.T) {
	f := &fakeRunner{}
	u := uninstaller{goos: "windows", run: f.run, out: &bytes.Buffer{}}
	for _, bad := range []string{"0", "'; Remove-Item C:\\ #", strings.Repeat("G", 40), strings.Repeat("A", 39)} {
		if _, err := u.untrust([]string{bad}); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("ran commands for malformed thumbprints: %v", f.calls)
	}
}

func TestUntrustDarwinUsesSHA1Flag(t *testing.T) {
	f := &fakeRunner{answers: map[string]string{"security find-certificate": "SHA-1 hash: " + tpA + "\n"}}
	u := uninstaller{goos: "darwin", run: f.run, out: &bytes.Buffer{}}
	if n, err := u.untrust([]string{tpA}); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(f.calls) != 2 || !strings.HasPrefix(f.calls[1], "security delete-certificate -Z "+tpA+" ") {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestUntrustLinuxChangesNothing(t *testing.T) {
	f := &fakeRunner{}
	u := uninstaller{goos: "linux", run: f.run, out: &bytes.Buffer{}}
	if n, err := u.untrust([]string{tpA}); err != nil || n != 0 || len(f.calls) != 0 {
		t.Fatalf("n=%d err=%v calls=%v", n, err, f.calls)
	}
}

func TestUninstallRemovesOnlyTwokeyContainers(t *testing.T) {
	f := &fakeRunner{answers: map[string]string{
		"docker ps": "twokey-gw-7171\nmy-twokey-gw-app\ntwokey-gw-8080\n",
	}}
	out := &bytes.Buffer{}
	u := uninstaller{home: t.TempDir(), goos: "linux", run: f.run, out: out}
	if err := u.Run(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "docker rm -f twokey-gw-7171") || !strings.Contains(joined, "docker rm -f twokey-gw-8080") {
		t.Fatalf("calls=%v", f.calls)
	}
	if strings.Contains(joined, "rm -f my-twokey-gw-app") {
		t.Fatal("removed a container twokey did not create")
	}
	if !strings.Contains(joined, "docker network rm "+strictNetwork) {
		t.Fatalf("network not removed: %v", f.calls)
	}
}

func TestUninstallIsIdempotentWithoutDocker(t *testing.T) {
	f := &fakeRunner{fail: map[string]bool{"docker": true}}
	out := &bytes.Buffer{}
	u := uninstaller{home: t.TempDir(), goos: "windows", run: f.run, out: out}
	for i := 0; i < 2; i++ {
		if err := u.Run(); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if !strings.Contains(out.String(), "nothing to remove") {
		t.Fatalf("output: %s", out)
	}
}

func TestPurgeDeletesTwokeyHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".twokey")
	if _, _, err := ca.LoadOrCreate(home); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{answers: map[string]string{"powershell": "removed"}, fail: map[string]bool{"docker": true}}
	u := uninstaller{home: home, goos: "windows", run: f.run, out: &bytes.Buffer{}, purge: true}
	if err := u.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("home still exists: %v", err)
	}
}

// TWOKEY_HOME may point at a directory with other content: purge deletes
// only the files twokey writes and keeps the directory if anything is left.
func TestPurgeDeletesOnlyTwokeyFiles(t *testing.T) {
	home := t.TempDir()
	if _, _, err := ca.LoadOrCreate(home); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(home, "important.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{fail: map[string]bool{"docker": true}}
	u := uninstaller{home: home, goos: "linux", run: f.run, out: &bytes.Buffer{}, purge: true}
	if err := u.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("a file twokey did not write was deleted")
	}
	for _, name := range []string{"ca.pem", "ca-key.pem"} {
		if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
			t.Fatalf("%s not purged", name)
		}
	}
}

func TestUntrustDarwinReportsRealFailures(t *testing.T) {
	present := map[string]string{"security find-certificate": "SHA-1 hash: " + tpA + "\n"}
	f := &fakeRunner{answers: present, fail: map[string]bool{"security delete-certificate": true}}
	u := uninstaller{goos: "darwin", run: f.run, out: &bytes.Buffer{}}
	if _, err := u.untrust([]string{tpA}); err == nil {
		t.Fatal("a failed keychain deletion was reported as success")
	}
	f = &fakeRunner{answers: map[string]string{"security find-certificate": "SHA-1 hash: 0000\n"}}
	u.run = f.run
	if n, err := u.untrust([]string{tpA}); err != nil || n != 0 {
		t.Fatalf("absent certificate must be a no-op: n=%d err=%v", n, err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "delete-certificate") {
			t.Fatal("tried to delete a certificate that is not in the keychain")
		}
	}
}
