//go:build windows

package ca

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyACLRestrictedToCurrentUser(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	assertKeyOnlyForUser(t, dir)
}

// An elevated process creates files with explicit (not inherited) ACEs for
// SYSTEM and Administrators; hardening must remove those too.
func TestHardenKeyRemovesExplicitForeignACEs(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, keyFile)
	if out, err := exec.Command("icacls", key, "/grant", "*S-1-5-18:F", "*S-1-1-0:R").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	if err := HardenKey(dir); err != nil {
		t.Fatal(err)
	}
	assertKeyOnlyForUser(t, dir)
}

func assertKeyOnlyForUser(t *testing.T, dir string) {
	t.Helper()
	out, err := exec.Command("icacls", filepath.Join(dir, keyFile)).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v\n%s", err, out)
	}
	// Drop the path (it contains "C:\Users\...") and keep only the ACEs.
	acl := strings.ReplaceAll(string(out), filepath.Join(dir, keyFile), "")
	if strings.Contains(acl, "(I)") {
		t.Fatalf("key still inherits ACEs from its folder:\n%s", acl)
	}
	for _, other := range []string{"SYSTEM", "Administrators", "Users", "Everyone"} {
		if strings.Contains(acl, other) {
			t.Fatalf("key is readable by %s:\n%s", other, acl)
		}
	}
}
