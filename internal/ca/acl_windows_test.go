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
