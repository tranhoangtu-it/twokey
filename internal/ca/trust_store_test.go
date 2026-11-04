package ca

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pemThumbprint(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	sum := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestThumbprintsIncludeRotatedCAs(t *testing.T) {
	dir := t.TempDir()
	want := map[string]bool{}
	for i := 0; i < 3; i++ {
		if _, _, err := LoadOrCreate(dir); err != nil {
			t.Fatal(err)
		}
		want[pemThumbprint(t, filepath.Join(dir, certFile))] = true
		if i < 2 {
			if err := Rotate(dir); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := Thumbprints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || len(want) != 3 {
		t.Fatalf("want 3 distinct thumbprints, got %v", got)
	}
	for _, tp := range got {
		if !want[tp] {
			t.Fatalf("unexpected thumbprint %s (want %v)", tp, want)
		}
	}
}

func TestThumbprintsEmptyDirIsNotAnError(t *testing.T) {
	got, err := Thumbprints(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestThumbprintsIncludeLegacyOldName(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	// v0.4 kept a single rotated CA as ca.old.pem.
	if err := os.Rename(filepath.Join(dir, certFile), filepath.Join(dir, "ca.old.pem")); err != nil {
		t.Fatal(err)
	}
	got, err := Thumbprints(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}
