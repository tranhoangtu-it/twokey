package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	got, _, err := Thumbprints(dir)
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

func TestCurrentThumbprintIsTheLiveCA(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := CurrentThumbprint(dir); ok || err != nil {
		t.Fatalf("no CA yet: ok=%v err=%v", ok, err)
	}
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(dir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	tp, ok, err := CurrentThumbprint(dir)
	if err != nil || !ok || tp != pemThumbprint(t, filepath.Join(dir, certFile)) {
		t.Fatalf("tp=%s ok=%v err=%v", tp, ok, err)
	}
}

func TestThumbprintsEmptyDirIsNotAnError(t *testing.T) {
	got, _, err := Thumbprints(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A file planted in the twokey home (a copy of some real root CA, or junk)
// must never make uninstall remove that root from the OS trust store.
func TestThumbprintsIgnoreForeignAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	foreign := selfSignedPEM(t, "Some Real Root CA", "Real CA Inc")
	if err := os.WriteFile(filepath.Join(dir, "ca.old.1.pem"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.old.2.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, skipped, err := Thumbprints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != pemThumbprint(t, filepath.Join(dir, certFile)) {
		t.Fatalf("want only twokey's own CA, got %v", got)
	}
	if len(skipped) != 2 {
		t.Fatalf("want 2 skipped files, got %v", skipped)
	}
}

func selfSignedPEM(t *testing.T, cn, org string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestResetDropsEveryKeyButKeepsCertsForUntrust(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(dir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	before, _, _ := Thumbprints(dir)
	if err := Reset(dir); err != nil {
		t.Fatal(err)
	}
	if keys, _ := filepath.Glob(filepath.Join(dir, "ca-key*.pem")); len(keys) != 0 {
		t.Fatalf("private keys left after reset: %v", keys)
	}
	after, _, _ := Thumbprints(dir)
	if len(after) != len(before) || len(after) != 2 {
		t.Fatalf("reset must keep every CA cert for untrust: before %v after %v", before, after)
	}
	if _, created, err := LoadOrCreate(dir); err != nil || !created {
		t.Fatalf("a new CA must be created after reset: created=%v err=%v", created, err)
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
	got, _, err := Thumbprints(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}
