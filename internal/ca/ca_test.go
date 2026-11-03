package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	a1, created, err := LoadOrCreate(dir)
	if err != nil || !created {
		t.Fatalf("first load: created=%v err=%v", created, err)
	}
	a2, created, err := LoadOrCreate(dir)
	if err != nil || created {
		t.Fatalf("second load: created=%v err=%v", created, err)
	}
	if !bytes.Equal(a1.CertPEM(), a2.CertPEM()) {
		t.Fatal("reloaded CA differs from the generated one")
	}
}

func TestLeafVerifiesAgainstCA(t *testing.T) {
	a, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(a.CertPEM())

	for _, host := range []string{"api.github.com", "127.0.0.1"} {
		leaf, err := a.LeafFor(host)
		if err != nil {
			t.Fatalf("LeafFor(%s): %v", host, err)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			t.Fatalf("leaf for %s does not verify: %v", host, err)
		}
		again, _ := a.LeafFor(host)
		if again != leaf {
			t.Errorf("leaf for %s not cached", host)
		}
	}
}

func TestEnsureBundleContainsRootsAndCA(t *testing.T) {
	a, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Fake "public roots": 60 throwaway CAs, so the test never hits the network.
	var fake bytes.Buffer
	for i := 0; i < 60; i++ {
		certPEM, _, err := generateRoot()
		if err != nil {
			t.Fatal(err)
		}
		fake.Write(certPEM)
	}
	orig, origFiles := fetchPublicRoots, systemRootFiles
	fetchPublicRoots = func(context.Context) ([]byte, error) { return fake.Bytes(), nil }
	systemRootFiles = nil
	t.Cleanup(func() { fetchPublicRoots, systemRootFiles = orig, origFiles })

	path, err := a.EnsureBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := countCerts(data); got != 61 {
		t.Fatalf("bundle has %d certs, want 61", got)
	}
	if !strings.Contains(string(data), strings.TrimSpace(string(a.CertPEM()))) {
		t.Fatal("bundle does not contain the twokey CA")
	}
}
