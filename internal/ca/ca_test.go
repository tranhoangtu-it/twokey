package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
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

func TestNameConstrainedCA(t *testing.T) {
	dir := t.TempDir()
	a, _, err := LoadOrCreate(dir, "github.com", "railway.com")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(a.CertPEM())

	leaf, err := a.LeafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.github.com", Roots: pool}); err != nil {
		t.Fatalf("permitted host should verify: %v", err)
	}
	if _, err := a.LeafFor("www.mybank.com"); err == nil {
		t.Fatal("CA must refuse hosts outside its name constraints")
	}
	if _, _, err := LoadOrCreate(dir, "github.com", "amazonaws.com"); !errors.Is(err, ErrConstraintsOutdated) {
		t.Fatalf("rules outside the CA's constraints must report ErrConstraintsOutdated, got %v", err)
	}
	if err := Rotate(dir); err != nil {
		t.Fatal(err)
	}
	b, created, err := LoadOrCreate(dir, "github.com", "amazonaws.com")
	if err != nil || !created || bytes.Equal(b.CertPEM(), a.CertPEM()) {
		t.Fatalf("rotation should create a new covering CA: created=%v err=%v", created, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.old.pem")); err != nil {
		t.Fatal("old CA must be kept as ca.old.pem")
	}
	if _, _, err := LoadOrCreate(dir, "github.com"); err != nil {
		t.Fatalf("subset of constraints must load: %v", err)
	}
}

func TestConcurrentCreateYieldsOneCA(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	pems := make(chan []byte, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			a, _, err := LoadOrCreate(dir, "github.com")
			if err != nil {
				errs <- err
				return
			}
			pems <- a.CertPEM()
		}()
	}
	var first []byte
	for i := 0; i < n; i++ {
		select {
		case err := <-errs:
			t.Fatal(err)
		case p := <-pems:
			if first == nil {
				first = p
			} else if !bytes.Equal(first, p) {
				t.Fatal("concurrent starts produced different CAs")
			}
		}
	}
}

func TestJavaTrustStoreRoundTrip(t *testing.T) {
	a, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(bundle, a.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := a.WriteJavaTrustStore(bundle)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	certs, err := pkcs12.DecodeTrustStore(data, JavaTrustStorePassword)
	if err != nil || len(certs) != 1 || !strings.HasPrefix(certs[0].Subject.CommonName, "twokey local CA") {
		t.Fatalf("truststore round trip: %v %v", certs, err)
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
		certPEM, _, err := generateRoot(nil)
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
