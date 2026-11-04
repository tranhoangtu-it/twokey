package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

// TestConstrainedCACannotSignForIPs: even with the CA key (e.g. leaked),
// a certificate for an IP address must not verify under the constrained
// root, for either address family.
func TestConstrainedCACannotSignForIPs(t *testing.T) {
	a, _, err := LoadOrCreate(t.TempDir(), "github.com")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(a.CertPEM())
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"8.8.8.8", "127.0.0.1", "2001:4860:4860::8888"} {
		serial, _ := randomSerial()
		tpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: ip},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:  []net.IP{net.ParseIP(ip)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &leafKey.PublicKey, a.key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ip, Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Errorf("a leaf for IP %s verifies under the name-constrained CA", ip)
		}
	}
	if _, err := a.LeafFor("8.8.8.8"); err == nil {
		t.Error("a name-constrained CA must refuse to issue for an IP address")
	}
	if a.Permits("10.0.0.1") {
		t.Error("Permits must refuse IP addresses for a name-constrained CA")
	}
	// DNS leaves keep working.
	leaf, err := a.LeafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.github.com", Roots: pool}); err != nil {
		t.Fatalf("permitted DNS leaf: %v", err)
	}
}
