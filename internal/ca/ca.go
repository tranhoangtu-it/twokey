// Package ca manages twokey's local root certificate authority and mints
// short-lived leaf certificates for the hosts the proxy inspects.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFile     = "ca.pem"
	keyFile      = "ca-key.pem"
	rootValidity = 5 * 365 * 24 * time.Hour
	leafValidity = 30 * 24 * time.Hour
)

// Authority is a loaded root CA plus a cache of minted leaf certificates.
type Authority struct {
	dir     string
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	leafKey *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreate loads the CA from dir, generating a new one if absent.
// created reports whether a new CA was written.
func LoadOrCreate(dir string) (a *Authority, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	certPEM, certErr := os.ReadFile(filepath.Join(dir, certFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, keyFile))
	if errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist) {
		certPEM, keyPEM, err = generateRoot()
		if err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o644); err != nil {
			return nil, false, err
		}
		created = true
	} else if certErr != nil || keyErr != nil {
		return nil, false, fmt.Errorf("incomplete CA in %s (delete it to regenerate): %v %v", dir, certErr, keyErr)
	}
	a, err = parseAuthority(dir, certPEM, keyPEM)
	return a, created, err
}

// CertPath is the PEM file to hand to clients (e.g. NODE_EXTRA_CA_CERTS).
func (a *Authority) CertPath() string { return filepath.Join(a.dir, certFile) }

// CertPEM returns the CA certificate in PEM form.
func (a *Authority) CertPEM() []byte { return append([]byte(nil), a.certPEM...) }

// Dir is where the CA files live.
func (a *Authority) Dir() string { return a.dir }

// LeafFor returns a certificate for host (DNS name or IP), signed by the CA.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok && time.Until(c.Leaf.NotAfter) > time.Hour {
		return c, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.leafKey, Leaf: leaf}
	a.leaves[host] = c
	return c, nil
}

func parseAuthority(dir string, certPEM, keyPEM []byte) (*Authority, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("CA files in %s are not valid PEM", dir)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{
		dir: dir, cert: cert, key: key, certPEM: certPEM, leafKey: leafKey,
		leaves: map[string]*tls.Certificate{},
	}, nil
}

func generateRoot() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	hostname, _ := os.Hostname()
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "twokey local CA (" + hostname + ")", Organization: []string{"twokey"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(rootValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
