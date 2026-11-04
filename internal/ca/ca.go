// Package ca manages twokey's local root certificate authority and mints
// short-lived leaf certificates for the hosts the proxy inspects.
package ca

import (
	"bytes"
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
	"strings"
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

const (
	lockFile     = "ca.lock"
	lockWait     = 10 * time.Second
	lockStaleAge = 30 * time.Second
	// maxCachedLeaves bounds the leaf certificate cache.
	maxCachedLeaves = 1024
)

// LoadOrCreate loads the CA from dir, generating a new one if absent.
// permitted, if given, are the DNS domains a new CA may issue for (X.509
// name constraints), so a leaked CA key cannot impersonate unrelated sites.
// An existing constrained CA that does not cover permitted is an error.
// created reports whether a new CA was written.
func LoadOrCreate(dir string, permitted ...string) (a *Authority, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		certPEM, certErr := os.ReadFile(filepath.Join(dir, certFile))
		keyPEM, keyErr := os.ReadFile(filepath.Join(dir, keyFile))
		switch {
		case certErr == nil && keyErr == nil:
			a, err = parseAuthority(dir, certPEM, keyPEM)
			if err != nil {
				return nil, false, err
			}
			return a, created, a.covers(permitted)
		case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
			ok, err := createLocked(dir, permitted)
			if err != nil {
				return nil, false, err
			}
			created = created || ok
		}
		// Partial state (one file present) is normally another process
		// mid-write; re-read until the deadline before calling it broken.
		if time.Now().After(deadline) {
			return nil, false, fmt.Errorf("incomplete CA in %s (run `twokey ca reset`): cert=%v key=%v", dir, certErr, keyErr)
		}
		if !created {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// createLocked generates the CA unless another process holds the lock.
// It reports whether this process wrote the CA.
func createLocked(dir string, permitted []string) (bool, error) {
	lock := filepath.Join(dir, lockFile)
	if info, err := os.Stat(lock); err == nil && time.Since(info.ModTime()) > lockStaleAge {
		_ = os.Remove(lock) // left behind by a crashed process
	}
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return false, nil // someone else is creating it; caller retries
	}
	if err != nil {
		return false, err
	}
	f.Close()
	defer os.Remove(lock)

	// Another process may have finished between our read and taking the
	// lock: never overwrite an existing CA.
	if _, err := os.Stat(filepath.Join(dir, certFile)); err == nil {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err == nil {
		return false, nil
	}
	certPEM, keyPEM, err := generateRoot(permitted)
	if err != nil {
		return false, err
	}
	// Key first, cert last: readers treat "cert exists" as "CA complete".
	if err := writeFileAtomic(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		return false, err
	}
	if err := writeFileAtomic(filepath.Join(dir, certFile), certPEM, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// writeFileAtomic writes via a unique temp file + rename, so concurrent
// twokey processes never truncate each other's output. If the rename fails
// (on Windows: the target is open in another process) but the target
// already holds the same bytes, that is success.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if existing, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(existing, data) {
			return nil
		}
		return err
	}
	return nil
}

// Reset deletes the CA (and the bundle that embeds it) from dir.
func Reset(dir string) error {
	for _, f := range []string{certFile, keyFile, bundleFile, lockFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// covers checks that a name-constrained CA may issue for every domain.
func (a *Authority) covers(domains []string) error {
	if len(a.cert.PermittedDNSDomains) == 0 {
		return nil // unconstrained (or legacy) CA covers everything
	}
	for _, d := range domains {
		if !domainPermitted(d, a.cert.PermittedDNSDomains) {
			return fmt.Errorf("%w: cannot issue certificates for %q", ErrConstraintsOutdated, d)
		}
	}
	return nil
}

// ErrConstraintsOutdated means the CA's name constraints predate the rule
// packs (e.g. after an upgrade added providers); see Rotate.
var ErrConstraintsOutdated = errors.New("the twokey CA does not cover all rule domains")

// Rotate moves the current CA aside (ca.old.pem / ca-key.old.pem) and drops
// files derived from it, so the next LoadOrCreate creates a fresh CA.
func Rotate(dir string) error {
	for _, f := range []string{certFile, keyFile} {
		old := filepath.Join(dir, strings.TrimSuffix(f, ".pem")+".old.pem")
		if err := os.Rename(filepath.Join(dir, f), old); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, f := range []string{bundleFile, javaTrustStoreFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Permits reports whether the CA may issue a certificate for host.
func (a *Authority) Permits(host string) bool {
	if net.ParseIP(host) != nil || len(a.cert.PermittedDNSDomains) == 0 {
		return true
	}
	return domainPermitted(host, a.cert.PermittedDNSDomains)
}

func domainPermitted(host string, permitted []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range permitted {
		p = strings.ToLower(p)
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// CertPath is the PEM file to hand to clients (e.g. NODE_EXTRA_CA_CERTS).
func (a *Authority) CertPath() string { return filepath.Join(a.dir, certFile) }

// CertPEM returns the CA certificate in PEM form.
func (a *Authority) CertPEM() []byte { return append([]byte(nil), a.certPEM...) }

// Dir is where the CA files live.
func (a *Authority) Dir() string { return a.dir }

// LeafFor returns a certificate for host (DNS name or IP), signed by the CA.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok && time.Until(c.Leaf.NotAfter) > time.Hour {
		return c, nil
	}
	if len(a.leaves) >= maxCachedLeaves {
		a.leaves = map[string]*tls.Certificate{} // wildcard rules can mint many hosts
	}
	if !a.Permits(host) {
		return nil, fmt.Errorf("host %q is outside the CA's name constraints; run `twokey ca reset`", host)
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

func generateRoot(permitted []string) (certPEM, keyPEM []byte, err error) {
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
	if len(permitted) > 0 {
		tpl.PermittedDNSDomains = permitted
		tpl.PermittedDNSDomainsCritical = true
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
