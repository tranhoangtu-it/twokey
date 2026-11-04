package ca

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Thumbprints returns the SHA-1 thumbprints (upper-case hex, the form the
// Windows Cert: provider and `security -Z` use) of the twokey CA
// certificates in dir: the current ca.pem and every rotated ca.old*.pem.
// Uninstall removes exactly these from the OS trust store.
//
// Only self-signed CA certificates issued to twokey count. Anything else in
// those files — a copy of a real root CA planted there, or junk — is
// skipped and reported, so it can never be removed from the trust store.
func Thumbprints(dir string) (thumbprints, skipped []string, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(name == certFile || (strings.HasPrefix(name, "ca.old") && strings.HasSuffix(name, ".pem"))) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, nil, err
		}
		tp, ok := twokeyThumbprint(data)
		if !ok {
			skipped = append(skipped, name)
			continue
		}
		if !seen[tp] {
			seen[tp] = true
			thumbprints = append(thumbprints, tp)
		}
	}
	sort.Strings(thumbprints)
	return thumbprints, skipped, nil
}

// twokeyThumbprint returns the thumbprint of a PEM certificate that is a
// self-signed CA issued to organization "twokey".
func twokeyThumbprint(data []byte) (string, bool) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !slices.Contains(cert.Subject.Organization, caOrganization) {
		return "", false
	}
	if cert.CheckSignatureFrom(cert) != nil {
		return "", false
	}
	sum := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:])), true
}

// RestrictToUser limits a secret file (e.g. the phone-approval topic) to
// the current user, like the CA key. On Unix it is a no-op: such files are
// written 0600.
func RestrictToUser(path string) error { return restrictKeyACL(path) }

// HardenKey restricts an existing CA key to the current user (Windows ACL;
// Unix keys are already written 0600). Safe to call repeatedly.
func HardenKey(dir string) error {
	p := filepath.Join(dir, keyFile)
	if _, err := os.Stat(p); err != nil {
		return err
	}
	return restrictKeyACL(p)
}
