package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	bundleFile = "bundle.pem"
	rootsFile  = "roots.pem"
	// curlRootsURL is the Mozilla root store as published by the curl project.
	curlRootsURL = "https://curl.se/ca/cacert.pem"
	// minPublicRoots guards against writing a truncated or bogus root store.
	minPublicRoots = 50
)

// systemRootFiles are well-known PEM root stores on Linux/macOS/BSD.
var systemRootFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/ssl/cert.pem",
	"/usr/local/etc/openssl/cert.pem",
}

// fetchPublicRoots is a variable so tests can avoid the network.
var fetchPublicRoots = downloadCurlRoots

// EnsureBundle writes bundle.pem = public roots + the twokey CA and returns
// its path. Tools such as Python, curl and OpenSSL *replace* their root store
// with SSL_CERT_FILE / REQUESTS_CA_BUNDLE, so the bundle must also contain the
// public roots or every non-intercepted HTTPS call would break.
func (a *Authority) EnsureBundle(ctx context.Context) (string, error) {
	roots, err := a.publicRoots(ctx)
	if err != nil {
		return "", err
	}
	bundle := bytes.Join([][]byte{bytes.TrimSpace(roots), bytes.TrimSpace(a.certPEM)}, []byte("\n"))
	bundle = append(bundle, '\n')
	path := filepath.Join(a.dir, bundleFile)
	if err := os.WriteFile(path, bundle, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// BundlePath is where EnsureBundle writes the combined store.
func (a *Authority) BundlePath() string { return filepath.Join(a.dir, bundleFile) }

func (a *Authority) publicRoots(ctx context.Context) ([]byte, error) {
	cached := filepath.Join(a.dir, rootsFile)
	if data, err := os.ReadFile(cached); err == nil && countCerts(data) >= minPublicRoots {
		return data, nil
	}
	for _, f := range systemRootFiles {
		if data, err := os.ReadFile(f); err == nil && countCerts(data) >= minPublicRoots {
			return data, nil
		}
	}
	data, err := fetchPublicRoots(ctx)
	if err != nil {
		return nil, fmt.Errorf("no system PEM root store found and download failed: %w", err)
	}
	if n := countCerts(data); n < minPublicRoots {
		return nil, fmt.Errorf("downloaded root store has only %d certificates", n)
	}
	if err := os.WriteFile(cached, data, 0o644); err != nil {
		return nil, err
	}
	return data, nil
}

func downloadCurlRoots(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, curlRootsURL, nil)
	if err != nil {
		return nil, err
	}
	// Never route our own bootstrap through a proxy (possibly ourselves).
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", curlRootsURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// countCerts counts parseable certificates in a PEM blob.
func countCerts(pemData []byte) int {
	n := 0
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return n
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err == nil {
				n++
			}
		}
	}
}
