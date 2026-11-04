package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

// JavaTrustStorePassword is the conventional JDK truststore password; the
// store holds only public certificates, so it protects nothing secret.
const JavaTrustStorePassword = "changeit"

const javaTrustStoreFile = "truststore.p12"

// WriteJavaTrustStore converts the PEM bundle (public roots + twokey CA)
// into a PKCS#12 truststore the JVM can load, since Java cannot read PEM
// trust stores. Like SSL_CERT_FILE it replaces the JVM's default trust, so
// it must contain the public roots too.
func (a *Authority) WriteJavaTrustStore(bundlePath string) (string, error) {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return "", err
	}
	var certs []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return "", errors.New("no certificates in bundle")
	}
	// LegacyDES: readable by every JDK (8+); the contents are public anyway.
	p12, err := pkcs12.LegacyDES.EncodeTrustStore(certs, JavaTrustStorePassword)
	if err != nil {
		return "", err
	}
	path := filepath.Join(a.dir, javaTrustStoreFile)
	if err := writeFileAtomic(path, p12, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
