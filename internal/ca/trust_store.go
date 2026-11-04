package ca

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Thumbprints returns the SHA-1 thumbprints (upper-case hex, the form
// certutil and `security -Z` use) of every CA certificate twokey has written
// to dir: the current ca.pem and every rotated ca.old*.pem. Uninstall removes
// exactly these from the OS trust store, never anything matched by name.
func Thumbprints(dir string) ([]string, error) {
	old, err := filepath.Glob(filepath.Join(dir, "ca.old*.pem"))
	if err != nil {
		return nil, err
	}
	paths := append([]string{filepath.Join(dir, certFile)}, old...)
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s is not a PEM certificate", p)
		}
		sum := sha1.Sum(block.Bytes)
		tp := strings.ToUpper(hex.EncodeToString(sum[:]))
		if !seen[tp] {
			seen[tp] = true
			out = append(out, tp)
		}
	}
	sort.Strings(out)
	return out, nil
}

// HardenKey restricts an existing CA key to the current user (Windows ACL;
// Unix keys are already written 0600). Safe to call repeatedly.
func HardenKey(dir string) error {
	p := filepath.Join(dir, keyFile)
	if _, err := os.Stat(p); err != nil {
		return err
	}
	return restrictKeyACL(p)
}
