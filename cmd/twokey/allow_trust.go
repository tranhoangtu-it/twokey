package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// allowTrustFile records which project allow files the human reviewed, by
// absolute path and SHA-256 of the content (like direnv's `allow`). The
// project directory is where the agent works and can write, so a
// ./.twokey-allow.yaml it wrote, or one that came with a cloned repo, must
// never pre-approve anything until a human trusts that exact content.
const allowTrustFile = "allow-trusted.json"

type trustStore struct {
	Files map[string]string `json:"files"` // absolute path -> sha256 hex
}

// allowLoad is the allow list to use and why a project file was skipped.
type allowLoad struct {
	allows  []rules.Allow
	path    string
	warning string // set when ./.twokey-allow.yaml exists but is not used
}

// loadProjectAllow returns the allow rules for this run. An explicit
// --allow FILE is the human naming the file, so it is used as is (and must
// exist). Otherwise ./.twokey-allow.yaml is used only if its current
// content was trusted with `twokey allow trust`.
func loadProjectAllow(home, explicit string) (allowLoad, error) {
	if explicit != "" {
		data, err := os.ReadFile(explicit)
		if err != nil {
			return allowLoad{}, fmt.Errorf("allow rules %s: %w", explicit, err)
		}
		allows, err := rules.ParseAllow(data)
		if err != nil {
			return allowLoad{}, fmt.Errorf("allow rules %s: %w", explicit, err)
		}
		if len(allows) == 0 {
			return allowLoad{}, fmt.Errorf("allow rules %s: no entries", explicit)
		}
		return allowLoad{allows: allows, path: explicit}, nil
	}
	data, err := os.ReadFile(defaultAllowFile)
	if errors.Is(err, os.ErrNotExist) {
		return allowLoad{}, nil
	}
	if err != nil {
		return allowLoad{}, fmt.Errorf("allow rules %s: %w", defaultAllowFile, err)
	}
	key, err := allowKey(defaultAllowFile)
	if err != nil {
		return allowLoad{}, err
	}
	store, err := readTrust(home)
	if err != nil {
		return allowLoad{path: key, warning: fmt.Sprintf("IGNORED %s: the trust list %s is unreadable (%v); fix or delete it, then run `twokey allow trust`",
			key, filepath.Join(home, allowTrustFile), err)}, nil
	}
	sum, ok := store.Files[key]
	switch {
	case !ok:
		return allowLoad{path: key, warning: fmt.Sprintf("IGNORED %s: not trusted yet (an agent can write files in this directory). Review it, then run `twokey allow trust`", key)}, nil
	case sum != digest(data):
		return allowLoad{path: key, warning: fmt.Sprintf("IGNORED %s: changed since you trusted it. Review it, then run `twokey allow trust`", key)}, nil
	}
	// Parse the bytes that were hashed, not a second read of the file.
	allows, err := rules.ParseAllow(data)
	if err != nil {
		return allowLoad{}, fmt.Errorf("allow rules %s: %w", key, err)
	}
	return allowLoad{allows: allows, path: key}, nil
}

// trustAllow records file's current content as reviewed. It refuses files
// that do not parse, and returns the entries so the human sees what they
// trusted.
func trustAllow(home, file string) (allowLoad, error) {
	if file == "" {
		file = defaultAllowFile
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return allowLoad{}, err
	}
	allows, err := rules.ParseAllow(data)
	if err != nil {
		return allowLoad{}, fmt.Errorf("%s: %w", file, err)
	}
	key, err := allowKey(file)
	if err != nil {
		return allowLoad{}, err
	}
	store, err := readTrust(home)
	if err != nil {
		store = trustStore{} // unreadable list: start over rather than block trusting
	}
	if store.Files == nil {
		store.Files = map[string]string{}
	}
	store.Files[key] = digest(data)
	if err := writeTrust(home, store); err != nil {
		return allowLoad{}, err
	}
	return allowLoad{allows: allows, path: key}, nil
}

// revokeAllow forgets file; it reports whether it was trusted.
func revokeAllow(home, file string) (bool, error) {
	if file == "" {
		file = defaultAllowFile
	}
	key, err := allowKey(file)
	if err != nil {
		return false, err
	}
	store, err := readTrust(home)
	if err != nil {
		return false, err
	}
	if _, ok := store.Files[key]; !ok {
		return false, nil
	}
	delete(store.Files, key)
	return true, writeTrust(home, store)
}

// allowKey is the canonical absolute path of an allow file.
func allowKey(file string) (string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	return abs, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readTrust(home string) (trustStore, error) {
	data, err := os.ReadFile(filepath.Join(home, allowTrustFile))
	if errors.Is(err, os.ErrNotExist) {
		return trustStore{Files: map[string]string{}}, nil
	}
	if err != nil {
		return trustStore{}, err
	}
	var s trustStore
	if err := json.Unmarshal(data, &s); err != nil {
		return trustStore{}, err
	}
	if s.Files == nil {
		s.Files = map[string]string{}
	}
	return s, nil
}

// writeTrust replaces the trust list atomically, readable only by the user.
func writeTrust(home string, s trustStore) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(home, allowTrustFile+".*.tmp") // created 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(append(data, '\n'))
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = ca.RestrictToUser(name) // Windows ignores 0600
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(home, allowTrustFile))
	}
	if werr != nil {
		os.Remove(name)
	}
	return werr
}

func cmdAllow(args []string) error {
	const usage = "usage: twokey allow trust [FILE] | twokey allow revoke [FILE]   (FILE defaults to ./" + defaultAllowFile + ")"
	if len(args) == 0 || len(args) > 2 {
		return errors.New(usage)
	}
	file := ""
	if len(args) == 2 {
		file = args[1]
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	switch args[0] {
	case "trust":
		got, err := trustAllow(home, file)
		if err != nil {
			return err
		}
		fmt.Printf("trusted %s (%d entr%s) — it is used until its content changes:\n", approval.Clean(got.path), len(got.allows), plural(len(got.allows), "y", "ies"))
		printAllowEntries(got.allows)
		return nil
	case "revoke":
		ok, err := revokeAllow(home, file)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("not trusted; nothing to revoke")
			return nil
		}
		fmt.Println("revoked: twokey ignores it until you trust it again")
		return nil
	default:
		return errors.New(usage)
	}
}

func printAllowEntries(allows []rules.Allow) {
	sorted := append([]rules.Allow(nil), allows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Rule < sorted[j].Rule })
	for _, a := range sorted {
		line := fmt.Sprintf("  %-28s resource %q", approval.Clean(a.Rule), approval.Clean(a.Resource))
		if a.Reason != "" {
			line += "  (" + approval.Clean(a.Reason) + ")"
		}
		fmt.Println(line)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
