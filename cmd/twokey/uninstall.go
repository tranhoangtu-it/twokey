package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/tranhoangtu-it/twokey/internal/ca"
)

// uninstaller removes everything twokey put outside its home directory
// (OS trust entries, strict-mode Docker objects) and, with purge, the home
// directory itself. run is injectable so tests never touch the real system.
type uninstaller struct {
	home  string
	goos  string
	run   func(name string, args ...string) ([]byte, error)
	out   io.Writer
	purge bool
}

func newUninstaller(home string, purge bool) uninstaller {
	return uninstaller{home: home, goos: runtime.GOOS, run: execRun, out: os.Stdout, purge: purge}
}

func execRun(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

var thumbprintRE = regexp.MustCompile(`^[0-9A-F]{40}$`)

// untrust removes the given CA thumbprints from the OS trust store and
// reports how many were removed. Only exact SHA-1 thumbprints are accepted:
// `certutil -delstore` would read a numeric id as a store *index*, so on
// Windows the Cert: provider path (exact thumbprint) is used instead.
func (u uninstaller) untrust(thumbprints []string) (int, error) {
	for _, tp := range thumbprints {
		if !thumbprintRE.MatchString(tp) {
			return 0, fmt.Errorf("refusing malformed thumbprint %q", tp)
		}
	}
	if u.goos != "windows" && u.goos != "darwin" {
		if len(thumbprints) > 0 {
			fmt.Fprintln(u.out, "Linux: twokey made no system trust change (it uses SSL_CERT_FILE). If you copied ca.pem into\n"+
				"/usr/local/share/ca-certificates/, remove it there and run `sudo update-ca-certificates`.")
		}
		return 0, nil
	}
	removed := 0
	var errs []error
	for _, tp := range thumbprints {
		ok, err := u.untrustOne(tp)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", tp, err))
		case ok:
			removed++
			fmt.Fprintln(u.out, "removed from OS trust store:", tp)
		}
	}
	return removed, errors.Join(errs...)
}

func (u uninstaller) untrustOne(tp string) (bool, error) {
	if u.goos == "windows" {
		script := fmt.Sprintf(`$p='Cert:\CurrentUser\Root\%s'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -ErrorAction Stop; 'removed' } else { 'absent' }`, tp)
		out, err := u.run("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return false, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return strings.Contains(string(out), "removed"), nil
	}
	home, _ := os.UserHomeDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if _, err := u.run("security", "delete-certificate", "-Z", tp, keychain); err != nil {
		return false, nil // not in the keychain: nothing to do
	}
	return true, nil
}

// removeDocker deletes strict-mode gateway containers and network. Docker
// being absent or stopped is not an error: then there is nothing of ours.
func (u uninstaller) removeDocker() []string {
	out, err := u.run("docker", "ps", "-a", "--filter", "name=twokey-gw-", "--format", "{{.Names}}")
	if err != nil {
		return nil
	}
	var removed []string
	for _, name := range strings.Fields(string(out)) {
		if !strings.HasPrefix(name, "twokey-gw-") { // the filter is a substring match
			continue
		}
		if _, err := u.run("docker", "rm", "-f", name); err == nil {
			removed = append(removed, "container "+name)
		}
	}
	if _, err := u.run("docker", "network", "inspect", strictNetwork); err == nil {
		if _, err := u.run("docker", "network", "rm", strictNetwork); err == nil {
			removed = append(removed, "network "+strictNetwork)
		}
	}
	return removed
}

// ownsHome reports whether dir looks like a twokey home, so --purge never
// deletes an unrelated directory that TWOKEY_HOME happens to point at.
func ownsHome(dir string) bool {
	if filepath.Base(dir) == ".twokey" {
		return true
	}
	for _, f := range []string{"ca.pem", "audit.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// Run untrusts every CA twokey created, removes strict-mode Docker objects
// and, with purge, deletes the home directory. Safe to run repeatedly.
func (u uninstaller) Run() error {
	if u.purge && !ownsHome(u.home) {
		return fmt.Errorf("refusing to purge %s: it does not look like a twokey home", u.home)
	}
	thumbprints, err := ca.Thumbprints(u.home)
	if err != nil {
		return err
	}
	n, untrustErr := u.untrust(thumbprints)
	docker := u.removeDocker()
	for _, d := range docker {
		fmt.Fprintln(u.out, "removed", d)
	}
	if untrustErr != nil {
		return fmt.Errorf("some certificates could not be removed (home kept): %w", untrustErr)
	}
	if u.purge {
		if err := os.RemoveAll(u.home); err != nil {
			return err
		}
		fmt.Fprintln(u.out, "deleted", u.home)
		return nil
	}
	if n == 0 && len(docker) == 0 {
		fmt.Fprintln(u.out, "nothing to remove (twokey has no OS trust entries or Docker objects here)")
	}
	return nil
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also delete the twokey home (CA, audit log, phone topic)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	if err := newUninstaller(home, *purge).Run(); err != nil {
		return err
	}
	if !*purge {
		fmt.Println("CA files and audit log kept in", home, "(use --purge to delete them).")
	}
	fmt.Println("To remove the binary: delete", executablePath())
	return nil
}

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return "the twokey executable"
	}
	return p
}

// cmdCAUntrust removes every CA twokey created from the OS trust store.
func cmdCAUntrust() error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	thumbprints, err := ca.Thumbprints(home)
	if err != nil {
		return err
	}
	u := newUninstaller(home, false)
	n, err := u.untrust(thumbprints)
	if n == 0 && err == nil {
		fmt.Println("no twokey CA in the OS trust store")
	}
	return err
}
