package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"rsc.io/qr"
)

type setupOptions struct {
	yes         bool // never prompt
	trust       bool // add the CA to the OS trust store without asking
	noPhone     bool
	noDoctor    bool
	interactive bool   // stdin is a terminal
	goos        string // runtime.GOOS (injectable for tests)
	server      string // ntfy server
}

// setupDeps are the side effects setup performs, injectable for tests.
type setupDeps struct {
	trust  func(certPath string) error
	doctor func(addr string) error
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	var o setupOptions
	fs.BoolVar(&o.yes, "yes", false, "do not ask questions (the OS trust store is changed only with --trust)")
	fs.BoolVar(&o.trust, "trust", false, "add the twokey CA to the OS trust store (Windows/macOS user store)")
	fs.BoolVar(&o.noPhone, "no-phone", false, "skip phone (ntfy) setup")
	fs.BoolVar(&o.noDoctor, "no-doctor", false, "skip the runtime check")
	fs.StringVar(&o.server, "ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.goos = runtime.GOOS
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		o.interactive = true
	}
	return runSetup(os.Stdout, os.Stdin, o, setupDeps{
		trust:  trustCA,
		doctor: func(addr string) error { return cmdDoctor([]string{"--addr", addr}) },
	})
}

// runSetup takes a fresh machine to "ready": CA, optional OS trust, phone
// approvals and a runtime check, then prints the command to run next.
func runSetup(w io.Writer, in io.Reader, o setupOptions, d setupDeps) error {
	a, created, err := loadAuthority(nil)
	if err != nil {
		return err
	}
	if _, err := a.EnsureBundle(context.Background()); err != nil {
		fmt.Fprintf(w, "warning: no CA bundle (%v); Python/curl may reject intercepted hosts\n", err)
	}
	state := "existing"
	if created {
		state = "created"
	}
	fmt.Fprintf(w, "1. Local CA (%s): %s\n   name-constrained to the rule packs' domains; the key never leaves this machine.\n", state, a.CertPath())

	if err := setupTrust(w, in, o, d, a.CertPath()); err != nil {
		return err
	}

	next := "twokey up      (then, in another terminal: twokey run -- claude)"
	if !o.noPhone {
		home, err := homeDir()
		if err != nil {
			return err
		}
		topic, err := phoneTopic(home, false)
		if err != nil {
			return err
		}
		url := strings.TrimRight(o.server, "/") + "/" + topic
		fmt.Fprintf(w, "\n3. Phone approvals: install the ntfy app and subscribe to\n     %s\n   (scan with your phone, or open the link). Keep it private: anyone with it can approve.\n\n", url)
		if err := renderQR(w, url); err != nil {
			fmt.Fprintf(w, "   (QR code unavailable: %v)\n", err)
		}
		next = "twokey run --phone -- claude      (one terminal, approve on your phone)"
	}

	if !o.noDoctor {
		fmt.Fprintln(w, "\n4. Checking that your runtimes go through twokey:")
		if err := setupDoctor(d); err != nil {
			fmt.Fprintf(w, "   %v — see the hints above; you can re-run `twokey doctor` while `twokey up` runs.\n", err)
		}
	}
	fmt.Fprintf(w, "\nReady. Next:\n  %s\n  twokey run --observe -- claude    (trial: logs what would be held, holds nothing)\n", next)
	return nil
}

func setupTrust(w io.Writer, in io.Reader, o setupOptions, d setupDeps, certPath string) error {
	if o.goos != "windows" && o.goos != "darwin" {
		fmt.Fprintln(w, "2. OS trust: not needed on this OS (twokey run sets SSL_CERT_FILE and friends).")
		return nil
	}
	doTrust := o.trust
	if !doTrust && o.interactive && !o.yes {
		fmt.Fprint(w, "2. Go tools (gh, terraform, flyctl) and Windows curl only trust the OS store.\n"+
			"   Add the twokey CA to your user trust store (no admin)? [y/N] ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		doTrust = ans == "y" || ans == "yes"
	}
	if !doTrust {
		fmt.Fprintln(w, "2. OS trust: skipped (run `twokey ca trust` later; `twokey uninstall` removes it).")
		return nil
	}
	if err := d.trust(certPath); err != nil {
		return fmt.Errorf("trust CA: %w", err)
	}
	fmt.Fprintln(w, "   trusted — `twokey ca untrust` or `twokey uninstall` removes it.")
	return nil
}

// setupDoctor runs the doctor against a short-lived in-process proxy in
// observe mode, so nothing can be held while probing.
func setupDoctor(d setupDeps) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := startProxy(ctx, proxyConfig{addr: "127.0.0.1:0", timeout: time.Minute, observe: true, logTo: io.Discard})
	if err != nil {
		return err
	}
	return d.doctor(p.addr)
}

// renderQR prints text as a QR code with half-block characters, light
// modules drawn as blocks (for the usual dark terminal), with a quiet zone.
func renderQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2
	light := func(x, y int) bool {
		if x < 0 || y < 0 || x >= code.Size || y >= code.Size {
			return true
		}
		return !code.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		b.WriteString("   ")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := light(x, y), light(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	_, err = io.WriteString(w, b.String())
	return err
}
