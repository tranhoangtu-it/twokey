package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/proxy"
)

// setupExitCode distinguishes twokey's own failures in `run` from the
// agent's exit status (like docker run's 125).
const setupExitCode = 125

const phoneTopicFile = "ntfy-topic"

// shutdownGrace gives denied holds time to be written before exit.
const shutdownGrace = 500 * time.Millisecond

// shutdownDrain bounds how long shutdown waits for denied holds to return
// from the broker (and be audited) before the audit log is closed.
const shutdownDrain = 3 * time.Second

// maxHoldTimeout caps --timeout: every pending hold pins a connection and a
// goroutine, and an hour is longer than anyone keeps an agent waiting.
const maxHoldTimeout = time.Hour

// validateTimeout checks a --timeout flag value.
func validateTimeout(d time.Duration) error {
	if d <= 0 || d > maxHoldTimeout {
		return fmt.Errorf("--timeout must be more than 0 and at most %s (got %s)", maxHoldTimeout, d)
	}
	return nil
}

// denyAndDrain denies every pending hold at shutdown and waits until the
// handlers have returned from the broker, so their by=shutdown rows reach
// the audit log before it is closed, and the 403s reach the agents.
func denyAndDrain(broker *approval.Broker) {
	if broker.DenyAll("twokey is shutting down") > 0 {
		broker.Drain(shutdownDrain)
		time.Sleep(shutdownGrace)
	}
}

// proxyConfig is what `up` and `run --phone` need to serve.
type proxyConfig struct {
	addr       string
	timeout    time.Duration
	rulesDir   string
	phone      bool   // use the persisted ntfy topic (created if missing)
	ntfyTopic  string // explicit topic; overrides the persisted one
	ntfyServer string
	terminal   bool      // approvals typed into this process's stdin
	logTo      io.Writer // where proxy diagnostics go
	allowFile  string    // pre-approved operations (default: a trusted ./.twokey-allow.yaml)
	observe    bool      // log and audit would-be holds but forward everything
	noDesktop  bool      // no native desktop notification on holds
}

// observeChannel is the banner line for observe mode.
const observeChannel = "OBSERVE MODE — nothing is held; would-be holds are logged and audited as by=observe (NOT PROTECTED)"

// defaultAllowFile is picked up from the current (project) directory.
const defaultAllowFile = ".twokey-allow.yaml"

type runningProxy struct {
	addr    string
	summary string
	done    chan error
}

// startProxy starts serving in the background; it stops when ctx ends.
func startProxy(ctx context.Context, c proxyConfig) (*runningProxy, error) {
	if err := requireLoopback(c.addr); err != nil {
		return nil, err
	}
	if err := validateTimeout(c.timeout); err != nil {
		return nil, err
	}
	engine, err := loadEngine(c.rulesDir)
	if err != nil {
		return nil, err
	}
	authority, _, err := loadAuthority(engine)
	if err != nil {
		return nil, err
	}
	logger := log.New(c.logTo, "twokey: ", log.LstdFlags)
	allow, err := loadProjectAllow(authority.Dir(), c.allowFile)
	if err != nil {
		return nil, err
	}
	if allow.warning != "" {
		logger.Print(allow.warning)
	}
	if _, err := authority.EnsureBundle(ctx); err != nil {
		logger.Printf("warning: could not build CA bundle (%v); Python/curl may reject intercepted hosts", err)
	}
	auditPath := filepath.Join(authority.Dir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		return nil, err
	}

	broker, channels, err := setupApprovals(ctx, c, authority.Dir(), logger)
	if err != nil {
		auditLog.Close()
		return nil, err
	}

	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		auditLog.Close()
		return nil, fmt.Errorf("listen on %s (is twokey already running?): %w", c.addr, err)
	}
	srv := &http.Server{
		Handler: proxy.New(proxy.Options{
			Engine: engine, CA: authority, Broker: broker, Audit: auditLog, Version: version, Logf: logger.Printf,
			Allow: allow.allows,
		}),
		ReadHeaderTimeout: 30 * time.Second,
		// Idle keep-alive connections from agents are closed; hijacked
		// CONNECT tunnels have their own idle timeout in internal/proxy and
		// end with the process on shutdown.
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20, // same cap as intercepted request heads
		ErrorLog:       logger,
	}
	p := &runningProxy{addr: ln.Addr().String(), done: make(chan error, 1)}
	go func() {
		err := srv.Serve(ln)
		auditLog.Close()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		p.done <- err
	}()
	go func() {
		<-ctx.Done()
		denyAndDrain(broker)
		_ = srv.Close() // Serve returns and the audit log is closed after this
	}()

	providers := map[string]bool{}
	rules := engine.Rules()
	for _, r := range rules {
		providers[r.Provider()] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  rules    %d destructive operations across %d providers (only those hosts are inspected)\n", len(rules), len(providers))
	label := "approve"
	if c.observe {
		label = "mode"
	}
	for _, ch := range channels {
		fmt.Fprintf(&b, "  %-8s %s\n", label, ch)
	}
	if len(allow.allows) > 0 {
		fmt.Fprintf(&b, "  allow    %d pre-approved operation(s) from %s\n", len(allow.allows), approval.Clean(allow.path))
	}
	if allow.warning != "" {
		fmt.Fprintf(&b, "  allow    %s\n", approval.Clean(allow.warning))
	}
	if !c.observe {
		fmt.Fprintf(&b, "  timeout  unanswered holds are denied after %s\n", c.timeout)
	}
	fmt.Fprintf(&b, "  audit    %s\n", auditPath)
	p.summary = b.String()
	return p, nil
}

// setupApprovals builds the broker and its approval channels (terminal
// and/or phone), shared by the HTTPS proxy and the Postgres guard.
func setupApprovals(ctx context.Context, c proxyConfig, home string, logger *log.Logger) (*approval.Broker, []string, error) {
	broker := approval.NewBroker(c.timeout)
	if c.observe {
		out := c.logTo
		if out == nil {
			out = os.Stdout
		}
		broker.SetObserve(true)
		broker.AddNotifier(approval.NewObserveLog(out))
		return broker, []string{observeChannel}, nil
	}
	var channels []string
	if c.terminal {
		term := approval.NewTerminal(broker, os.Stdout)
		broker.AddNotifier(term)
		go term.Run(os.Stdin)
		channels = append(channels, `this window — type "approve <id> <resource>" or "deny <id>"`)
	}
	topic := c.ntfyTopic
	if topic == "" && c.phone {
		var err error
		if topic, err = phoneTopic(home, false); err != nil {
			return nil, nil, err
		}
	}
	if topic != "" {
		// Refuse before anything is sent: over http, or with a guessable
		// topic, anyone could read the approval nonces and approve.
		if err := approval.ValidateNtfy(c.ntfyServer, topic); err != nil {
			return nil, nil, err
		}
		n := approval.NewNtfy(c.ntfyServer, topic, broker)
		n.SetLogf(logger.Printf)
		broker.AddNotifier(n)
		go n.Listen(ctx)
		// The banner may land in the agent's console (run --phone): show
		// only the end of the topic; `twokey phone` prints the whole one.
		channels = append(channels, fmt.Sprintf("phone — ntfy topic %s on %s (see `twokey phone`)",
			approval.RedactTopic(topic), strings.TrimRight(c.ntfyServer, "/")))
	}
	if len(channels) == 0 {
		return nil, nil, errors.New("no approval channel: use the terminal or a phone (--phone, see `twokey phone`)")
	}
	if !c.noDesktop {
		// Only a heads-up: approving still needs the terminal or the phone.
		broker.AddNotifier(approval.NewDesktop(logger.Printf))
	}
	return broker, channels, nil
}

// phoneTopic returns the persisted ntfy topic, creating it on first use.
// It lives in a 0600 file instead of argv or the environment, where the
// agent could read it and approve its own requests. The file is written
// atomically (temp file, then link or rename), so a crash never leaves a
// half-written topic; an empty file (from older versions) is regenerated.
func phoneTopic(dir string, rotate bool) (string, error) {
	path := filepath.Join(dir, phoneTopicFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	const attempts = 3
	for i := 0; i < attempts; i++ {
		replace := rotate
		if !rotate {
			data, err := os.ReadFile(path)
			switch {
			case errors.Is(err, os.ErrNotExist):
			case err != nil:
				return "", err
			case strings.TrimSpace(string(data)) == "":
				replace = true // empty: nothing anyone subscribed to
			default:
				t := strings.TrimSpace(string(data))
				if err := approval.ValidateNtfy("https://ntfy.sh", t); err != nil {
					return "", fmt.Errorf("%s is corrupt (%v); run `twokey phone --rotate` and re-subscribe on your phone", path, err)
				}
				// Topics from older versions kept the folder's ACL on Windows.
				_ = ca.RestrictToUser(path)
				return t, nil
			}
		}
		topic := "twokey-" + randomHex(12)
		won, err := placeTopic(dir, path, topic, replace)
		if err != nil {
			return "", err
		}
		if won {
			return topic, nil
		}
		// Another process created it first: read theirs.
	}
	return "", fmt.Errorf("could not create %s; run `twokey phone --rotate`", path)
}

// placeTopic writes topic to a private temp file, then moves it into place:
// replacing path when replace is set, else only if path does not exist yet
// (a hard link fails if it does, so concurrent first runs agree on one).
func placeTopic(dir, path, topic string, replace bool) (bool, error) {
	tmp, err := os.CreateTemp(dir, phoneTopicFile+".*.tmp") // created 0600
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, werr := tmp.WriteString(topic + "\n")
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return false, werr
	}
	// Anyone who can read the topic can approve; Windows ignores 0600.
	if err := ca.RestrictToUser(name); err != nil {
		return false, fmt.Errorf("restrict %s: %w", name, err)
	}
	if !replace {
		err := os.Link(name, path)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		// Filesystems without hard links: fall through to a rename.
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	return true, nil
}

func cmdPhone(args []string) error {
	fs := flag.NewFlagSet("phone", flag.ContinueOnError)
	rotate := fs.Bool("rotate", false, "generate a new topic (re-subscribe on your phone)")
	server := fs.String("ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	topic, err := phoneTopic(home, *rotate)
	if err != nil {
		return err
	}
	err = approval.ValidateNtfy(*server, topic)
	if err != nil {
		return err
	}
	srv := strings.TrimRight(*server, "/")
	fmt.Printf(`Phone approvals via ntfy (free, no account):
  1. Install the ntfy app (iOS / Android) and subscribe to:
       topic   %s
       server  %s        (or open %s/%s in a browser)
  2. Start twokey with phone approvals:
       twokey up --phone                 (terminal + phone)
       twokey run --phone -- claude      (one terminal, phone only)

Keep the topic private: anyone who knows it can approve. It is stored in
%s and never passed to the agent.
`, topic, srv, srv, topic, filepath.Join(home, phoneTopicFile))
	return nil
}

// setupFailure reports a twokey (not agent) failure in `run`.
func setupFailure(err error) error {
	fmt.Fprintln(os.Stderr, "twokey:", err)
	return exitCode(setupExitCode)
}
