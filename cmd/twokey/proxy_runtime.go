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
	"github.com/tranhoangtu-it/twokey/internal/proxy"
)

// setupExitCode distinguishes twokey's own failures in `run` from the
// agent's exit status (like docker run's 125).
const setupExitCode = 125

const phoneTopicFile = "ntfy-topic"

// shutdownGrace gives denied holds time to be written before exit.
const shutdownGrace = 500 * time.Millisecond

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
}

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
	engine, err := loadEngine(c.rulesDir)
	if err != nil {
		return nil, err
	}
	authority, _, err := loadAuthority(engine)
	if err != nil {
		return nil, err
	}
	logger := log.New(c.logTo, "twokey: ", log.LstdFlags)
	if _, err := authority.EnsureBundle(ctx); err != nil {
		logger.Printf("warning: could not build CA bundle (%v); Python/curl may reject intercepted hosts", err)
	}
	auditPath := filepath.Join(authority.Dir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		return nil, err
	}

	broker := approval.NewBroker(c.timeout)
	var channels []string
	if c.terminal {
		term := approval.NewTerminal(broker, os.Stdout)
		broker.AddNotifier(term)
		go term.Run(os.Stdin)
		channels = append(channels, `this window — type "approve <id> <resource>" or "deny <id>"`)
	}
	topic := c.ntfyTopic
	if topic == "" && c.phone {
		if topic, err = phoneTopic(authority.Dir(), false); err != nil {
			auditLog.Close()
			return nil, err
		}
	}
	if topic != "" {
		if len(topic) < 16 {
			logger.Printf("warning: short ntfy topics are guessable; use `twokey phone`")
		}
		n := approval.NewNtfy(c.ntfyServer, topic, broker)
		n.SetLogf(logger.Printf)
		broker.AddNotifier(n)
		go n.Listen(ctx)
		channels = append(channels, fmt.Sprintf("phone — ntfy app subscribed to %s/%s", strings.TrimRight(c.ntfyServer, "/"), topic))
	}
	if len(channels) == 0 {
		auditLog.Close()
		return nil, errors.New("no approval channel: use the terminal (twokey up) or a phone (--phone, see `twokey phone`)")
	}

	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		auditLog.Close()
		return nil, fmt.Errorf("listen on %s (is twokey already running?): %w", c.addr, err)
	}
	srv := &http.Server{
		Handler: proxy.New(proxy.Options{
			Engine: engine, CA: authority, Broker: broker, Audit: auditLog, Version: version, Logf: logger.Printf,
		}),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
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
		if broker.DenyAll("twokey is shutting down") > 0 {
			time.Sleep(shutdownGrace) // let the 403s reach the agents
		}
		_ = srv.Close()
	}()

	providers := map[string]bool{}
	rules := engine.Rules()
	for _, r := range rules {
		providers[r.Provider()] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  rules    %d destructive operations across %d providers (only those hosts are inspected)\n", len(rules), len(providers))
	for _, ch := range channels {
		fmt.Fprintf(&b, "  approve  %s\n", ch)
	}
	fmt.Fprintf(&b, "  timeout  unanswered holds are denied after %s\n  audit    %s\n", c.timeout, auditPath)
	p.summary = b.String()
	return p, nil
}

// phoneTopic returns the persisted ntfy topic, creating it on first use.
// It lives in a 0600 file instead of argv or the environment, where the
// agent could read it and approve its own requests.
func phoneTopic(dir string, rotate bool) (string, error) {
	path := filepath.Join(dir, phoneTopicFile)
	if !rotate {
		if data, err := os.ReadFile(path); err == nil {
			if t := strings.TrimSpace(string(data)); t != "" {
				return t, nil
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	topic := "twokey-" + randomHex(12)
	if err := os.WriteFile(path, []byte(topic+"\n"), 0o600); err != nil {
		return "", err
	}
	return topic, nil
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
