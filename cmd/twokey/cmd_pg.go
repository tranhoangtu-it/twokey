package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/pgguard"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// cmdPG runs the Postgres guard: point the agent's DATABASE_URL at the
// local port instead of the real database.
func cmdPG(args []string) error {
	fs := flag.NewFlagSet("pg", flag.ContinueOnError)
	upstream := fs.String("upstream", "", "real Postgres host:port (required)")
	listen := fs.String("listen", "127.0.0.1:6543", "local address the agent connects to (loopback only)")
	upstreamTLS := fs.Bool("upstream-tls", false, "use TLS to the upstream (managed Postgres usually needs this)")
	timeout := fs.Duration("timeout", 2*time.Minute, "deny holds nobody answers within this time")
	phone := fs.Bool("phone", false, "also approve from your phone (see `twokey phone`)")
	ntfyTopic := fs.String("ntfy-topic", os.Getenv("TWOKEY_NTFY_TOPIC"), "explicit ntfy topic")
	ntfyServer := fs.String("ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	allowFile := fs.String("allow", "", "pre-approved operations file (default ./"+defaultAllowFile+" if present)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return errors.New("usage: twokey pg --upstream db.example.com:5432 [--upstream-tls] [--listen 127.0.0.1:6543]")
	}
	if _, _, err := net.SplitHostPort(*upstream); err != nil {
		return fmt.Errorf("bad --upstream %q (want host:port): %w", *upstream, err)
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	allowPath := *allowFile
	if allowPath == "" {
		allowPath = defaultAllowFile
	}
	allows, err := rules.LoadAllow(allowPath)
	if err != nil {
		return fmt.Errorf("allow rules %s: %w", allowPath, err)
	}
	auditPath := filepath.Join(home, "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(os.Stderr, "twokey: ", log.LstdFlags)
	broker, channels, err := setupApprovals(ctx, proxyConfig{
		timeout: *timeout, phone: *phone, ntfyTopic: *ntfyTopic, ntfyServer: *ntfyServer, terminal: true,
	}, home, logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	srv := pgguard.New(pgguard.Options{
		Upstream: *upstream, UpstreamTLS: *upstreamTLS, Broker: broker, Audit: auditLog,
		Allow: allows, Logf: logger.Printf,
	})

	fmt.Printf("twokey %s — Postgres guard on %s → %s\n", version, ln.Addr(), *upstream)
	fmt.Println("  holds    DROP …, TRUNCATE, DELETE/UPDATE without WHERE, ALTER TABLE … DROP")
	for _, ch := range channels {
		fmt.Printf("  approve  %s\n", ch)
	}
	fmt.Printf("  timeout  unanswered holds are denied after %s\n  audit    %s\n\n", *timeout, auditPath)
	fmt.Printf("Point the agent at it, e.g.  DATABASE_URL=postgres://USER:PASS@%s/DB?sslmode=disable\n", ln.Addr())

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	if broker.DenyAll("twokey is shutting down") > 0 {
		time.Sleep(shutdownGrace)
	}
	return ln.Close()
}
