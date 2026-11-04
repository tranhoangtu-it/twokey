package main

import (
	"context"
	"crypto/tls"
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
	"github.com/tranhoangtu-it/twokey/internal/myguard"
	"github.com/tranhoangtu-it/twokey/internal/pgguard"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// dbGuard describes one database flavour for `twokey pg` / `twokey mysql`.
type dbGuard struct {
	cmd, name, defaultListen, example string
	tls                               bool // supports --upstream-tls
}

var (
	postgresGuard = dbGuard{"pg", "Postgres", "127.0.0.1:6543", "DATABASE_URL=postgres://USER:PASS@%s/DB?sslmode=disable", true}
	mysqlGuard    = dbGuard{"mysql", "MySQL", "127.0.0.1:3307", "DATABASE_URL=mysql://USER:PASS@%s/DB   (or: mysql -h 127.0.0.1 -P PORT)", true}
)

func cmdPG(args []string) error    { return cmdDBGuard(postgresGuard, args) }
func cmdMySQL(args []string) error { return cmdDBGuard(mysqlGuard, args) }

// dbServer is what both guards provide.
type dbServer interface{ Serve(net.Listener) error }

// cmdDBGuard runs a database guard: point the agent's connection string at
// the local port instead of the real database.
func cmdDBGuard(g dbGuard, args []string) error {
	fs := flag.NewFlagSet(g.cmd, flag.ContinueOnError)
	upstream := fs.String("upstream", "", "real "+g.name+" host:port (required)")
	listen := fs.String("listen", g.defaultListen, "local address the agent connects to (loopback only)")
	upstreamTLS := fs.Bool("upstream-tls", false, "use TLS to the upstream, verifying its certificate (managed databases usually need this)")
	skipVerify := fs.Bool("upstream-tls-skip-verify", false, "use TLS to the upstream without verifying its certificate (like sslmode=require)")
	timeout := fs.Duration("timeout", 2*time.Minute, "deny holds nobody answers within this time")
	phone := fs.Bool("phone", false, "also approve from your phone (see `twokey phone`)")
	ntfyTopic := fs.String("ntfy-topic", os.Getenv("TWOKEY_NTFY_TOPIC"), "explicit ntfy topic")
	ntfyServer := fs.String("ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	allowFile := fs.String("allow", "", "pre-approved operations file (default ./"+defaultAllowFile+" if present)")
	observe := fs.Bool("observe", false, "log and audit statements that would be held, but hold nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return fmt.Errorf("usage: twokey %s --upstream db.example.com:PORT [--listen %s]", g.cmd, g.defaultListen)
	}
	useTLS := *upstreamTLS || *skipVerify
	if useTLS && !g.tls {
		return errors.New("--upstream-tls is not supported for " + g.name)
	}
	upHost, _, err := net.SplitHostPort(*upstream)
	if err != nil {
		return fmt.Errorf("bad --upstream %q (want host:port): %w", *upstream, err)
	}
	var tlsConfig *tls.Config
	if useTLS {
		tlsConfig = &tls.Config{ServerName: upHost, MinVersion: tls.VersionTLS12, InsecureSkipVerify: *skipVerify} //nolint:gosec // explicit opt-in flag
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
		observe: *observe,
	}, home, logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	var srv dbServer
	if g.cmd == mysqlGuard.cmd {
		srv = myguard.New(myguard.Options{
			Upstream: *upstream, Broker: broker, Audit: auditLog, Allow: allows, Logf: logger.Printf,
			UpstreamTLS: useTLS, TLSConfig: tlsConfig,
		})
	} else {
		srv = pgguard.New(pgguard.Options{
			Upstream: *upstream, UpstreamTLS: useTLS, TLSConfig: tlsConfig, Broker: broker, Audit: auditLog,
			Allow: allows, Logf: logger.Printf,
		})
	}

	fmt.Printf("twokey %s — %s guard on %s → %s\n", version, g.name, ln.Addr(), *upstream)
	fmt.Println("  holds    DROP …, TRUNCATE, DELETE/UPDATE without WHERE, ALTER TABLE … DROP")
	for _, ch := range channels {
		fmt.Printf("  approve  %s\n", ch)
	}
	fmt.Printf("  timeout  unanswered holds are denied after %s\n  audit    %s\n\n", *timeout, auditPath)
	fmt.Printf("Point the agent at it, e.g.  "+g.example+"\n", ln.Addr())

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
