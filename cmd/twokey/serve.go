package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
	"github.com/tranhoangtu-it/twokey/internal/proxy"
	"github.com/tranhoangtu-it/twokey/internal/runenv"
)

// ---- up --------------------------------------------------------------------------

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "listen address (loopback only)")
	timeout := fs.Duration("timeout", 2*time.Minute, "deny holds nobody answers within this time")
	rulesDir := fs.String("rules", "", "extra rule pack directory")
	ntfyTopic := fs.String("ntfy-topic", os.Getenv("TWOKEY_NTFY_TOPIC"), "ntfy topic for phone approvals (see `twokey ntfy-topic`)")
	ntfyServer := fs.String("ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireLoopback(*addr); err != nil {
		return err
	}

	engine, err := loadEngine(*rulesDir)
	if err != nil {
		return err
	}
	authority, _, err := loadAuthority()
	if err != nil {
		return err
	}
	if _, err := authority.EnsureBundle(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not build CA bundle (%v); Python/curl may reject intercepted hosts\n", err)
	}
	auditLog, err := audit.Open(filepath.Join(authority.Dir(), "audit.jsonl"))
	if err != nil {
		return err
	}
	defer auditLog.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	broker := approval.NewBroker(*timeout)
	term := approval.NewTerminal(broker, os.Stdout)
	broker.AddNotifier(term)
	phone := "off (add --ntfy-topic to approve from your phone)"
	if *ntfyTopic != "" {
		if len(*ntfyTopic) < 16 {
			fmt.Fprintln(os.Stderr, "warning: short ntfy topics are guessable; use `twokey ntfy-topic`")
		}
		n := approval.NewNtfy(*ntfyServer, *ntfyTopic, broker)
		broker.AddNotifier(n)
		go n.Listen(ctx)
		phone = fmt.Sprintf("subscribe to %q on %s in the ntfy app", *ntfyTopic, *ntfyServer)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen on %s (is twokey already running?): %w", *addr, err)
	}
	srv := &http.Server{
		Handler: proxy.New(proxy.Options{
			Engine: engine, CA: authority, Broker: broker, Audit: auditLog, Version: version,
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	ruleList := engine.Rules()
	providers := map[string]bool{}
	for _, r := range ruleList {
		providers[r.Provider()] = true
	}
	fmt.Printf(`twokey %s — proxy on http://%s
  rules    %d destructive operations across %d providers (only those hosts are inspected)
  approve  here: type "approve <id> <resource>" or "deny <id>"
  phone    %s
  timeout  unanswered holds are denied after %s
  audit    %s

Now, in another terminal:  twokey run -- claude     (or codex, cursor-agent, aider, ...)
`, version, *addr, len(ruleList), len(providers), phone, *timeout, filepath.Join(authority.Dir(), "audit.jsonl"))

	go term.Run(os.Stdin)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requireLoopback refuses to become an open proxy on the network.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad --addr %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to listen on non-loopback address %q", addr)
}

// ---- run / env -------------------------------------------------------------------

func agentEnv(addr string) ([]runenv.KV, error) {
	a, _, err := loadAuthority()
	if err != nil {
		return nil, err
	}
	bundle := a.BundlePath()
	if _, err := os.Stat(bundle); err != nil {
		fmt.Fprintln(os.Stderr, "warning: no CA bundle yet; run `twokey ca init` (Python/curl trust)")
		bundle = ""
	}
	cfg := runenv.Config{ProxyURL: "http://" + addr, CACert: a.CertPath(), Bundle: bundle}
	return runenv.Vars(cfg, runenv.Lookup(os.Environ(), "NO_PROXY")), nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of `twokey up`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("usage: twokey run [--addr A] -- <agent> [args...]")
	}
	if err := checkHealth(*addr); err != nil {
		return fmt.Errorf("twokey proxy is not reachable at %s (%v)\nstart it first in another terminal:  twokey up", *addr, err)
	}
	vars, err := agentEnv(*addr)
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = runenv.Apply(os.Environ(), vars)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "twokey: %s is routed through http://%s — destructive cloud API calls need your approval\n", argv[0], *addr)

	// Ctrl+C belongs to the agent; twokey just waits for it to exit.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
}

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of `twokey up`")
	defShell := "sh"
	if runtime.GOOS == "windows" {
		defShell = "powershell"
	}
	shell := fs.String("shell", defShell, "sh | powershell")
	if err := fs.Parse(args); err != nil {
		return err
	}
	vars, err := agentEnv(*addr)
	if err != nil {
		return err
	}
	for _, kv := range vars {
		switch *shell {
		case "powershell", "pwsh":
			fmt.Printf("$env:%s = '%s'\n", kv.Key, strings.ReplaceAll(kv.Value, "'", "''"))
		default:
			fmt.Printf("export %s='%s'\n", kv.Key, strings.ReplaceAll(kv.Value, "'", `'\''`))
		}
	}
	return nil
}

func checkHealth(addr string) error {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://" + addr + proxy.HealthPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"twokey"`) {
		return fmt.Errorf("something else is listening there (%s)", resp.Status)
	}
	return nil
}

// ---- doctor ----------------------------------------------------------------------

// probeURL is a harmless GET on a watched host: if the response carries
// X-Twokey, the runtime both used the proxy and trusted the twokey CA.
const probeURL = "https://api.github.com/zen"

// probeCommand is the hidden subcommand doctor runs as a child process to
// test Go's own HTTP stack (the one gh, terraform and flyctl use).
const probeCommand = "__probe-go"

type probe struct {
	name string
	bins []string // first one found on PATH is used
	args []string
	hint string
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of `twokey up`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("twokey doctor")
	if err := checkHealth(*addr); err != nil {
		fmt.Printf("  ✗ proxy        not reachable at %s: %v\n    → start it: twokey up\n", *addr, err)
		return errors.New("proxy not running")
	}
	fmt.Printf("  ✓ proxy        listening on %s\n", *addr)
	vars, err := agentEnv(*addr)
	if err != nil {
		return err
	}
	env := runenv.Apply(os.Environ(), vars)

	self, err := os.Executable()
	if err != nil {
		return err
	}
	pythons := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		pythons = []string{"python", "py"} // python3.exe is often a Store stub
	}
	probes := []probe{
		{"curl", []string{"curl"}, []string{"-sS", "-o", os.DevNull, "-D", "-", probeURL},
			"curl must honor CURL_CA_BUNDLE; on Windows (Schannel) run `twokey ca trust`"},
		{"python", pythons, []string{"-c", "import urllib.request as u;r=u.urlopen('" + probeURL + "',timeout=20);print('x-twokey:',r.headers.get('X-Twokey'))"},
			"Python must honor SSL_CERT_FILE / REQUESTS_CA_BUNDLE"},
		{"node", []string{"node"}, []string{"-e", "fetch('" + probeURL + "').then(r=>console.log('x-twokey:',r.headers.get('x-twokey'))).catch(e=>{console.log('error:',(e.cause||e).message);process.exit(1)})"},
			"needs Node >= 22.21 or >= 24.5 for NODE_USE_ENV_PROXY"},
		{"go (gh, terraform, flyctl)", []string{self}, []string{probeCommand},
			"Go uses the OS trust store on Windows/macOS: run `twokey ca trust`"},
	}
	failed := 0
	for _, p := range probes {
		ok, detail := runProbe(p, env)
		switch {
		case detail == "not installed":
			fmt.Printf("  – %-26s not installed (skipped)\n", p.name)
		case ok:
			fmt.Printf("  ✓ %-26s routed through twokey and trusts its CA\n", p.name)
		default:
			failed++
			fmt.Printf("  ✗ %-26s %s\n    → %s\n", p.name, detail, p.hint)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d runtime(s) would bypass or reject twokey", failed)
	}
	fmt.Println("\nAll set. Try it: twokey replay pocketos --live")
	return nil
}

func runProbe(p probe, env []string) (bool, string) {
	bin := ""
	for _, b := range p.bins {
		if path, err := exec.LookPath(b); err == nil {
			bin = path
			break
		}
	}
	if bin == "" {
		return false, "not installed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, p.args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if strings.Contains(strings.ToLower(string(out)), "x-twokey: inspected") {
		return true, ""
	}
	return false, lastLine(string(out), err)
}

// lastLine picks the most informative line of a failed probe: the first
// line that looks like an error, else the last line.
func lastLine(out string, err error) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	for _, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "error") || strings.HasPrefix(low, "curl:") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" && err != nil {
		line = err.Error()
	}
	if line == "" {
		line = "request did not go through twokey"
	}
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
}

// cmdProbe runs inside the doctor's child process with the agent env.
func cmdProbe([]string) error {
	client := &http.Client{Timeout: 20 * time.Second} // default transport: env proxy + OS roots
	resp, err := client.Get(probeURL)
	if err != nil {
		fmt.Println("error:", err)
		return exitCode(1)
	}
	defer resp.Body.Close()
	fmt.Println("x-twokey:", resp.Header.Get("X-Twokey"))
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
