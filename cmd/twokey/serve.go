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

	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/proxy"
	"github.com/tranhoangtu-it/twokey/internal/runenv"
)

// ---- up --------------------------------------------------------------------------

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "listen address (loopback only)")
	timeout := fs.Duration("timeout", 2*time.Minute, "deny holds nobody answers within this time")
	rulesDir := fs.String("rules", "", "extra rule pack directory")
	phone := fs.Bool("phone", false, "also approve from your phone (see `twokey phone`)")
	ntfyTopic := fs.String("ntfy-topic", os.Getenv("TWOKEY_NTFY_TOPIC"), "explicit ntfy topic (default: the one from `twokey phone`)")
	ntfyServer := fs.String("ntfy-server", envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"), "ntfy server URL")
	allow := fs.String("allow", "", "pre-approved operations file (default ./"+defaultAllowFile+" if present)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p, err := startProxy(ctx, proxyConfig{
		addr: *addr, timeout: *timeout, rulesDir: *rulesDir, phone: *phone,
		ntfyTopic: *ntfyTopic, ntfyServer: *ntfyServer, terminal: true, logTo: os.Stderr, allowFile: *allow,
	})
	if err != nil {
		return err
	}
	fmt.Printf("twokey %s — proxy on http://%s\n%s\nNow, in another terminal:  twokey run -- claude     (or codex, cursor-agent, aider, ...)\n",
		version, p.addr, p.summary)
	return <-p.done
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
	a, _, err := loadAuthority(nil)
	if err != nil {
		return nil, err
	}
	bundle := a.BundlePath()
	if _, err := os.Stat(bundle); err != nil {
		if bundle, err = a.EnsureBundle(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: no CA bundle (%v); Python/curl may reject intercepted hosts\n", err)
			bundle = ""
		}
	}
	if old := runenv.Lookup(os.Environ(), "NO_PROXY"); old != "" {
		fmt.Fprintf(os.Stderr, "twokey: ignoring NO_PROXY=%q so watched hosts cannot bypass the proxy\n", old)
	}
	cfg := runenv.Config{ProxyURL: "http://" + addr, CACert: a.CertPath(), Bundle: bundle}
	vars := runenv.Vars(cfg)
	trustStore := ""
	if bundle != "" {
		if ts, err := a.WriteJavaTrustStore(bundle); err == nil {
			trustStore = ts
		} else {
			fmt.Fprintf(os.Stderr, "warning: Java truststore not written (%v); JVM tools may reject intercepted hosts\n", err)
		}
	}
	vars = append(vars, runenv.KV{Key: "JAVA_TOOL_OPTIONS", Value: runenv.JavaToolOptions(
		addr, trustStore, ca.JavaTrustStorePassword, os.Getenv("JAVA_TOOL_OPTIONS"))})
	if runtime.GOOS == "windows" {
		if dir, err := curlHome(a.Dir()); err == nil {
			vars = append(vars, runenv.KV{Key: "CURL_HOME", Value: dir})
		} else {
			fmt.Fprintf(os.Stderr, "warning: curl config not written (%v); curl may reject intercepted hosts\n", err)
		}
	}
	return vars, nil
}

// curlHome writes a curl config for the agent on Windows. Schannel curl
// fails with CRYPT_E_NO_REVOCATION_CHECK on certificates from a local CA
// (they have no CRL/OCSP endpoint); ssl-revoke-best-effort skips the check
// only when it cannot be performed. The user's own curlrc is preserved.
func curlHome(twokeyDir string) (string, error) {
	dir := filepath.Join(twokeyDir, "curl")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var user []byte
	for _, p := range userCurlrcCandidates() {
		if data, err := os.ReadFile(p); err == nil {
			user = data
			break
		}
	}
	content := strings.TrimRight(string(user), "\r\n")
	if content != "" {
		content += "\n"
	}
	content += "# added by twokey: local-CA certificates have no revocation endpoint\nssl-revoke-best-effort\n"
	if err := os.WriteFile(filepath.Join(dir, ".curlrc"), []byte(content), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// userCurlrcCandidates mirrors curl's Windows lookup order.
func userCurlrcCandidates() []string {
	var dirs []string
	for _, env := range []string{"CURL_HOME", "USERPROFILE", "APPDATA"} {
		if d := os.Getenv(env); d != "" {
			dirs = append(dirs, d)
		}
	}
	var out []string
	for _, d := range dirs {
		out = append(out, filepath.Join(d, ".curlrc"), filepath.Join(d, "_curlrc"))
	}
	return out
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of `twokey up`")
	phone := fs.Bool("phone", false, "one-terminal mode: start the proxy in-process, approve on your phone")
	timeout := fs.Duration("timeout", 2*time.Minute, "with --phone: deny holds nobody answers within this time")
	rulesDir := fs.String("rules", "", "with --phone: extra rule pack directory")
	allow := fs.String("allow", "", "with --phone: pre-approved operations file (default ./"+defaultAllowFile+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("usage: twokey run [--addr A | --phone] -- <agent> [args...]")
	}

	proxyAddr := *addr
	if *phone {
		home, err := homeDir()
		if err != nil {
			return setupFailure(err)
		}
		if err := os.MkdirAll(home, 0o700); err != nil { // first run: no ~/.twokey yet
			return setupFailure(err)
		}
		logFile, err := os.OpenFile(filepath.Join(home, "twokey.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return setupFailure(err)
		}
		defer logFile.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, err := startProxy(ctx, proxyConfig{
			addr: "127.0.0.1:0", timeout: *timeout, rulesDir: *rulesDir, phone: true,
			ntfyTopic: os.Getenv("TWOKEY_NTFY_TOPIC"), ntfyServer: envOr("TWOKEY_NTFY_SERVER", "https://ntfy.sh"),
			logTo:     logFile, // keep diagnostics out of the agent's TUI
			allowFile: *allow,
		})
		if err != nil {
			return setupFailure(err)
		}
		proxyAddr = p.addr
		fmt.Fprintf(os.Stderr, "twokey %s (one-terminal mode, log: %s)\n%s", version, logFile.Name(), p.summary)
	} else if err := checkHealth(proxyAddr); err != nil {
		return setupFailure(fmt.Errorf("%v\nStart the proxy first in another terminal:  twokey up\n"+
			"or use one terminal with phone approvals:   twokey run --phone -- %s", err, argv[0]))
	}

	vars, err := agentEnv(proxyAddr)
	if err != nil {
		return setupFailure(err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = runenv.Apply(os.Environ(), vars)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "twokey: %s is routed through http://%s — destructive cloud API calls need your approval\n", argv[0], proxyAddr)

	// Ctrl+C belongs to the agent; twokey just waits for it to exit.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if code := ee.ExitCode(); code > 0 {
				return exitCode(code)
			}
			return exitCode(1) // killed by a signal: ExitCode() is -1
		}
		return setupFailure(fmt.Errorf("start %s: %w", argv[0], err))
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
		return fmt.Errorf("nothing is listening on %s", addr)
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
			"on Windows (Schannel curl) run `twokey ca trust` once; twokey sets CURL_HOME for the revocation check"},
		{"python", pythons, []string{"-c", "import urllib.request as u;r=u.urlopen('" + probeURL + "',timeout=20);print('x-twokey:',r.headers.get('X-Twokey'))"},
			"Python must honor SSL_CERT_FILE / REQUESTS_CA_BUNDLE"},
		{"node", []string{"node"}, []string{"-e", "fetch('" + probeURL + "').then(r=>console.log('x-twokey:',r.headers.get('x-twokey'))).catch(e=>{console.log('error:',(e.cause||e).message);process.exit(1)})"},
			"needs Node >= 22.21 or >= 24.5 for NODE_USE_ENV_PROXY"},
		{"go (gh, terraform, flyctl)", []string{self}, []string{probeCommand},
			"Go uses the OS trust store on Windows/macOS: run `twokey ca trust`"},
	}
	failed := 0
	if javaProbe, err := writeJavaProbe(); err == nil {
		defer os.RemoveAll(filepath.Dir(javaProbe))
		probes = append(probes, probe{"java (JVM SDKs)", []string{"java"}, []string{javaProbe},
			"needs Java 11+; twokey sets JAVA_TOOL_OPTIONS (proxy + truststore)"})
	}
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

// javaProbeSource uses HttpURLConnection, which honors the proxy system
// properties set through JAVA_TOOL_OPTIONS.
const javaProbeSource = `public class Probe {
  public static void main(String[] a) throws Exception {
    var c = (java.net.HttpURLConnection) new java.net.URL("` + probeURL + `").openConnection();
    c.setConnectTimeout(20000); c.setReadTimeout(20000);
    System.out.println("x-twokey: " + c.getHeaderField("X-Twokey"));
  }
}
`

// writeJavaProbe writes the probe to a fresh temp dir (single-file source
// launch, Java 11+).
func writeJavaProbe() (string, error) {
	dir, err := os.MkdirTemp("", "twokey-doctor-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "Probe.java")
	if err := os.WriteFile(path, []byte(javaProbeSource), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
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
