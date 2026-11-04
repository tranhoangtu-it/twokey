// Command twokey is a two-person rule for AI agents: a local proxy that holds
// destructive cloud API calls until a human approves them out of band.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// version is set at release time (-ldflags "-X main.version=..."); for
// `go install …@vX.Y.Z` it is read from the module build info instead.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

func printUsage() { fmt.Print(strings.Replace(usage, "VERSION", version, 1)) }

const defaultAddr = "127.0.0.1:7171"

// errHeld is returned by `explain` when the request would be held (exit 2).
var errHeld = errors.New("held")

const usage = `twokey VERSION — make your AI agent ask a human before it deletes prod

Usage:
  twokey replay pocketos                               see what twokey does, in 5 seconds
  twokey setup [--yes] [--trust]                       one-time setup: CA, phone, runtime check
  twokey up [--phone] [--timeout 2m] [--observe]       start the proxy + approval prompt
  twokey run [--phone] -- <agent> [args...]            run an agent routed through twokey
  twokey run --observe -- <agent> [args...]            trial: log what would be held, hold nothing
  twokey phone [--rotate]                              set up approvals on your phone (ntfy)
  twokey pg --upstream HOST:5432 [--upstream-tls]      guard a Postgres database (DROP, TRUNCATE, …)
  twokey mysql --upstream HOST:3306                    guard a MySQL database
  twokey log [-n 20] [--denied] [--provider P] [--since 24h] [--json]  what was held and decided
  twokey env [--shell sh|powershell]                 print the variables 'run' sets
  twokey doctor [--addr A]                             check curl/python/node/go are covered
  twokey replay <scenario> [--live]                    replay a real-world incident
  twokey explain --method M --url U [-H k:v] [--data D] would this request be held?
  twokey rules [--rules DIR]                           list destructive-operation rules
  twokey rules test --rules DIR [--fixtures DIR]       check your rules against .http fixtures
  twokey ca init|path|trust|untrust|reset              manage the local CA
  twokey uninstall [--purge]                           remove OS trust + Docker objects (and ~/.twokey)
  twokey version

Typical use:
  two terminals:  1) twokey up --phone     2) twokey run -- claude
  one terminal:   twokey run --phone -- claude      (approve on your phone)

Exit codes: 2 = explain would hold; 125 = twokey itself failed in run;
otherwise run exits with the agent's status.
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		var exit exitCode
		switch {
		case errors.As(err, &exit):
			os.Exit(int(exit))
		case errors.Is(err, errHeld):
			os.Exit(2)
		case errors.Is(err, flag.ErrHelp):
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "twokey:", err)
		os.Exit(1)
	}
}

// exitCode propagates a child's exit status from `twokey run`.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func dispatch(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "up":
		return cmdUp(rest)
	case "run":
		return cmdRun(rest)
	case "env":
		return cmdEnv(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "replay":
		return cmdReplay(rest)
	case "explain":
		return cmdExplain(rest)
	case "rules":
		return cmdRules(rest)
	case "ca":
		return cmdCA(rest)
	case "uninstall":
		return cmdUninstall(rest)
	case "log":
		return cmdLog(rest)
	case "setup":
		return cmdSetup(rest)
	case "mysql":
		return cmdMySQL(rest)
	case "pg":
		return cmdPG(rest)
	case "phone":
		return cmdPhone(rest)
	case "version", "--version", "-v":
		fmt.Println("twokey", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	case probeCommand:
		return cmdProbe(rest)
	default:
		return fmt.Errorf("unknown command %q (see `twokey help`)", cmd)
	}
}

// homeDir holds the CA, bundle and audit log. TWOKEY_HOME overrides it.
func homeDir() (string, error) {
	if h := os.Getenv("TWOKEY_HOME"); h != "" {
		return h, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".twokey"), nil
}

// loadAuthority loads (or creates) the CA, name-constrained to the domains
// of engine's rules (builtin rules when engine is nil).
func loadAuthority(engine *rules.Engine) (*ca.Authority, bool, error) {
	home, err := homeDir()
	if err != nil {
		return nil, false, err
	}
	if engine == nil {
		if engine, err = loadEngine(""); err != nil {
			return nil, false, err
		}
	}
	a, created, err := ca.LoadOrCreate(home, engine.Domains()...)
	if errors.Is(err, ca.ErrConstraintsOutdated) {
		// New providers since this CA was made: rotate instead of failing.
		if rerr := ca.Rotate(home); rerr != nil {
			return nil, false, fmt.Errorf("%v (and rotating it failed: %w)", err, rerr)
		}
		fmt.Fprintln(os.Stderr, "twokey: rule packs now cover more domains, so a new local CA was created "+
			"(the old one is kept so `twokey ca untrust` can remove it). If you used `twokey ca trust`, run it again.")
		return ca.LoadOrCreate(home, engine.Domains()...)
	}
	if err == nil && !created {
		// CAs made before v0.5 on Windows inherit the folder ACL; tighten it.
		if herr := ca.HardenKey(home); herr != nil {
			fmt.Fprintln(os.Stderr, "twokey: warning: could not restrict CA key permissions:", herr)
		}
	}
	return a, created, err
}

// loadEngine combines builtin packs with optional user packs from dir.
func loadEngine(dir string) (*rules.Engine, error) {
	packs, err := rules.BuiltinPacks()
	if err != nil {
		return nil, fmt.Errorf("builtin rules: %w", err)
	}
	if dir != "" {
		extra, err := rules.LoadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("rules in %s: %w", dir, err)
		}
		packs = append(packs, extra...)
	}
	return rules.NewEngine(packs)
}

// ---- rules / explain / replay ------------------------------------------------

func cmdRules(args []string) error {
	if len(args) > 0 && args[0] == "test" {
		return cmdRulesTest(args[1:])
	}
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	dir := fs.String("rules", "", "extra rule pack directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	engine, err := loadEngine(*dir)
	if err != nil {
		return err
	}
	list := engine.Rules()
	sort.SliceStable(list, func(i, j int) bool { return list[i].Provider() < list[j].Provider() })
	providers := map[string]bool{}
	for _, r := range list {
		providers[r.Provider()] = true
		fmt.Printf("%-13s %-9s %-36s %s\n", r.Provider(), r.Severity, r.ID, describeMatcher(r))
	}
	fmt.Printf("\n%d rules across %d providers\n", len(list), len(providers))
	return nil
}

func describeMatcher(r rules.Rule) string {
	switch {
	case r.GraphQL != nil:
		return "graphql mutation " + strings.Join(r.GraphQL.Mutations, ", ")
	case r.AWS != nil:
		return "aws action " + strings.Join(r.AWS.Actions, ", ")
	default:
		return strings.TrimSpace(strings.Join(r.Methods, ",") + " " + r.Path)
	}
}

type headerFlags []string

func (h *headerFlags) String() string     { return strings.Join(*h, "; ") }
func (h *headerFlags) Set(v string) error { *h = append(*h, v); return nil }

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	method := fs.String("method", "GET", "HTTP method")
	rawURL := fs.String("url", "", "full request URL")
	data := fs.String("data", "", "request body, or @file")
	dir := fs.String("rules", "", "extra rule pack directory")
	var headers headerFlags
	fs.Var(&headers, "H", "header 'Name: value' (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rawURL == "" {
		return errors.New("--url is required")
	}
	body := []byte(*data)
	if strings.HasPrefix(*data, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(*data, "@"))
		if err != nil {
			return err
		}
		body = b
	}
	h := http.Header{}
	for _, kv := range headers {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return fmt.Errorf("bad header %q, want 'Name: value'", kv)
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	engine, err := loadEngine(*dir)
	if err != nil {
		return err
	}
	return explain(os.Stdout, engine, strings.ToUpper(*method), *rawURL, h, body)
}

func explain(w io.Writer, engine *rules.Engine, method, rawURL string, h http.Header, body []byte) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("bad --url %q", rawURL)
	}
	v := engine.Evaluate(rules.Request{Method: method, Host: u.Host, Path: u.Path, Query: u.RawQuery, Header: h, Body: body})
	fmt.Fprintf(w, "%s %s\n", method, u.Redacted())
	if !v.Hold() {
		if engine.HostWatched(u.Host) {
			fmt.Fprintln(w, "✓ would pass: inspected, no destructive rule matched")
		} else {
			fmt.Fprintln(w, "✓ would pass: host has no rules, traffic is tunneled untouched")
		}
		return nil
	}
	fmt.Fprintln(w, "⏸ WOULD BE HELD for human approval")
	for _, m := range v.Matches {
		res := m.Resource
		if res == "" {
			res = "(unknown)"
		}
		fmt.Fprintf(w, "  %-8s %s  operation=%s  resource=%s\n", strings.ToUpper(m.Severity), m.RuleID, m.Operation, res)
		if m.Message != "" {
			fmt.Fprintf(w, "           %s\n", m.Message)
		}
	}
	if v.Uninspectable != "" {
		fmt.Fprintf(w, "  UNKNOWN  %s\n", v.Uninspectable)
	}
	return errHeld
}

// ---- ca ------------------------------------------------------------------------

func cmdCA(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: twokey ca init|path|trust|untrust|reset")
	}
	if args[0] == "untrust" {
		return cmdCAUntrust()
	}
	if args[0] == "path" {
		// Report only; never create a CA (key material) as a side effect.
		home, err := homeDir()
		if err != nil {
			return err
		}
		p := filepath.Join(home, "ca.pem")
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("no CA yet at %s (created by `twokey up` or `twokey ca init`)", p)
		}
		fmt.Println(p)
		return nil
	}
	if args[0] == "reset" {
		home, err := homeDir()
		if err != nil {
			return err
		}
		if err := ca.Reset(home); err != nil {
			return err
		}
		fmt.Println("CA removed from", home, "— a new one is created on the next `twokey up`.")
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			fmt.Println("If you ran `twokey ca trust`, remove the old \"twokey local CA\" from your OS trust store and trust the new one.")
		}
		return nil
	}
	a, created, err := loadAuthority(nil)
	if err != nil {
		return err
	}
	switch args[0] {
	case "path":
		fmt.Println(a.CertPath())
		return nil
	case "init":
		bundle, err := a.EnsureBundle(context.Background())
		if err != nil {
			return err
		}
		state := "existing"
		if created {
			state = "new"
		}
		fmt.Printf("CA (%s): %s\nbundle:   %s\n", state, a.CertPath(), bundle)
		return nil
	case "trust":
		return trustCA(a.CertPath())
	default:
		return fmt.Errorf("unknown ca subcommand %q", args[0])
	}
}

// trustCA adds the CA to the OS trust store, which Go programs (gh,
// terraform, flyctl) use on Windows and macOS instead of SSL_CERT_FILE.
func trustCA(certPath string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("certutil", "-user", "-addstore", "Root", certPath)
	case "darwin":
		home, _ := os.UserHomeDir()
		cmd = exec.Command("security", "add-trusted-cert", "-r", "trustRoot",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"), certPath)
	default:
		fmt.Printf("On Linux, programs honor SSL_CERT_FILE (set by `twokey run`), so no system change is needed.\n"+
			"To trust it system-wide anyway (Debian/Ubuntu):\n  sudo cp %s /usr/local/share/ca-certificates/twokey.crt && sudo update-ca-certificates\n", certPath)
		return nil
	}
	fmt.Println("running:", strings.Join(cmd.Args, " "))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// ---- replay ----------------------------------------------------------------------

type scenario struct {
	story  string
	method string
	url    string
	header http.Header
	body   string
}

var scenarios = map[string]scenario{
	"pocketos": {
		story: "April 25, 2026: a coding agent working on a *staging* task called Railway's GraphQL API\n" +
			"and deleted PocketOS's production volume — and its backups — in about nine seconds.\n" +
			"Railway's API is GraphQL: every mutation is a POST, so 'block DELETE' rules miss it.",
		method: "POST",
		url:    "https://backboard.railway.com/graphql/v2",
		header: http.Header{"Content-Type": {"application/json"}},
		body:   `{"query":"mutation volumeDelete($volumeId: String!) { volumeDelete(volumeId: $volumeId) }","variables":{"volumeId":"pg-data-prod"}}`,
	},
	"github-repo-delete": {
		story:  "An agent 'cleaning up old repos' deletes the wrong one.",
		method: "DELETE",
		url:    "https://api.github.com/repos/acme/prod-api",
	},
	"aws-rds-delete": {
		story:  "An agent tears down 'unused' infrastructure, including the orders database, with no final snapshot.",
		method: "POST",
		url:    "https://rds.us-east-1.amazonaws.com/",
		header: http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"}},
		body:   "Action=DeleteDBInstance&DBInstanceIdentifier=orders-prod&SkipFinalSnapshot=true&Version=2014-10-31",
	},
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	live := fs.Bool("live", false, "send the request through the running proxy (no credentials are sent)")
	addr := fs.String("addr", defaultAddr, "proxy address for --live")
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	if name == "" {
		fmt.Println("usage: twokey replay <scenario> [--live]\n\nscenarios:")
		for _, n := range names {
			fmt.Printf("  %-20s %s\n", n, strings.SplitN(scenarios[n].story, "\n", 2)[0])
		}
		return nil
	}
	sc, ok := scenarios[name]
	if !ok {
		return fmt.Errorf("unknown scenario %q; available: %s", name, strings.Join(names, ", "))
	}
	fmt.Printf("── replay: %s ──\n%s\n\n", name, sc.story)
	if !*live {
		engine, err := loadEngine("")
		if err != nil {
			return err
		}
		err = explain(os.Stdout, engine, sc.method, sc.url, sc.header, []byte(sc.body))
		if errors.Is(err, errHeld) {
			fmt.Println("\nWith `twokey up` running, add --live to watch it get held and decide yourself.")
			return nil
		}
		return err
	}
	return replayLive(*addr, sc)
}

// replayLive sends the scenario through the proxy. It carries no
// credentials, so even an approved request is rejected by the provider.
func replayLive(addr string, sc scenario) error {
	a, _, err := loadAuthority(nil)
	if err != nil {
		return err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(a.CertPEM())
	proxyURL := &url.URL{Scheme: "http", Host: addr}
	client := &http.Client{
		Timeout: 10 * time.Minute, // the human may take a while
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	req, err := http.NewRequest(sc.method, sc.url, strings.NewReader(sc.body))
	if err != nil {
		return err
	}
	for k, vs := range sc.header {
		req.Header[k] = vs
	}
	fmt.Println("sending through twokey… decide in the `twokey up` window or on your phone.")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("is `twokey up` running on %s? %w", addr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	fmt.Printf("\n← %s (X-Twokey: %s)\n%s\n", resp.Status, resp.Header.Get("X-Twokey"), strings.TrimSpace(string(body)))
	return nil
}
