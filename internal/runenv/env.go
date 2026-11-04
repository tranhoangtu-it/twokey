// Package runenv builds the environment that routes an agent (and every
// child process it spawns) through twokey: proxy variables plus CA trust for
// each common runtime.
package runenv

import (
	"strings"
)

// Config locates the running proxy and the CA files.
type Config struct {
	ProxyURL string // e.g. http://127.0.0.1:7171
	CACert   string // twokey CA only (additive trust, Node)
	Bundle   string // public roots + twokey CA (replacing trust: OpenSSL, Python, curl, AWS)
}

// KV is one environment variable.
type KV struct{ Key, Value string }

// secretPrefix marks variables that belong to the approver, not the agent.
const secretPrefix = "TWOKEY_NTFY_"

// localBypass keeps local traffic (dev servers, the proxy itself) direct.
const localBypass = "localhost,127.0.0.1,::1"

// Vars returns the variables to set, in a stable order. Any existing
// NO_PROXY is deliberately replaced: entries like ".amazonaws.com" would let
// traffic to watched hosts bypass twokey entirely.
func Vars(c Config) []KV {
	noProxy := localBypass
	vars := []KV{
		{"HTTPS_PROXY", c.ProxyURL},
		{"HTTP_PROXY", c.ProxyURL},
		{"https_proxy", c.ProxyURL},
		{"http_proxy", c.ProxyURL},
		{"NO_PROXY", noProxy},
		{"no_proxy", noProxy},
		// Node >= 22.21 / 24.5 only honors *_PROXY with this flag.
		{"NODE_USE_ENV_PROXY", "1"},
		{"NODE_EXTRA_CA_CERTS", c.CACert},
		{"TWOKEY_PROXY", c.ProxyURL},
	}
	if c.Bundle != "" {
		vars = append(vars,
			KV{"SSL_CERT_FILE", c.Bundle},      // OpenSSL, Go on Linux, Ruby, Python ssl
			KV{"REQUESTS_CA_BUNDLE", c.Bundle}, // Python requests
			KV{"CURL_CA_BUNDLE", c.Bundle},     // curl
			KV{"AWS_CA_BUNDLE", c.Bundle},      // AWS CLI / SDKs
		)
	}
	return vars
}

// Apply returns base with vars overriding any existing entries. Keys compare
// case-insensitively so Windows (case-insensitive env) never ends up with
// two competing values.
func Apply(base []string, vars []KV) []string {
	override := map[string]bool{}
	for _, kv := range vars {
		override[strings.ToUpper(kv.Key)] = true
	}
	out := make([]string, 0, len(base)+len(vars))
	for _, e := range base {
		k, _, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(k)
		// The phone-approval topic is the approval secret: the agent must
		// never see it, or it could approve its own requests.
		if override[upper] || strings.HasPrefix(upper, secretPrefix) {
			continue
		}
		out = append(out, e)
	}
	for _, kv := range vars {
		out = append(out, kv.Key+"="+kv.Value)
	}
	return out
}

// JavaToolOptions returns JAVA_TOOL_OPTIONS routing the JVM through the
// proxy with twokey's truststore, appended to any existing options.
// (HttpURLConnection and SDKs that honor the proxy system properties.)
func JavaToolOptions(proxyHostPort, trustStore, password, existing string) string {
	host, port, ok := strings.Cut(proxyHostPort, ":")
	if !ok {
		return existing
	}
	opts := []string{
		"-Dhttps.proxyHost=" + host, "-Dhttps.proxyPort=" + port,
		"-Dhttp.proxyHost=" + host, "-Dhttp.proxyPort=" + port,
		"-Dhttp.nonProxyHosts=localhost|127.0.0.1|[::1]",
	}
	if trustStore != "" {
		opts = append(opts,
			"-Djavax.net.ssl.trustStore="+trustStore,
			"-Djavax.net.ssl.trustStoreType=PKCS12",
			"-Djavax.net.ssl.trustStorePassword="+password)
	}
	joined := strings.Join(opts, " ")
	if existing = strings.TrimSpace(existing); existing != "" {
		return existing + " " + joined
	}
	return joined
}

// Lookup returns the value of key in env (case-insensitive), or "".
func Lookup(env []string, key string) string {
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok && strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
