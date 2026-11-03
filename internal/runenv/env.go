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

// localBypass keeps local traffic (dev servers, the proxy itself) direct.
const localBypass = "localhost,127.0.0.1,::1"

// Vars returns the variables to set, in a stable order. existingNoProxy is
// the caller's current NO_PROXY, which is preserved.
func Vars(c Config, existingNoProxy string) []KV {
	noProxy := localBypass
	if existingNoProxy != "" {
		noProxy = existingNoProxy + "," + localBypass
	}
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
		if !override[strings.ToUpper(k)] {
			out = append(out, e)
		}
	}
	for _, kv := range vars {
		out = append(out, kv.Key+"="+kv.Value)
	}
	return out
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
