package runenv

import (
	"strings"
	"testing"
)

func TestApplyOverridesCaseInsensitivelyAndDropsUserNoProxy(t *testing.T) {
	base := []string{"PATH=/bin", "https_proxy=http://corp:3128", "No_Proxy=.amazonaws.com", "HOME=/h"}
	env := Apply(base, Vars(Config{ProxyURL: "http://127.0.0.1:7171", CACert: "/ca.pem", Bundle: "/bundle.pem"}))

	if got := Lookup(env, "HTTPS_PROXY"); got != "http://127.0.0.1:7171" {
		t.Fatalf("HTTPS_PROXY = %q", got)
	}
	for _, e := range env {
		if strings.Contains(e, "corp:3128") || strings.Contains(e, ".amazonaws.com") {
			t.Fatalf("stale entry kept: %q", e)
		}
	}
	if Lookup(env, "PATH") != "/bin" || Lookup(env, "HOME") != "/h" {
		t.Fatal("unrelated variables must be preserved")
	}
	for _, k := range []string{"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "NODE_USE_ENV_PROXY"} {
		if Lookup(env, k) == "" {
			t.Errorf("%s not set", k)
		}
	}
}

func TestApprovalSecretsNeverReachTheAgent(t *testing.T) {
	base := []string{"TWOKEY_NTFY_TOPIC=twokey-secret", "twokey_ntfy_server=https://x", "TWOKEY_HOME=/h"}
	env := Apply(base, Vars(Config{ProxyURL: "http://p"}))
	for _, e := range env {
		if strings.Contains(strings.ToUpper(e), "TWOKEY_NTFY") {
			t.Fatalf("approval secret leaked into agent env: %q", e)
		}
	}
	if Lookup(env, "TWOKEY_HOME") != "/h" {
		t.Fatal("non-secret twokey settings should be kept")
	}
}

func TestVarsWithoutBundleSkipsReplacingTrustStores(t *testing.T) {
	for _, kv := range Vars(Config{ProxyURL: "http://x", CACert: "/ca.pem"}) {
		if kv.Key == "SSL_CERT_FILE" {
			t.Fatal("SSL_CERT_FILE must not point at a missing bundle")
		}
	}
}
