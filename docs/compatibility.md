# Compatibility promise (1.x)

twokey follows [Semantic Versioning](https://semver.org/). From v1.0.0 on, everything listed under
**Stable** keeps working across every 1.x release. A change that breaks any of it ships only in a
new major version, is called out in [CHANGELOG.md](../CHANGELOG.md), and when possible is preceded
by a deprecation warning printed by the CLI for at least one minor release.

## Stable

| Surface | What is guaranteed |
|---|---|
| CLI | Commands, subcommands and flags listed by `twokey --help` keep their names and meaning. New commands and flags may be added. |
| Exit codes | `explain`: 0 passes, 2 would be held. `run`: the agent's exit status, or 125 when twokey itself failed. Other commands: 0 success, non-zero failure. |
| Rule YAML | Pack fields `provider`, `docs`, `rules`; rule fields `id`, `hosts`, `methods`, `path`, `unless_query`, `graphql.mutations`, `aws.actions`, `json.field/equals`, `resource`, `severity`, `message`; path template syntax `{x}` / `{x...}`; resource templates `{pathvar}`, `{a\|b}`, `{query.<key>}`, `{json.<path>}`. |
| Allow file | `.twokey-allow.yaml` (`allow:` list of `rule`, `resource`, `reason`), `--allow FILE`, and the trust step (`twokey allow trust`). |
| Audit log | `audit.jsonl`: one JSON object per line with `time` (RFC 3339), `id`, `method`, `url`, `matches`, `uninspectable`, `approved`, `by`, `reason`. Fields may be added, never removed or renamed. |
| Denial response | HTTP 403 with a JSON body whose message tells the model not to retry; Postgres/MySQL return an ordinary server error. |
| Agent environment | Variables `twokey run` sets: `HTTPS_PROXY`, `HTTP_PROXY` (and lowercase), `NO_PROXY`, `NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`, `TWOKEY_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`, `JAVA_TOOL_OPTIONS` (when Java is present), `CURL_HOME` (Windows). `TWOKEY_NTFY_*` is always removed. |
| Home directory | `TWOKEY_HOME` (default `~/.twokey`) and the meaning of `ca.pem`, `ca-key.pem`, `ca.old.*.pem`, `ntfy-topic`, `audit.jsonl`. |

## Not breaking (may change in any minor release)

- **New rules.** Minor releases add rules and providers. More requests being held is the point of
  an upgrade. When new rules add domains, the local CA rotates and `twokey ca trust` must be run
  again (`twokey setup --yes --trust`), as documented in the README.
- **Fixing a bypass.** If a request that a rule was meant to cover slipped through, holding it is
  a fix, not a breaking change — even if someone relied on it passing.
- **Stricter parsing.** Requests that become uninspectable because twokey now detects an
  ambiguity are held (fail closed).
- Human-facing text: terminal prompts, banners, phone notifications, `doctor` output, error wording.
- Internal Go packages (`internal/...`) — twokey is not a library.

## Breaking (major release only)

- Removing a builtin rule, or narrowing it so that a request it held now passes, other than to fix
  a false positive confirmed against the provider's API reference.
- Removing or renaming a command, flag, exit code, rule/allow field, audit field or `run` variable.
- Changing defaults so that something held by default is no longer held.

## Supported platforms

Linux, macOS and Windows on amd64 and arm64, built with the Go version in `go.mod` (security patch
releases of Go are picked up in twokey patch releases). Node ≥ 22.21 / ≥ 24.5 for Node agents.
