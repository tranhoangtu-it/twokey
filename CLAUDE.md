# CLAUDE.md

twokey: a local HTTPS proxy + Postgres/MySQL guard that holds destructive cloud API calls made by AI
agents until a human approves (terminal or phone). Go ≥ 1.26.10, module `github.com/tranhoangtu-it/twokey`.
User-facing behavior is in README.md; threat model and key handling in SECURITY.md.

## Commands

```sh
go vet ./... && go test -race ./...          # must pass; CI runs ubuntu/macos/windows
go test ./internal/rules/ -run Fixture       # rule ↔ fixture check (every rule needs one)
go test -tags e2e ./e2e/                     # real binary end to end (Python + network;
                                             # TWOKEY_E2E_PG=host:port for the Postgres case)
go run ./cmd/twokey rules                    # list rules
go run ./cmd/twokey explain --method DELETE --url https://api.github.com/repos/a/b   # exit 2 = held
```

Use a throwaway `TWOKEY_HOME` (e.g. `$TEMP/tk-x`) when running the binary by hand: the real
`~/.twokey` holds the user's trusted CA, and adding rule hosts rotates it (the user must re-trust).

## Layout

- `cmd/twokey/` — CLI: `main.go` (dispatch, usage, `ca`, explain/replay), `serve.go` (up, run, env,
  doctor), `proxy_runtime.go` (startProxy, setupApprovals, phone topic), `cmd_pg.go` (pg/mysql guards),
  `strict.go` (Docker `--strict`), `setup.go`, `log.go`, `uninstall.go`, `rules_fixtures.go`.
- `internal/proxy/` — selective MITM: only hosts with rules are intercepted, everything else tunneled.
  `proxy.go` (CONNECT/tunnel), `intercept.go`, `check.go` (rules → allow → broker → audit), `response.go`.
- `internal/rules/` — YAML packs (`packs/*.yaml`, embedded), engine (`rules.go`), path templates,
  GraphQL / AWS (Query `Action`, `X-Amz-Target`) decoders, `json:` body matcher, allow rules, fixtures.
- `internal/approval/` — Broker (first decision wins; timeout denies), terminal + ntfy channels,
  observe mode, timed grants (exact method+URL+rule+resource+statement, ≤1h, in memory), desktop toasts.
- `internal/ca/` — name-constrained local CA (rotates when rule domains grow), Windows key DACL,
  thumbprints for untrust, CA bundle, Java truststore.
- `internal/pgguard`, `internal/myguard` — wire-protocol guards; `sqlclass` classifies SQL,
  `sqlhold` is the shared hold/audit step. `internal/runenv` builds the agent's env vars.

## Rules and fixtures

Every builtin rule must have `internal/rules/testdata/<rule-id>.http`: the destructive request copied
from the provider's **official API reference** (`# source:` URL, `# resource:`), then `###` and
requests that must NOT be held. `TestEveryBuiltinRuleHasPassingFixture` fails otherwise. Never weaken a
rule to make a fixture pass. Resource templates: `{pathvar}`, `{a|b}`, `{query.<key>}`, `{json.<path>}`.

## Invariants (security tool — keep them)

- Fail closed: a watched request that cannot be parsed is held (`Uninspectable`).
- Request-derived text shown to a human goes through `approval.Clean`; never interpolate it into
  scripts or shell commands (pass via argv/env).
- Grants/allow rules never cover uninspectable requests or unknown resources.
- Windows: remove certificates with `certutil` and re-check the store; PowerShell launched from Go
  inherits PSModulePath and loses the `Cert:` drive; all-digit ids are certutil store indexes.
- Verify OS-level behavior (trust stores, ACLs, toasts) live from a Go-launched process, not only in
  unit tests — the v0.6.1 untrust bug passed every unit test.

## Workflow

Tests first. Conventional commits, no AI attribution. Branch + PR; never push to `main`. The maintainer
merges and tags (`git tag vX.Y.Z origin/main && git push origin vX.Y.Z` → goreleaser release).
