# Brainstorm: twokey v0.5 — trust & adoption (2026-11-04)

## Context (scout)
- Go, ~5.4k LOC prod / ~1.8k LOC tests, 10 packages; largest `internal/proxy/proxy.go` 664 LOC (limit 800).
- Features: HTTPS proxy, Postgres/MySQL guards, `--strict` (Docker), JVM, allow rules, terminal+phone approvals, 68 rules / 21 providers.
- Releases v0.1→v0.4, CI 3 OS, Dependabot. Adoption: 1 star, 0 forks, 0 issues.

## Problem (problem-first)
Not "missing features" — **no users yet**. Blockers: time-to-aha (install → ca trust → phone → 2 terminals), trust (root CA install without clean removal; CA key ACL on Windows; unverified rules), no demo/launch.

## Decision
User chose "all" → implement the 10 MUST + SHOULD items. Explicitly OUT of scope (YAGNI / risk): remote rule-pack auto-update, web dashboard, team approvals, kubectl plugin, new wire protocols.

## Scope (10 functions)
| # | Function | Acceptance criteria | Size |
|---|---|---|---|
| 1 | `twokey uninstall` + `twokey ca untrust` | Removes current + `ca.old.pem` CAs from OS store (Win certutil -delstore by thumbprint, macOS security delete-certificate), removes `twokey-gw-*` containers + `twokey-strict` network if Docker present; `--purge` deletes `~/.twokey`; idempotent | S |
| 2 | CA key ACL on Windows | After CA creation, `icacls ca-key.pem /inheritance:r /grant:r <user>:F`; doctor warns if others can read | S |
| 3 | Rule fixtures + `twokey rules test` | `internal/rules/testdata/<rule-id>.http` (raw request recorded from official CLI/SDK or docs) for every builtin rule; test asserts each fixture is held by its rule and a sibling safe request passes; CI fails on rule without fixture | M |
| 4 | `twokey setup` | One command: ca init → offer ca trust (y/N) → phone topic + QR (terminal) → doctor summary; non-interactive `--yes` | S |
| 5 | `twokey up --observe` | Matches logged + audited (`by: observe`) but forwarded; banner says OBSERVE; works for pg/mysql guards too | S |
| 6 | `twokey log` | Pretty last N (default 20) from audit.jsonl; filters `--provider`, `--denied`, `--since`; `--json` passthrough | S |
| 7 | Desktop notifications | Notifier on hold (Windows toast / macOS osascript / Linux notify-send); best-effort, never blocks broker; `--no-desktop` | S |
| 8 | Timed approvals | Terminal `approve <id> <resource> --for 15m` → grant scoped to rule id + exact resource, expires; shown in banner/log; never applies to uninspectable | M |
| 9 | Packaging | goreleaser: Homebrew tap, Scoop bucket (winget manifest optional); README install section | S |
| 10 | Refactor `proxy.go` | Split into intercept.go / response.go / body.go, no behavior change, tests unchanged & green | S |

## Risks
- #1 removing certs by subject could hit unrelated certs → match by exact thumbprint of files we created.
- #8 over-approval → exact resource match only, max 1h, audited.
- #9 needs separate tap/bucket repos + PAT secret in Actions (user action).
- #3 fixture authenticity: prefer docs/CLI-source captures; mark source in fixture header.

## Success metrics
- Fresh machine → first held request in ≤ 2 commands (`setup`, `run`).
- `uninstall` leaves no twokey certs in OS store (verified on Windows).
- 100% builtin rules have fixtures; CI enforces.
- All existing tests + new tests green with -race on 3 OS.

## Next
`/ck:plan` with this report; after v0.5: demo GIF + Show HN, then let issues drive further features.

## Unresolved
- Homebrew/Scoop need two extra public repos + token — user must create (or approve creation).
