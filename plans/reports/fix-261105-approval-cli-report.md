# Fix report: approval / audit / runenv / cmd/twokey

Input: `plans/reports/audit-261104-2351-approval-cli-report.md`. Scope: internal/approval, internal/audit,
internal/runenv, cmd/twokey (+ README/SECURITY docs). Nothing committed.

Gates (final run): `gofmt -l .` empty; `go vet ./...` clean; `go test -race -count=1 ./internal/approval/...
./internal/audit/... ./internal/runenv/... ./cmd/...` ok; staticcheck v0.8.2 on those packages clean.
Live check with a throwaway TWOKEY_HOME (built binary, Windows): an untrusted allow file is ignored and the
banner says so; after `allow trust` it is used; after an edit it is ignored again; `up --timeout 0` and
`phone --ntfy-server http://example.com` fail with clear errors; `allow revoke` works.

TDD note: tests were written before the code. The first RED run of the approval and cmd tests was hidden
by other engineers' compile breakage in internal/rules and internal/sqlclass. The assertions target
behavior that did not exist (new functions, changed outputs), and the audit report documents
reproduction for #2 (stack overflow) and #8.

## Findings

| # | Finding | Result |
|---|---------|--------|
| 1 | HIGH: cwd `.twokey-allow.yaml` self-approval | **Fixed** (direnv-style trust) |
| 2 | phoneTopic infinite recursion | **Fixed** |
| 3 | ntfy server/topic not validated | **Fixed** |
| 4 | topic leaks into logs/banners | **Fixed** (logs, banners). The `--ntfy-topic` argv exposure was left as is (see below) |
| 5 | grants ignore body/query | **Fixed in approval; needs cross-package change** to take effect |
| 6 | audit log unbounded; `log` loads the whole file | **Fixed** |
| 7 | Clean misses invisible chars; notify-send markup | **Fixed** |
| 8 | resource ending in `--for <dur>` cannot be approved | **Fixed** |
| 9a | `--timeout` not validated; `log --since -1h` | **Fixed** (also ports, `log -n`) |
| 9b | no startup probe of the phone channel | **Not done**: a probe publish would push a notification to the phone on every start. Product decision left open |
| 9c | hold flood | **Fixed** (cap of 100) |
| 9d | `Terminal.Run` silent on stdin EOF | **Fixed** (prints that typed approvals are off) |
| 9e | long ntfy messages | **Fixed** (message capped at 3000 bytes, hold id kept) |
| 9f | shutdown audit race | **Fixed** |
| 10 | `--strict` gateway unpinned and left behind | **Fixed** |
| 11 | curlrc copied with proxy settings | **Fixed** |

### Details

1. `twokey allow trust [FILE]` / `twokey allow revoke [FILE]` (cmd/twokey/allow_trust.go). Trust is stored in
   `TWOKEY_HOME/allow-trusted.json` (path to SHA-256), written atomically, 0600 + `ca.RestrictToUser`. On
   load, `./.twokey-allow.yaml` is parsed only when the hashed bytes match. The same bytes are parsed,
   so there is no TOCTOU. Otherwise the file is ignored, a warning is logged, and the banner shows
   `allow IGNORED … run twokey allow trust`. `--allow FILE` counts as trust and must exist with at least
   one entry. `trust` refuses files that do not parse and prints the entries, passed through
   `approval.Clean`. Wired into `up`, `run --phone/--observe`, `pg`, and `mysql`. Under `--strict`, an
   existing allow file is bind-mounted read-only over `/work/.twokey-allow.yaml`. If the file is absent
   the agent can create one, but it is untrusted.
2. `phoneTopic` is now a bounded loop with no recursion. The topic is written to a 0600 temp file
   (restricted), then hard-linked into place. A link fails if the file exists, so concurrent first runs
   agree on one topic. Without hard links it falls back to rename. An empty file is regenerated. A
   non-empty invalid file gives a clear error pointing to `twokey phone --rotate`.
3. `approval.ValidateNtfy(server, topic)`: https only (http only for localhost, 127.0.0.0/8 and ::1); no
   credentials in the URL; topic 16–64 characters from `[A-Za-z0-9_-]`. Errors never include the topic.
   It is enforced in `setupApprovals`, which covers up, run, pg and mysql, and in `twokey phone`. It is a
   hard error, not a warning.
4. Ntfy errors are logged through `redact`, which replaces the topic with `…<last4>` (covers `*url.Error`
   URLs and server bodies). The channel banner is now `phone — ntfy topic …abcd on https://ntfy.sh (see
   twokey phone)` in every mode. The full topic appears only in `twokey phone` and `twokey setup`.
5. `approval.Request.Fingerprint` and `approval.BodyFingerprint(body, rawQuery)` are added. Grants store
   and match the fingerprint exactly. **Needs a cross-package change (internal/proxy/check.go):** set
   `Fingerprint: approval.BodyFingerprint(evalBody, req.URL.RawQuery)` in the `approval.Request` passed to
   `Decide`, and for SQL (internal/sqlhold) the statement is already bound via `Statement`. Until then
   both sides are empty and the behavior is unchanged.
6. audit: rotation when the next line would exceed 20 MiB (`audit.jsonl.1..3`). If another process
   rotated first, the file is reopened. If a rename fails (for example on Windows while another process
   holds the file), writing continues instead of dropping rows. Agent-controlled fields (URL, reason,
   uninspectable, match message, resource, operation) are capped at 8 KiB with `…[truncated]`, on a copy.
   The caller's data is not mutated. Each line is a single `Write`, and a short write is terminated with a
   newline. Files stay 0600. `twokey log` now streams with a bounded ring of `-n` entries. It skips
   over-long lines without buffering them and reads `audit.jsonl.3 … .1, audit.jsonl` oldest first,
   always, which covers `--since`. It uses `bufio.Reader.ReadSlice` rather than `Scanner`, because
   `Scanner` cannot skip an over-long line and continue.
7. `Clean` also maps every Unicode `Cf` character (zero-width U+200B–U+200F, U+2060–U+2064, U+FEFF, soft
   hyphen, bidi) and the whole tag block U+E0000–U+E007F to `?`. On Linux/BSD, the notify-send title and
   body escape `& < >`.
8. Terminal: an exact match of the whole typed text against the confirmation approves once. Only
   otherwise is a final `--for <dur>` pair read as a grant, and only when it is a valid duration of at
   most 1h.
9. `--timeout` must be greater than 0 and at most 1h in `up`, `run` and `pg/mysql` (`run` exits 125 per
   the existing convention). Addresses must have a numeric port from 0 to 65535 (`--upstream` needs
   1–65535). `log -n` must be at least 0 and `--since` at least 0. Broker: `MaxPending = 100`. Beyond it,
   `Decide` returns `{By: "overload", Reason: "denied without asking: 100 requests are already waiting…"}`
   at once, with no prompt or notification. The proxy already audits it and puts `reason`/`decided_by` in
   the 403 body. Shutdown: `denyAndDrain` runs `DenyAll`, then `Broker.Drain(3s)` (waits for every
   `Decide` to return), then the existing 500ms grace, before `srv.Close` and the audit close. pg/mysql
   close the listener first, then deny and drain, then the deferred audit close. As a backstop,
   `audit.Log.Write` after `Close` reopens the file for that one append, so late rows are not lost.
10. The gateway image is pinned to
    `alpine/socat@sha256:466c8a0383e16463fabdb7df01008292fb78d07da60224a46cb5d3142ce122ed`, the multi-arch
    index digest of `latest`, looked up with `docker buildx imagetools inspect` on 2026-11-05. Gateways are
    now per run (`twokey-gw-<port>-<rand>`) with no `--restart`, and are removed when the agent exits.
    twokey ignores Ctrl+C during a strict run so it can clean up. `uninstall` still removes any
    `twokey-gw-*` left behind.
11. `curlHome` drops curlrc lines for proxy*, socks*, noproxy, preproxy and insecure, plus the short forms
    `-x -U -p -k`.

## Needs cross-package change (not made)
- internal/proxy/check.go: set `approval.Request.Fingerprint` (see #5).
- internal/proxy/response.go `blockedResponse`: the human-readable message says "denied by a human" for
  `decided_by: overload` and `shutdown` too. Suggest wording by `d.By`. `reason` is already correct.

## Not changed (with reason)
- `--ntfy-topic X` in argv (finding 4): this flag is the user's explicit choice. The recommended path is
  the 0600 file. It could be removed or deprecated if wanted.
- Startup ntfy probe (9b): see the table.
- Grants were not extended to the raw query separately: the fingerprint covers query and body together.

## Files changed
- internal/approval: broker.go (Fingerprint, BodyFingerprint, Clean/isInvisible, MaxPending/SetMaxPending,
  Drain), grants.go (fingerprint binding), terminal.go (--for parsing, EOF message), ntfy.go (ValidateNtfy,
  RedactTopic, redacted logs, bounded messages), desktop.go (markup escaping); approval_test.go (raised the
  cap in the stalled-console test, which exercises the console rather than the cap).
- internal/audit: audit.go (rotation, Options/OpenWith, Files, field caps, write-after-close,
  short-write); audit_test.go (dropped the "write after close fails" assertion; that behavior was
  intentionally replaced by #7/9f).
- cmd/twokey: allow_trust.go (new), proxy_runtime.go, cmd_pg.go, serve.go, strict.go, log.go, main.go
  (usage + `allow` dispatch); main_test.go (strictRunArgs now takes the gateway name).
- README.md (allow trust section, timeout/overload/ntfy rules, audit rotation, strict gateway),
  SECURITY.md (topic redaction/validation, allow trust).

## Tests added
- internal/approval/hardening_test.go: zero-width/tag Clean; notify-send escaping; resource ending in
  `--for`; pending cap + default; Drain; ValidateNtfy table; topic redaction against a closed port; bounded
  ntfy message; grant fingerprint binding.
- internal/audit/rotate_test.go: rotation keeps 3 files under the cap at 0600; defaults; 20×50 concurrent
  writes stay whole lines; field truncation without mutating input; write after Close lands; Files order.
- cmd/twokey/hardening_test.go: allow trust/modify/revoke; `--allow` counts as trust; trust rejects an
  invalid file; `startProxy` ignores an untrusted file (banner); empty/corrupt topic file; setupApprovals
  rejects http/short topics and never shows the topic; timeout/port/log flag validation (including run's
  exit 125); log reads rotated files and separates files without a trailing newline; pinned gateway,
  per-run name, no restart, read-only allow mount; curlrc proxy lines dropped.

## User-visible changes (CHANGELOG/README)
- **Breaking:** `./.twokey-allow.yaml` is ignored until you run `twokey allow trust` (re-run it after
  every edit). `--allow FILE` still works without trust. New command: `twokey allow trust|revoke [FILE]`.
- **Breaking:** the ntfy server must be https (http only for localhost), and topics must be 16 or more
  characters from `[A-Za-z0-9_-]`. Short topics are now an error, not a warning.
- `--timeout` must be greater than 0 and at most 1h. Ports are validated. `log -n`/`--since` must not be
  negative.
- Over 100 pending holds: new ones are denied immediately (`decided_by: overload`).
- The audit log rotates at 20 MiB (keeps `.1`–`.3`) and long fields are truncated. `twokey log` streams
  and includes rotated files.
- Banners and logs show the ntfy topic as `…last4`.
- `--strict`: the gateway is pinned by digest, created per run and removed on exit.
- Resources named like `x --for 5m` are approvable from the terminal. Invisible Unicode is shown as `?`.
- The Windows curl config for the agent drops proxy, noproxy and insecure options copied from your curlrc.
- `twokey up` with no stdin now says typed approvals are off.

## Unresolved questions
- Should `--ntfy-topic` (argv) be deprecated in favor of the file only?
- Should there be a startup ntfy health check (for example GET `/v1/health`) instead of a publish probe?
