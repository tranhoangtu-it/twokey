# Audit: approval, audit, runenv, cmd/twokey (read-only)

Scope: internal/approval, internal/audit, internal/runenv, cmd/twokey (non-test). Method: full read of every file in scope plus the call sites in internal/proxy/check.go, internal/sqlhold/hold.go and internal/rules/allow.go. Nothing was executed; the tests below are proposals. No file other than this report was written.

Checked and found sound (not findings):
- ANSI/C0/C1/bidi neutralization via `approval.Clean` on every request-derived string reaching the terminal, ntfy and toast.
- Toast: constant PowerShell script, text via env vars. osascript and notify-send get text as argv (`--` guards notify-send).
- Query strings are stripped before they reach Request/audit/ntfy (`displayURL`, check.go:170), so tokens in query strings do not leak. DSNs are never logged: the pg/mysql target is `scheme://upstream[/db]`.
- ntfy replies require an unguessable per-hold nonce (64-bit crypto/rand) and are single-use. Replays and stale taps are inert.
- Broker resolve/expire races are correct (buffered chan, delete-under-lock).
- ntfy publish is bounded to 15s, and the subscription has a 90s idle watchdog.
- Grants: capped at 1h, in memory, never cover uninspectable or unknown-resource requests, monotonic expiry.
- Audit appends are mutex-guarded, single `Write`, O_APPEND, 0600.
- `NO_PROXY` is replaced, `TWOKEY_NTFY_*` is stripped from the agent env, `twokey env` quoting is correct.

## Findings

### 1. HIGH: agent can self-approve across sessions via `./.twokey-allow.yaml` in the working directory
- Where: cmd/twokey/proxy_runtime.go:74-84 (`allowPath` defaults to `./.twokey-allow.yaml`), cmd/twokey/cmd_pg.go:83-90, internal/rules/allow.go:29-85. The `--strict` mount `-v workdir:/work` (strict.go:43) is read-write.
- Scenario: SECURITY.md lists "a way for the agent's normal process environment to approve its own hold" as in scope. The allow file is read from the directory the human starts `twokey up`, `run --phone` or `pg` in, normally the agent's project dir, where the agent can write. A prompt-injected or confused agent writes `allow: [{rule: "*", resource: "*"}]`. This is an ordinary file write that no hold covers. At the next `twokey up` or `twokey run --phone` in that dir, every destructive call is auto-approved. The only trace is one banner line ("allow N pre-approved operation(s)", proxy_runtime.go:144) and `by=allowlist` audit rows. The same happens if a cloned repo ships such a file.
- The file is read once at startup, so it is not a same-session bypass. It is a persistent cross-session one.
- Fix options: default the allow file to `~/.twokey/allow.yaml` (outside the agent's write path), or require an explicit `--allow` flag, or refuse `*` / any file not owned or protected by the user. At minimum, print each allow entry in the banner and require confirmation when the file is in cwd and was modified after the last run.
- Test (cmd/twokey): `t.Chdir(tmp)`; write `.twokey-allow.yaml` with `rule: "*"`, `resource: "*"`; call `startProxy` with `allowFile: ""`; send `DELETE https://api.github.com/repos/a/b` through the proxy. Assert it is held. It currently passes through with `by=allowlist`.

### 2. MEDIUM: `phoneTopic` recurses forever (stack overflow crash) on an empty or whitespace `ntfy-topic` file
- Where: cmd/twokey/proxy_runtime.go:205-231.
- Scenario: the file is created with O_EXCL (:224) and then written (:232). A crash, disk-full or kill between those two calls leaves a 0-byte file with no cleanup on the write-error path. Afterwards:
  1. `ReadFile` succeeds but `TrimSpace` is empty, so the function falls through.
  2. `OpenFile(O_EXCL)` returns `ErrExist`.
  3. `phoneTopic(dir, false)` is called again with the same state, forever.
  The Go runtime dies with "goroutine stack exceeds 1000000000-byte limit". `twokey phone`, `setup`, `up --phone` and `run --phone` all crash. Only `phone --rotate` recovers, and nothing tells the user that.
- Fix: treat an empty file as absent, via `os.Remove` plus a bounded retry. Also remove the file when the write or ACL step fails.
- Test: `os.WriteFile(filepath.Join(dir,"ntfy-topic"), nil, 0o600); phoneTopic(dir,false)` must return a topic or an error. Today it kills the test binary with a fatal stack overflow.

### 3. MEDIUM: ntfy server and topic are not validated, so the approval secret can travel in cleartext or be guessable
- Where: internal/approval/ntfy.go:32-35, cmd/twokey/proxy_runtime.go:182-190, cmd/twokey/serve.go:36,191 (server from env/flag, unchecked).
- Scenario A: `TWOKEY_NTFY_SERVER=http://ntfy.example.com`, or a scheme-less value. With `http://`, topic, reply topic and the per-hold nonce (carried in the Approve button body) cross the network unencrypted. Anyone on path reads topic and nonce and can POST `approve <id> <nonce>`. A scheme-less value makes every publish fail with "unsupported protocol scheme", logged only.
- Scenario B: `--ntfy-topic mytopic` or `TWOKEY_NTFY_TOPIC`. On public ntfy.sh, anyone can subscribe and read the nonce, then approve. The only guard is a `logger.Printf` warning for len<16 (:183). In `run --phone` the logger writes to `~/.twokey/twokey.log` (serve.go:182,192), so the human never sees the warning.
- Fix: require `https://` unless the host is loopback or an explicit `--ntfy-insecure` is given; reject topics shorter than 16 chars or low-entropy ones, or fail hard instead of warn. Do a startup publish probe so a dead channel is reported immediately (see #9).
- Test: `setupApprovals` with `ntfyServer: "http://example.com"` (or a topic of `"abc"`) should return an error. It currently starts the channel.

### 4. MEDIUM: phone-approval topic leaks into diagnostics and the agent's terminal
- Where: internal/approval/ntfy.go:180-185 and :162. The `client.Do` error is a `*url.Error` whose text embeds the full URL `…/<topic>-reply/json?since=…`, and `listenOnce`'s error is logged verbatim: `n.logf("ntfy: subscription dropped (%v)…")`. Also cmd/twokey/proxy_runtime.go:190 and serve.go:201.
- Scenario 1: any network blip writes the secret topic to `twokey.log` (run --phone) or stderr. Logs are routinely pasted into issues or CI.
- Scenario 2: in `run --phone` the banner `phone — ntfy app subscribed to <server>/<topic>` is printed to twokey's stderr (serve.go:201). That is the same console the agent child inherits. It stays in the scrollback and, on Windows, any process attached to the console can read the screen buffer. It contradicts "the agent must never see it" (ntfy.go:22). The agent deliberately reading the console is arguably out of scope, but there is no need to print the secret in that mode. Same for the QR/URL in `setup`, which is justified there.
- Also: `--ntfy-topic X` puts the secret in argv (visible in the process list), contradicting SECURITY.md "never on the command line".
- Fix: unwrap `*url.Error` (`ue.Err`) before logging; print the topic only in `twokey phone`/`setup`, and elsewhere show `…<last4>`.
- Test: point `Ntfy` at a closed port; capture `logf`; assert the output does not contain the topic.

### 5. MEDIUM: timed grant ignores request body and query, so a grant approved for one payload covers another
- Where: internal/approval/grants.go:105-113 (key = method, URL, rule, resource, statement). `Request.URL` is query-stripped (check.go:170) and the body is not part of the key.
- Scenario: the human approves `POST https://rds.us-east-1.amazonaws.com/` `DeleteDBInstance orders-prod` with `--for 30m` after seeing `SkipFinalSnapshot=false`. Within 30 minutes the agent re-sends the same action and resource with `SkipFinalSnapshot=true`, or `DeleteAutomatedBackups=true` / `force=true`. It gets `by=grant` with no prompt. The same applies to any rule whose resource comes from the path and whose destructive severity depends on parameters in the body or query. The README promise "exact repeats" (terminal.go:178) is stronger than what is enforced.
- Fix: include a digest of the evaluated body and the raw query in the grant key (`Request` needs a `Fingerprint` field), or document the limitation in the terminal text.
- Test: `AddFor` with Request{…} and `Match` with the same URL/rule/resource but a different body fingerprint. Expect no match. Today it matches, because there is no field to differ.

### 6. MEDIUM: audit log has no size bound, and allowlist/observe paths write one unbounded entry per request
- Where: internal/audit/audit.go:36-63; writers at internal/proxy/check.go:67 (allowlist) and the observe path via `Decide`.
- Scenario: in observe mode, or with a broad allow rule, the agent loops on an allowed operation. Each request appends a line with no human rate limit. `URL` is the unbounded path (up to the 1 MB header limit) and `Matches[].Message` is SQL text of any length. Disk fills, and the audit writer then fails (`audit log write failed` is only logged and the request still proceeds). `twokey log` (log.go:66-92) reads every line into memory before trimming to `-n`, so a large file means a large allocation.
- Partial-write corner: `os.File.Write` can return a short write on disk-full. The torn line has no newline, so the next entry is appended to it and two records are lost (a skipped "malformed line").
- Fix: cap field sizes (truncate URL/Message to a few KB when writing), add size-based rotation, and stream `printLog` with a ring buffer of N lines.
- Test: write 1000 entries with 100 KB URLs and assert the file stays under the cap, or that the entry is truncated. Separately, `printLog` with `-n 5` over a 50 MB file should hold at most 5 lines in memory.

### 7. LOW: `Clean` misses invisible format characters, and notify-send renders markup
- Where: internal/approval/broker.go:61-85; desktop.go:123.
- Scenario: `Clean` strips C0, DEL, C1 and bidi/line separators. It still lets through ZWSP/ZWNJ/ZWJ (U+200B-D), U+2060, U+FEFF, soft hyphen and Unicode tag chars U+E0000-E007F. Resource names in the terminal's `approve <id> <confirm>` hint (terminal.go:89) are printed with `%s`, so two resources can look identical, or the hint contains characters the human cannot type, which makes terminal approval impossible (fails closed). `Operation`, `URL` and `Message` are printed with `%s`, which has no `%q` escaping to save them. On Linux, notify-send interprets Pango markup in the body (`<b>`, `<a href=…>`, `&`), so a path such as `/x/<a href="http://evil">approve in browser</a>` renders as a link in the toast.
- Fix: also map `unicode.Is(unicode.Cf, r)` and the tag block to `?`; escape `& < >` in the toast body for freedesktop.
- Test: `Clean("a​b‮evil\U000E0041")` should contain no Cf runes. Today only U+202E is mapped.

### 8. LOW: resource name ending in `--for <duration>` cannot be approved from the terminal
- Where: internal/approval/terminal.go:155-162, 184-193.
- Scenario: agent-controlled resource, e.g. repo `x --for 5m`. `ConfirmText` = `x --for 5m`. When the human types exactly that, `splitFor` strips the suffix as a grant request, then `rest != want` gives "not approved". Terminal approval is impossible (fail-closed DoS). Phone is unaffected.
- Fix: compare against `want` before stripping `--for`, or reject such resources up front.
- Test: `Handle("approve 1 x --for 5m")` with a pending Request whose resource is `x --for 5m`. Expect approved.

### 9. LOW: robustness and input validation gaps
- `--timeout` is not validated (serve.go:32,158; cmd_pg.go:48; broker.go:191). `0` or negative makes every hold time out instantly (silent deny-all with reason "within 0s"); a huge value pins goroutines and connections. Add `> 0` and an upper bound (and similar for `log --since -1h`, which is silently ignored at log.go:121).
- No startup check that the phone channel works (ntfy.go:110-133). With `run --phone` there is no terminal, so an unreachable or misspelled ntfy server means each hold is invisible and silently times out. The user only sees denials. A probe publish at startup would fix that.
- Hold flood: `Decide` registers every request with no cap (broker.go:179). Each hold costs a goroutine, a `Terminal` output burst and an ntfy POST goroutine. The terminal drops output once its 256-line queue is full (terminal.go:56-59), so the real prompt can vanish while the hold stays pending. Add a pending cap that fails closed (deny with a clear reason) and log the drop.
- `Terminal.Run` returns silently on EOF (terminal.go:112-117) while the banner still advertises "type approve…" (proxy_runtime.go:173). `twokey up` with stdin closed (service, IDE task) has a dead terminal channel and only the timeout denies.
- ntfy long messages: `Notify` embeds the cleaned URL untruncated (ntfy.go:74). A very long path exceeds ntfy's message limit (~4 KB; behavior depends on server version, unverified), so publish fails (logged only) while the hold waits. Truncate with `truncate()`.
- Shutdown audit race: in `up` the shutdown goroutine does `DenyAll`, sleeps 500ms, then `srv.Close()`, and `auditLog.Close()` runs when `Serve` returns (proxy_runtime.go:114-128). Handlers that wake after the file is closed lose their `by=shutdown` row (the error is only logged). The pg path (cmd_pg.go:140-143) closes after a bare `ln.Close()` with the same race. Wait for in-flight handlers (`srv.Shutdown` with a short context) before closing the log.

### 10. LOW: `--strict` gateway hygiene
- Where: cmd/twokey/strict.go:18-23,111-127.
- The gateway image `alpine/socat` is unpinned (`latest`) and pulled at runtime. It sits on the path of all agent proxy traffic, including plain-HTTP requests. Pin it by digest.
- `gatewayName` is keyed by the proxy port. `run --phone --strict` uses a random port every run, so a `--restart unless-stopped` container is left behind per run until `uninstall` (strict.go:118, uninstall.go removeDocker). They accumulate.
- Test: `strictRunArgs`/`ensureGateway` call with two ports should not leave two permanent containers. Or a unit test asserting the image string contains `@sha256:`.

### 11. LOW: `curlHome` copies the user's curlrc verbatim
- Where: cmd/twokey/serve.go:116-137 (Windows only).
- The user's `.curlrc` is copied into `~/.twokey/curl/.curlrc` and handed to the agent as `CURL_HOME`. Any `noproxy =`, `proxy =` or credentials in it survive. A `noproxy = ".amazonaws.com"` line would let curl bypass twokey, which is the very case the code removes for `NO_PROXY` (runenv.go:26-28). On Unix curl reads `~/.curlrc` directly, so twokey cannot stop that either, and this is noted for completeness. Strip `proxy`, `noproxy` and `insecure` lines when copying.

## Dropped after verification
- Query-string/token leakage to ntfy and audit: disproved (query stripped in `displayURL`).
- DSN password leakage: disproved (target excludes credentials).
- Missing HTTP timeouts for ntfy: bounded by context and watchdog.
- Toast/osascript/notify-send injection: argv or env only, constant scripts.
- Nonce/terminal approval races: single-use under mutex; typed confirmation defeats retargeting.
- Concurrent audit appends: serialized by the mutex; multi-process appends use O_APPEND.
- Grant expiry: monotonic and pruned on every access.
- Path traversal in CLI file args: `--data @file`, `--rules`, `--fixtures`, `--allow` are user-supplied read-only paths with no privilege boundary.

## Unresolved questions
- Is the cwd allow file intentional as a committed team policy file? If so, finding 1 needs a different fix (e.g. a signed or user-home policy) rather than removal.
- Does ntfy.sh truncate or reject JSON messages over 4096 bytes? Needed to size finding 9's long-message case.
- Should the phone approval carry a typed or resource-level confirmation as the terminal does? One tap approves everything in a batch; this is by design and was not flagged.
