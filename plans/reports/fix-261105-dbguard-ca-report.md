# Fix report: dbguard + ca (input: audit-261104-2351-dbguard-ca-report.md)

Scope: internal/sqlclass, internal/sqlhold, internal/pgguard, internal/myguard, internal/ca (+ tests),
README database section. Nothing committed.

## Verification

- `gofmt -l .` is empty; `go vet ./...` and `go vet -tags e2e ./e2e/` pass.
- `go test -race -count=1` passes for sqlclass, pgguard, myguard, sqlhold, ca and cmd/....
- `staticcheck@v0.8.2` is clean on the five packages.
- RED evidence on the old code: a probe test (since removed) reproduced C2, C3, C4, H1, H2, H3
  (EXPLAIN ANALYZE, CTE, COPY, MERGE all returned no finding), H5 (only `tmp_a` reported), the
  L7 false positive, and the **H4 panic: 50 of 4095 lengths crashed** (for example
  "slice bounds out of range [:33] with capacity 32"). M2 was RED before its fix (IP leaves
  verified, `LeafFor("8.8.8.8")` succeeded).
- The guard tests could not be run RED against the old code, because they need the new API
  (`Close`, `IdleTimeout`, the read cap parameter). C1, M3, M4, H6 and M7 were traced in the old
  code instead, and each test checks the fixed behaviour.

## Findings

| ID | Result | Fix |
|----|--------|-----|
| C1 MySQL compression | fixed | `hideCapabilities` removes CLIENT_SSL, CLIENT_COMPRESS and ZSTD (upper caps) from the greeting. The handshake response is now read before relaying; if it asks for compress, zstd or SSL (also M7), the client gets ERR 1043 (08S01) and the connection closes. The login never reaches the server. |
| C2 E'' / backslash strings | fixed | Postgres `E'…'` always uses backslash escapes. A plain literal containing a backslash is lexed both ways (Postgres standard_conforming_strings, MySQL NO_BACKSLASH_ESCAPES) and the findings are combined. If the other reading leaves a literal open, its findings are dropped for Postgres (the whole message is parsed first) and only for the last statement in MySQL (earlier statements run). |
| C3 MySQL comments don't nest | fixed | Dialect-specific lexer. |
| C4 `/*! */`, `/*!NNNNN`, `/*M!` | fixed | The comment body is lexed as SQL, whatever the version number. |
| H1 MySQL `--` | fixed | `--` is a comment only when followed by whitespace, a control character or the end of input. |
| H2 `$tag$` in MySQL | fixed | Dollar quoting is Postgres-only. |
| H3 nested / indirect | fixed | Destructive verbs are found at any depth when they start a statement: after `(`, `)`, BEGIN, THEN, ELSE, LOOP, REPEAT, ATOMIC, ROW, INSTEAD/ALSO, QUERY, `AS` (PREPARE/CREATE), or `DO` (but not for ON CONFLICT DO UPDATE). This covers EXPLAIN [ANALYZE], WITH (CTE DML), COPY (…), MERGE … THEN DELETE, PREPARE … AS, MySQL procedure/trigger/event bodies, Postgres routine bodies (string or dollar literal, checked recursively) and BEGIN ATOMIC. Held as UNINSPECTABLE: DO, CALL, COPY … PROGRAM, MySQL `PREPARE … FROM` anything other than a single literal, plpgsql `EXECUTE` of a computed string. A literal in `PREPARE … FROM 'x'` or `EXECUTE 'x'` is classified itself. |
| H4 panic | **confirmed, fixed** | The new lexer never indexes past the end (fuzzed). Each connection handler and relay goroutine has a `recover` that logs and closes only that connection (tested by forcing a panic with a nil broker). |
| H5 multi-target | fixed | One finding per object (`DROP TABLE a, b`, `TRUNCATE a, b`, `DROP FUNCTION f(int), g()`). The message runs as a whole, so allow rules are now all-or-nothing: unless every match is pre-approved, every match is held and shown. |
| H6 memory | fixed (no connection cap) | pg/mysql readers grow a `bytes.Buffer` with `io.CopyN` as bytes arrive (a 60 MiB header with no payload allocates under 1 MiB, tested). Classification is capped at `sqlclass.MaxInspect` = 1 MiB; anything larger is UNINSPECTABLE. **No limit on concurrent connections was added.** |
| M1 >64 MiB server rows | fixed | Server→client messages are streamed (cap 1 GiB, Postgres' own limit). Only `Z` and small `E` messages are buffered. Tested with a 65 MiB DataRow. |
| M2 CA IP constraints | fixed (IP only) | New constrained roots get `ExcludedIPRanges` 0.0.0.0/0 and ::/0. `Permits`/`LeafFor` refuse IP hosts on any constrained CA, old ones included. Not done: URI/email exclusions and an EKU on the root. `rules.Domains` over-breadth is **reported, not changed**: it keeps the last two labels, so a rule host under `co.uk` or `github.io` constrains the CA to the whole public suffix. |
| M3 hold ignores disconnect | fixed | New `sqlhold.WatchClient` (peeks the client while the statement is held) and `Guard.CheckContext(ctx, …)`. `Check` is kept and calls it with `Background`. Tested end to end in both guards: decision `By=client`. |
| M4 extended desync | fixed | A denied Q or Parse is no longer swallowed. It is forwarded with its SQL replaced by `twokey_denied`, so the server answers with a syntax error in the right place and handles Sync and the transaction itself. The relay rewrites that error (matched by batch number and marker) into the denial. Tested: P/B/E(ok) + P(denied)/B/E + S gives `12CEZ`; a pipelined slow Q then a denied Q gives `CZEZ`. A denied statement inside a transaction now aborts it, as a real permission error would. |
| M5 DROP object kinds | partly | Every DROP is now held except `DROP PREPARE`, `DROP TEMPORARY` (MySQL) and `DROP POLICY`. Multi-word kinds are named (EVENT TRIGGER, FOREIGN TABLE, …). `ALTER TABLE t DROP identity/expression` is held, because it drops a column with that name; only `ALTER [COLUMN] c DROP DEFAULT/NOT NULL/IDENTITY/EXPRESSION` is treated as harmless. MySQL `ALTER TABLE … TRUNCATE PARTITION` is held. **DROP POLICY stays unheld because an existing test says "not data-destroying"; the audit calls it security-relevant. Needs a maintainer decision.** |
| M6 deadlines / shutdown | fixed except the connection cap | 30 s handshake deadline (pg startup and upstream TLS; mysql greeting and login). `Options.IdleTimeout` (default `DefaultIdleTimeout` = 8 h) for client reads. `Server.Close()` closes every session, and a held statement then ends "client went away". |
| M7 forced SSLRequest | fixed | Covered by the C1 login check. |
| L7 | partly | `… FOR UPDATE` is no longer flagged. `WHERE TRUE` / `1=1` still passes (a design limit). |
| L9 | fixed | At most 4 SSL/GSS negotiation rounds. |
| L1–L5, L6 (200-rune statement text), L8 | not addressed | Outside the decided scope. L6 is reduced: every target is listed now. |

## Needs cross-package change (cmd/twokey, Engineer B)

1. `cmd/twokey/cmd_pg.go`: extend `dbServer` with `Close() error` and call `srv.Close()` on shutdown,
   next to `broker.DenyAll`, so open sessions end.
2. The `holds` banner line in cmd_pg.go should mention `MERGE … DELETE` and uninspectable SQL
   (DO, CALL, COPY … PROGRAM, dynamic EXECUTE/PREPARE).

## API (backward compatible)

- sqlclass: `Classify` and `ClassifyMySQL` are unchanged (they wrap the new
  `ClassifyDialect(sql, Postgres|MySQL)`). New: `Dialect`, `KindUninspectable`, `MaxInspect`,
  and `Finding.Reason`.
- sqlhold: `Check` is unchanged. New: `CheckContext` and `WatchClient`. Uninspectable findings set
  `Request.Uninspectable` and `audit.Entry.Uninspectable`, so grants and allow rules never cover
  them. The rule id is `<provider>.uninspectable`.
- pgguard/myguard: new `Options.IdleTimeout`, `DefaultIdleTimeout`, `Server.Close`. myguard's
  `clearSSLCapability` was renamed `hideCapabilities` (it is unexported).

## Tests added

- `sqlclass/bypass_test.go` covers every lexer bypass, safe look-alikes, nested statements,
  uninspectable cases, multi-target, the H4 length sweep (2..4096, both dialects), and the
  wrappers.
- `sqlclass/fuzz_test.go`: `FuzzClassifyPostgres` and `FuzzClassifyMySQL`.
- `sqlhold/hold_test.go`: allow must cover every target; uninspectable is never allowed; a hold
  ends when ctx ends.
- `pgguard/hardening_test.go`: no preallocation, batch order, pipeline order, approval path,
  disconnect during a hold, panic recovery, idle timeout, Close, the startup loop bound, a 65 MiB
  row. The fake server in `proxy_test.go` now follows extended-protocol error semantics.
- `pgguard/fuzz_test.go`: `FuzzReadMessage`.
- `myguard/guard_test.go` (fake MySQL server): greeting hides SSL/compress/zstd; login asking for
  compress/zstd/ssl is refused before upstream; holds; no preallocation; disconnect during a hold;
  panic recovery; idle timeout and Close.
- `myguard/fuzz_test.go`: `FuzzReadPacket`.
- `ca/ip_constraints_test.go`: a leaf signed with the CA key for an IPv4 or IPv6 address fails
  verification; `LeafFor`/`Permits` refuse IPs; DNS leaves still work.

## Fuzz results (30 s each, 16 workers, no crashers, nothing under testdata/fuzz)

- FuzzClassifyPostgres: 4.04M execs. FuzzClassifyMySQL: 6.82M execs.
- The oracle: for any input s, `s + "\n;DROP TABLE t"` is never classified safe. The newline ends
  a line comment and `;` ends a statement, so the appended statement is code unless s leaves a
  literal, identifier, dollar body or block comment open, and that case must be reported as
  uninspectable. The fuzzer also checks the classifier is deterministic and never panics.
- FuzzReadMessage: 330k execs. FuzzReadPacket: 485k execs. Both check no panic, that the payload
  length equals the header, and that no more bytes are returned than were received.

## User-visible changes (for CHANGELOG/README; the README database section is updated)

- More SQL is held: nested or wrapped destructive statements, MERGE … DELETE, every DROP kind
  except PREPARE, TEMPORARY and POLICY, `ALTER TABLE … TRUNCATE PARTITION`, `ALTER TABLE t DROP
  identity`.
- New holds marked UNINSPECTABLE: DO, CALL, COPY … PROGRAM, dynamic PREPARE/EXECUTE, untokenizable
  SQL (for example an unterminated literal), and statements over 1 MiB.
- A Postgres plain string containing a backslash is read both ways, which can add holds (false
  positives only).
- Allow rules are all-or-nothing per statement.
- The MySQL guard refuses clients that request compression or TLS on the local hop.
- A denied Postgres statement now gets the server's own error handling: it aborts an open
  transaction, as a real permission error does.
- Idle client connections close after 8 hours.
- A hold ends as soon as the agent disconnects.
- New name-constrained CAs exclude all IP addresses. Constrained CAs (new and existing) no longer
  mint certificates for IP-literal hosts, so custom rules on IP hosts get 502 from intercept.

## Concerns

- **Not verified live (CLAUDE.md requirement):** whether Windows, macOS and Linux trust stores and
  clients such as curl, Node and Python accept a root with IP-excluded name constraints. Run a
  Go-launched check with a throwaway TWOKEY_HOME after `twokey ca reset`. Existing CAs get the IP
  exclusion only after a reset or rotation.
- Multibyte client charsets whose trailing byte can be 0x5C or 0x27 (GBK, SJIS, Big5) can still
  make the lexer disagree with the server. UTF-8 and latin1 are fine.
- `EXPLAIN` without ANALYZE of a DELETE or UPDATE without WHERE is held, which fails closed.
- A CREATE TABLE column named `update` or `delete` followed by SET/FROM-like tokens could be a
  false positive.
- The approval package's display falls back to "unknown resource" for uninspectable matches;
  Terminal shows the reason on its UNKNOWN line.
- No connection-count limit.
- The tooling hook reported the shared session cost at about $97 during this work.
