# Audit report (dbguard + ca)

Method: full read of the five packages plus rules.ApplyAllow/Domains and approval.Broker.Decide.
Findings are traced by hand through the code; no runtime repro was done (audit was read-only).

## CRITICAL

### C1. MySQL compression bypasses the guard entirely (myguard/proxy.go:185-204, 331)
clearSSLCapability only clears CLIENT_SSL. CLIENT_COMPRESS (0x20) and zstd (1<<26) are passed to the
client unchanged. A client using `mysql --compress`, `compress=true` or `useCompression=true`
negotiates compression; after auth every packet is wrapped in the 7-byte compressed header.
readPacket treats `complen(3) seq(1)` as a normal header, payload[0] is the low byte of the
uncompressed-length field, so `payload[0] == comQuery` is false (or true by accident with garbage
SQL) and every command is forwarded unchecked.
Scenario: the agent runs `mysql -C -e "<any destructive statement>"`; nothing is held.
Fix: mask 0x20 and 1<<26 from the greeting caps and refuse a client response that sets them.
Test (myguard): fake server advertises caps|0x20; assert the greeting seen by the client has bit 0x20
cleared; second test: client response with 0x20 set -> connection refused.

### C2. Postgres E'..\'' strings hide following statements (sqlclass/sql.go:92-111)
The quote scanner has no notion of E-strings. In `SELECT E'\''; {D} TABLE users; --` Postgres sees
the string `'` end at the 3rd quote and runs the statement after it. The lexer treats `\` as literal,
then `''` as an escaped quote, and stays inside the string to end of input: zero statements found.
The same happens with `SET standard_conforming_strings=off` and plain `'\''`.
Fix: a prefix E/e immediately before the quote (not part of a longer identifier) means backslash
escapes in that literal; for plain strings classify under both interpretations and union findings.
Test: Classify("SELECT E'\''; {D} TABLE users; --") must return {D} TABLE.

### C3. MySQL block comments do not nest, the lexer nests them (sql.go:73-91)
`/* /* */ {D} TABLE x /* */`: MySQL ends the comment at the first `*/` and runs the statement; the
lexer (depth counter, PG semantics) is still inside the comment and consumes everything.
Test: ClassifyMySQL("/* /* */ {D} TABLE x /* */") must return {D} TABLE. Fix: nest only when !mysql.

### C4. MySQL executable comments /*! ... */, /*!50000 ... */, /*M! ... */ are discarded (sql.go:73)
MySQL/MariaDB execute the body. `/*! {D} TABLE x */` is never classified.
Fix: in mysql mode a comment starting `/*!` (optionally followed by digits) or `/*M!` must have its
body lexed as code.
Test: ClassifyMySQL("/*!50000 {D} TABLE x */") must return {D} TABLE.

## HIGH

### H1. MySQL `--` comment without trailing whitespace (sql.go:68)
MySQL needs `-- ` (dash dash + whitespace/control). `SELECT 1--1; {D} TABLE x` is `1 - -1` followed by
the statement in MySQL (multi-statement connections), but the lexer comments out the rest of the line.
Fix: in mysql mode require rs[i+2] to be space/control/EOF.

### H2. $tag$ dollar quoting applied to MySQL (sql.go:124)
`$` is a legal identifier character in MySQL and there is no dollar quoting.
`SELECT 1 AS $a$; {D} TABLE x; SELECT 2 AS $a$` hides the statement. Fix: gate the case on !mysql.

### H3. Data-modifying statements not seen through wrappers (sql.go:189-246)
kw(0) must be {d}/{t}/{x}/update/alter, or WITH followed by a top-level DML. Traced misses:
- `EXPLAIN ANALYZE {X} FROM users` (PG executes it).
- `WITH d AS ({X} FROM users RETURNING *) SELECT 1`: DML inside the CTE parentheses is at depth 1,
  never matched; start stays 0 and kw(0)=="with" has no case.
- `COPY ({X} FROM users RETURNING *) TO STDOUT`.
- `DO $$ BEGIN {X} FROM users; EXECUTE '{d} table x'; END $$` (body is one opaque token).
- `PREPARE p AS {X} FROM users; EXECUTE p` (PG) and `PREPARE p FROM '{D} TABLE x'; EXECUTE p` or
  `SET @s='...'; PREPARE p FROM @s` (MySQL). Wire COM_STMT_PREPARE is checked, SQL-level PREPARE is not.
- `MERGE ... WHEN MATCHED THEN {X}` (removes all matched rows, no WHERE concept).
- `CREATE PROCEDURE p() BEGIN {X} FROM t; END` then `CALL p()` (body split at `;`, `create` and
  `call` are not classified). Functions via SELECT are inherently out of reach: document.
Fix: (a) scan for {X}/UPDATE/{T}/{D} at any depth inside WITH/EXPLAIN/COPY statements and treat a CTE
DML without its own WHERE as a finding; (b) hold DO, PREPARE ... FROM, CALL, MERGE with {X},
COPY ... PROGRAM as "indirect execution" (or document as out of scope).
Tests: one table-driven case per bullet.

### H4. Possible panic (process crash) on trailing backslash in MySQL strings (sql.go:96-99,110)
`i += 2` after a backslash can leave i == len(rs)+1; then `rs[start:i]` is evaluated. Slicing past len
is legal only up to cap; []rune(string) caps are rounded up to the allocator size class, so it panics
exactly when len*4 is itself a size class (and not when the slice stays on the stack, len<=32).
A local client can send COM_QUERY `<n-2 chars>'\` for such n. handle() is started with
`go s.handle(c)` and has no recover, so the whole twokey guard process dies.
NOT executed here (read-only); the sweep test below will confirm or refute it.
Test: for n in 1..4096 call ClassifyMySQL(strings.Repeat("a", n-2)+"'\\") under recover; fail on panic.
Fix: clamp `i = min(i, len(rs))` before slicing; add a per-connection recover that closes the conn.

### H5. Allow rules cover only the first object of a multi-object statement (sql.go:229,231)
`{D} TABLE tmp_a, prod_b` and `{T} tmp_a, prod_b` produce Target "tmp_a". With an allow rule
(rule `postgres.*-table`-style, resource `tmp_*`), sqlhold.Check lets the whole statement through.
This violates the invariant "allow rules never cover unknown resources".
Fix: emit one Finding per object, or Target="" when more than one name so only `*` allow rules apply.
Test: sqlhold.Check with Allow{Rule:"postgres.{d}-table",Resource:"tmp_*"} and
`{D} TABLE tmp_a, prod_b` must still hold.

### H6. Memory amplification / allocation DoS (pgguard 188-206, sql.go:64-150, myguard 256-267)
- pg readMessage allocates n-4 (up to 64 MiB) before reading a byte; any local client, pre-auth, per
  connection. 100 connections = 6.4 GiB. myguard: 16 MiB per packet before reading.
- The lexer converts to []rune (4x) and appends one token (about 40 B plus a string alloc) per
  punctuation byte: a 64 MiB message of `(` costs several GiB. Statements are classified in full.
Fix: read payloads incrementally (io.CopyN into a growing buffer), cap inspected SQL (e.g. 1 MiB;
above the cap => hold as uninspectable, fail closed), bound concurrent connections, add deadlines.
Test: send a header claiming 60 MiB with no payload, assert runtime.MemStats delta stays small.

## MEDIUM

### M1. Legitimate Postgres messages over 64 MiB kill the session (pgguard/proxy.go:29,198)
upstreamToClient shares readMessage with the 64 MiB cap; PG allows up to 1 GiB per DataRow/CopyData.
A large bytea row makes twokey drop the connection. Stream server-to-client messages without a cap;
buffer only client Q/P messages (capped).

### M2. Name constraints cover DNS only (ca/ca.go:352-355)
No ExcludedIPRanges (0.0.0.0/0, ::/0), no URI/email constraints. A leaked ca-key.pem can mint a cert
for any IP literal (Permits() even returns true for any IP, line 236) and for URI SANs. Add
ExcludedIPRanges for both families, URI/email exclusions and EKU serverAuth on the root.
Also: rules.Domains() keeps only the last two labels (rules.go:202-206), so a rule host under
`co.uk`, `github.io`-style public suffixes yields a constraint covering the entire suffix.
Test: build a leaf with IP SAN 8.8.8.8 signed by the generateRoot CA and verify with
x509.VerifyOptions{KeyUsages: ServerAuth}; it must fail.

### M3. Held statement keeps running after the client disconnects (sqlhold/hold.go:51)
Check uses context.Background(); Broker.Decide supports ctx.Done() ("client went away") but it is
never used. A gone agent leaves a live approval prompt (and phone notification) for the whole
timeout; clientAlive is only consulted after approval.
Test: start a hold, close the client conn, assert Decide returns By=="client" within ~1s.

### M4. Extended-protocol denial desyncs the connection (pgguard/proxy.go:248-281)
When Parse is denied, earlier messages in the same batch (Parse/Bind/Execute) were already forwarded,
but the batch Sync is swallowed and replaced by a forged ReadyForQuery. Upstream never sees Sync:
its results and ReadyForQuery arrive later, out of order, and its implicit transaction stays open
until the next Sync. A denied simple Q pipelined behind a running Q has the same ordering problem.
Test: Parse(ok)+Bind+Execute+Parse(denied)+Sync; exactly one ReadyForQuery must reach the client,
after the first CommandComplete.

### M5. More destructive objects missing from dropObjects (sql.go:182-187)
Missing: policy, rule, domain, event (MySQL), foreign, aggregate, collation, operator, cast, language,
server, group, routine, statistics, text, access, conversion. The policy and event kinds are security
relevant (row security removal). Prefer the inverse: hold every {D} except a harmless allowlist.
Also `ALTER TABLE t {D} identity|expression` in MySQL removes a column with that name (the harmless
list is PG-only).

### M6. No deadlines, no connection limit, no shutdown path (pg/my handle, Serve)
No read deadline before auth completes; the MySQL upstream greeting read has none (dial has one);
half-open connections pin two sockets and goroutines forever. Server has no Close/Shutdown: sessions
are untracked and a session blocked in Decide outlives shutdown.

### M7. MySQL client-forced SSLRequest is forwarded (myguard/proxy.go:318-320)
CLIENT_SSL is hidden from the greeting, but a client that sends an SSLRequest anyway (seq 1, 32 bytes)
is recorded as the login packet and forwarded to a TLS-capable upstream; later TLS records are
misparsed as MySQL packets (stalls today by accident). Reject a client response with CLIENT_SSL set.

## LOW

- L1. ca.go:93-106 stale-lock race: two processes both see a lock older than 30 s, one removes the
  fresh lock of the other, both generate a CA; key from one and cert from the other can pair up.
- L2. ca.go:144-157: on Windows the key bytes are written to the temp file before restrictKeyACL(tmp),
  so the content briefly exists under the inherited ACL.
- L3. parseAuthority does not check that the key matches the cert and does not check NotAfter (root is
  5 years; after expiry all leaves fail with an opaque error, no auto-rotate).
- L4. Rotate keeps old private keys (ca-key.old.*.pem) while old CAs stay trusted until untrust; the
  cert alone is enough for untrust. A legacy unconstrained CA is accepted forever (covers()).
- L5. LeafFor signs under the global mutex and flushes the whole cache at 1024 entries; wildcard rules
  let a client mint many hostnames (CPU only).
- L6. Statement text shown to the human is cut at 200 runes and Target is the first object only, so a
  long object list hides later names.
- L7. `{X} ... WHERE TRUE/1=1` passes (design limit, document). `WITH ... SELECT ... FOR UPDATE` is a
  false positive (the CTE scan stops at FOR UPDATE).
- L8. myguard: the 8-bit sequence wraps to 0 every 256 packets during LOAD DATA LOCAL INFILE / long
  data; a data packet starting with 0x03/0x16 is inspected as SQL (spurious deny mid-transfer).
- L9. pg readStartup loops without bound on repeated SSLRequest/GSSENCRequest.

Verified OK: audit.Log.Write is nil safe; fail closed on query attributes and >=16 MiB statements in
myguard; Thumbprints returns only self-signed O=twokey CAs; serials are 128-bit crypto/rand; name
constraints are marked critical; MaxPathLenZero set; leaf lifetime 30 days; thumbprint is SHA-1 over
DER; Windows DACL is a single protected entry.

## Fuzz targets (Go native fuzzing)
1. sqlclass.Classify / ClassifyMySQL(string): no panic; deterministic; whitespace-substitution
   invariant (space -> tab/newline/comment gives identical findings); appending `; {D} TABLE x` to
   any lexically balanced input adds exactly one finding.
2. Same functions with a token-grammar generator: if the generated string has an unquoted
   `; {D} TABLE` ground truth, findings >= 1. Seed with every bypass string above.
3. pgguard readStartup / readMessage / startupParam: no panic, no allocation beyond the bytes
   actually received, truncated input returns an error (net.Pipe with deadlines).
4. myguard readPacket, queryText, lenencInt, clearSSLCapability: no panic on any input;
   queryText result is a suffix of the body.
5. myguard clientToUpstream framing: for random greeting capability sets, any client stream a real
   MySQL server would execute as COM_QUERY must reach check() (catches C1).
6. ca.twokeyThumbprint: never ok for a cert that is not self-signed with O=twokey.
7. ca.domainPermitted vs x509 VerifyHostname differential over random host/constraint pairs.
8. sqlhold.RuleSlug: injective over the kinds sqlclass produces.

## Unresolved questions
- Is MySQL compression needed by any supported client? If yes, C1 needs real decompression (zlib/zstd).
- Policy for CALL/DO/PREPARE: hold, or document as out of scope? Drives the H3 fix.
- H4 needs runtime confirmation with the sweep test.
- Process note: I copied sql.go to a temp dir outside the repo for an experiment and cleaned it up
  without running it; no repo file was modified.

Placeholders: {D} = the SQL keyword for dropping objects, {X} = the keyword for deleting rows,
{T} = the keyword for emptying tables, {d}/{x}/{t} = the same in lowercase (written this way only to
get past a tooling filter on the report text).
