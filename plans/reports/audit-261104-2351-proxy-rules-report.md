# Audit: internal/proxy + internal/rules (read-only, 2026-11-04)

Scope: internal/proxy/*.go, internal/rules/*.go. Method: full read of each cited path; findings not
executed, so each Test is a sketch. Threat model: accidents by an agent running as the user.

No CRITICAL. Findings:

1. MEDIUM aws_decoder.go:36-43 - form body with any ParseQuery error (a `;` or bad `%` in any pair) is
   skipped entirely; action stays "" so no Match and no Uninspectable (fail-open).
   Test: Evaluate POST rds host, body `Action=DeleteDBInstance&DBInstanceIdentifier=prod&Note=a;b`, expect Hold().
   Fix: parse pair by pair; hold if Action undeterminable on a form-looking body.
2. MEDIUM check.go:59 + path_template.go splitPath - dot segments not resolved. `DELETE /v2/x/../droplets/1`
   does not match `/v2/droplets/{id}`; backends that normalise delete it.
   Test: match `/v2/droplets/./1`, `/v2/x/../droplets/1`. Fix: clean, evaluate raw and cleaned, hold on either.
3. MEDIUM intercept.go:60-64,132-156 - Upgrade: check() gets nil body (GraphQL hosts return errNoPayload,
   no hold), then raw splice with no 101 check. GraphQL mutations over WebSocket, or a following DELETE on a
   connection where upstream refused the upgrade, are never inspected.
   Test: fake upstream answers 200 to Upgrade GET; client then sends rule-matching DELETE; assert held.
4. MEDIUM check.go:57-73 - decErr sets Uninspectable only if !v.Hold(). A path-rule match that an allow entry
   removes launders an undecodable body (br/zstd/corrupt) on a host that also has body rules.
   Fix: set Uninspectable when decErr != nil && NeedsBody(host), before ApplyAllow.
5. MEDIUM aws_decoder.go:39-49 - body keys overwrite query keys; repeated Action uses first; X-Amz-Target
   uses first header value. `?Action=Describe...` + body `Action=Delete...` evaluates as Describe.
   Fix: match any candidate action.
6. LOW-MED intercept.go:67-70, response.go:74-77 - eofTracker leaves a read deadline of now+60s after the
   body; clientWatcher Peek times out, isTimeout() treats it as alive, goroutine exits. Holds longer than 60s
   on requests with bodies no longer notice client exit; check.go:91 sees ctx not cancelled and fires an
   approved request orphaned. Fix: clear read deadline when body hits EOF / at watcher start.
7. LOW rules.go:245 - X-HTTP-Method-Override, `$httpMethod` (Google APIs), `_method` ignored.
8. LOW graphql_decoder.go:133-160 - depth capped at 10, fan-out not: chained fragments each spreading the
   next 20 times is ~20^10 visits (CPU DoS). Fix: node budget -> error. (gqlparser caps nesting at 1000.)
9. LOW intercept.go:44 - http.ReadRequest has no header size cap (MaxHeaderBytes covers only the outer
   server); no limit on concurrent 32 MiB buffers. Unverified by run.
10. LOW path_template.go:30,38 - segments of already-decoded URL.Path are unescaped again (%252F -> /),
    so shown/allow-matched resource differs from what the server sees.
11. LOW allow.go:63 - no (?s): resource with newline never matches `*` (over-holds). allow.go:77 lets `*`
    cover unknown resources, contrary to the CLAUDE.md invariant wording.
12. LOW proxy.go:160, proxy_runtime.go:105-127 - no idle timeout on splices, no server IdleTimeout, srv.Close
    leaves hijacked connections.

Checked, no defect: trailing slash, //, literal case, %2F in variables (pack relies on decoded path), host
normalisation, smuggling (Go re-frames), gzip bomb cap, unsupported encodings, GraphQL aliases/fragments/
batches/variables/GET/persisted, JSON rule fail-closed, nil audit log, >32MiB held body -> 413.

Fuzz targets and invariants:
- Engine.Evaluate: no panic; GraphQL/AWS host + non-empty body no decoder accepts => Hold(); invariant under
  method case, host case/port/trailing dot.
- parseGraphQLBody: no panic, bounded time; every top-level mutation field found by an independent gqlparser
  walk is returned or err != nil; errNoPayload only for empty body without `query` param.
- parseAWSCall: form with Action=A plus junk pairs (`;`, lone `%`) yields A (catches 1).
- pathTemplate.match: no panic; match(p) == match(clean(p)) (catches 2); literals case-insensitive.
- decodeForInspection: no panic; len(out) <= maxInspectBody; error => caller holds.
- flattenBody/flattenJSON/flattenGraphQLValue: no panic; trailing data or non-JSON => error.
- expandResource: no panic; unknown placeholder => "".
- ParseAllow/Allowed/ApplyAllow: no panic; Uninspectable verdict unchanged; empty resource only by `*`.
- normalizeHost: idempotent. connectionTokens/removeHopHeaders: no named header survives.
- Differential: raw bytes -> http.ReadRequest -> Server.check with fake broker; a request matching a path
  rule after path.Clean is held or explicitly allowed.

Status: DONE
