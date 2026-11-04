# Fix report: internal/proxy + internal/rules (2026-11-05)

Input: `audit-261104-2351-proxy-rules-report.md`, plus two coordinator items. Every finding was reproduced
with a failing test first (RED), then fixed (GREEN). None were dropped.

## Findings

| # | Finding | Result | Test |
|---|---------|--------|------|
| 1 | AWS form/query with `;` or bad `%` skipped (fail-open) | Fixed: decode error on a host with AWS rules => Uninspectable | `TestAWSMalformedFormIsUninspectable` |
| 5 | AWS: body overrode query, first Action / first X-Amz-Target won | Fixed: every Action (query + body, repeated) and every X-Amz-Target value is evaluated; a parameter with conflicting values gives an unknown resource | `TestAWSEveryActionValueIsEvaluated`, `TestAWSAmbiguousParameterIsUnknownResource` |
| 2 | Dot segments not resolved | Fixed: rules are evaluated on the raw path and on `path.Clean` of it; a match on either holds | `TestDotSegmentsAreResolved` |
| 10 | Path variables decoded twice (`%252F` -> `/`) | Fixed: `Request.Path` is documented as decoded; templates no longer unescape | `TestPathVariablesAreNotDecodedTwice` |
| 7 | Method override ignored | Fixed: `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override` and `_method` (lenient parse) are extra effective methods | `TestMethodOverrideIsEvaluated` |
| 3 | Upgrade: no body inspection, raw splice without 101 | Fixed: an upgrade on a host with body rules is held as Uninspectable; splicing happens only after the upstream answers 101, otherwise the answer is relayed and later requests on the connection are inspected | `TestUpgradeOnBodyRuleHostIsHeld`, `TestUpgradeRefusedByUpstreamKeepsInspecting` |
| 4 | Decode failure laundered by allow rules | Fixed: a decode error on a body-rule host is always Uninspectable, before allow rules run | `TestUndecodableBodyIsHeldEvenWhenAllowed` |
| 6 | 60s body read deadline blinded the disconnect watcher | Fixed: the watcher clears the read deadline when it starts. Body idle timeout is now a Server field so the test can shorten it | `TestClientDisconnectNoticedAfterBodyIdleTimeout` (100ms body deadline, 400ms hold) |
| 8 | GraphQL fragment fan-out (CPU DoS) | Fixed: at most 10,000 selections per operation and 100,000 flattened argument values (a large variable used by many fields). Going over either limit => Uninspectable | `TestGraphQLFragmentFanOutIsBounded` |
| 9 | No header size cap on intercepted requests | Fixed: 1 MiB (+4 KiB read-ahead) per request head. Over the cap, the proxy answers 431 itself, never forwards, and lingers briefly before closing | `TestOversizedRequestHeaderIsRejected` |
| 12 | No idle timeout on splices | Fixed: tunnels and upgraded connections close after 30 min with no traffic in either direction | `TestIdleSpliceIsClosed` |
| 11 | Allow glob without `(?s)`; `resource: "*"` covered unknown resources | Fixed: globs compile with `(?s)`; `Allowed` never covers an empty resource, which matches the CLAUDE.md invariant | `TestAllowGlobsSpanNewlinesAndNeverCoverUnknownResources`, updated `TestAllowRules` |

Not fixed (outside my files): server `IdleTimeout` and `srv.Close` leaving hijacked connections open are in
`cmd/twokey/proxy_runtime.go` (engineer B). There is still no global cap on concurrent 32 MiB body buffers.

Coordinator items:
- `check.go` passes `Fingerprint: approval.BodyFingerprint(evalBody, RawQuery)` to Decide. evalBody is the
  decoded body that was evaluated. On path-only hosts it is the body buffered at hold time, decoded the same
  way. Test: `TestTimedGrantIsBoundToTheBody`. `TestTimedGrantForwardsOnlyTheGrantedResource` now sets the
  fingerprint.
- `blockedResponse` wording now follows `Decision.By`: timeout, overload, shutdown, client, otherwise
  "denied by a human". The JSON shape and "Do not retry" are unchanged. Test: `TestBlockedMessageFollowsTheDecision`.
  I did not run these two tests against the old code first.

## Files changed

- rules: `rules.go` (Evaluate moved out, flattenBody trailing-data fix, Path doc), new `evaluate.go`,
  `aws_decoder.go`, `path_template.go`, `graphql_decoder.go`, `allow.go`.
- proxy: `check.go`, `intercept.go`, `proxy.go`, `response.go`.
- tests: `rules/hardening_test.go`, `rules/fuzz_test.go`, `rules/allow_test.go`, `proxy/hardening_test.go`,
  `proxy/fuzz_test.go`, `proxy/proxy_test.go` (harness `newHarnessOpts`; the WebSocket splice test now uses a
  path-only pack).
- regression seed: `internal/rules/testdata/fuzz/FuzzFlattenBody/7f0c098d1a999379`.

## Fuzzing (30s each, local)

FuzzEvaluate (372k execs), FuzzParseGraphQLBody (3.4M), FuzzParseAWSCall (4.6M), FuzzPathTemplateMatch (5.0M),
FuzzFlattenBody (1.5M, after the fix), FuzzAllow (845k), FuzzDecodeForInspection (1.3M). One crasher:
`flattenBody` accepted `""}` because `dec.More()` misses a stray `]`/`}`, so a JSON matcher could pass
malformed JSON as valid. Fixed: only a clean EOF may follow the value. The input is kept as a seed.

## Verification

gofmt clean for my packages. `go vet`, `go test -race -count=1 ./internal/proxy/... ./internal/rules/... ./cmd/...`,
the Fixture test and staticcheck 0.8.2 all pass. The new proxy tests passed 5 runs in a row under -race.
`go vet ./...` and `gofmt -l .` currently fail only on engineer C's in-progress sqlhold and pgguard files.

## User-visible changes (CHANGELOG)

- Requests are also evaluated after resolving `.`/`..` segments and under method-override headers or `_method`.
- AWS Query-protocol requests with an undecodable query or form body are held as uninspectable. Any destructive
  Action value among several is held.
- WebSocket and other upgrades to hosts with GraphQL, AWS or JSON-body rules are held as uninspectable. Upgrades
  the upstream refuses no longer turn the connection into an uninspected tunnel.
- Allow entries with `resource: "*"` no longer pre-approve matches whose resource is unknown. README/docs that
  describe the old behaviour need updating (not in my files).
- A body that cannot be decoded (e.g. `br`) on a host with body rules is held even if an allow rule matches.
- Intercepted request heads over 1 MiB get a twokey 431.
- Idle tunnels and upgraded connections close after 30 minutes.
- Timed grants are bound to the exact body and query.
- Blocked messages no longer claim a human denied requests that timed out, were rejected for overload, or were
  stopped at shutdown.

## Open notes

- AWS services that move to the Smithy RPCv2 CBOR protocol (operation in the URL path) would bypass Action rules.
  No current watched service uses it.
- Google's `$httpMethod` override is not handled; it was outside the agreed scope.
- Two rules have no `resource` template, so they can never be pre-approved now. This fails closed.
