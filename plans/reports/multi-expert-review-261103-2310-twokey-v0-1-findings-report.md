# twokey v0.1 — multi-expert review (2026-11-03)

Reviewers (read-only, independent): HTTP/TLS proxy · red team · Go concurrency · cloud API rule packs · DX/OSS launch.
Baseline: commit 8f1d0fa, `go vet` clean, `go test -race` green.

## P0 — fix before anyone uses it
| # | Finding | Where | Source | Status |
|---|---|---|---|---|
| 1 | ntfy topic leaks to the agent: `TWOKEY_NTFY_TOPIC` passes through `twokey run` env; topic also in `up` argv → agent can subscribe, read nonce, self-approve | cmd/twokey/serve.go, internal/runenv/env.go, internal/approval/ntfy.go | red team + DX | CONFIRMED (code) |
| 2 | Coverage gap: DynamoDB account endpoints `<acct>.ddb.<region>.amazonaws.com` not watched | packs/aws.yaml | red team | CONFIRMED (`explain` exit 0) |
| 3 | Coverage gap: Railway `/graphql/internal` not watched (rules pinned to `/graphql/v2`) | packs/railway.yaml | red team | CONFIRMED |
| 4 | Upload + early upstream response: keep-alive reuses conn while transport still reads body → bufio race / stream desync | internal/proxy/proxy.go (intercept loop) | proxy | CONFIRMED (code) |

## P1 — correctness
| # | Finding | Source |
|---|---|---|
| 5 | CA create race still possible: after taking lock, must re-check files exist; "incomplete CA" false error | Go |
| 6 | Legacy S3 hosts `s3-<region>`, `*.s3-<region>`, `s3-fips`, access points not watched | red team |
| 7 | False positive: S3 `DELETE /?policy|lifecycle|cors|website` held as bucket delete (query ignored) → need "empty query" matcher | red team |
| 8 | `github.graphql.delete` resource var wrong (`deleteIssue` uses `input.issueId`) | cloud API |
| 9 | AWS Query detection requires form Content-Type; gzip form body slips | red team |
| 10 | Connection-listed headers (`Connection: X-Foo`) forwarded | proxy |
| 11 | 304 with Content-Length / HEAD-204 unknown length framing; keepAlive computed before normalisation | proxy (PLAUSIBLE) |
| 12 | Tunnel + upgrade splice drop the other direction on half-close | proxy + Go |
| 13 | ntfy subscription: no idle watchdog, replay window ignores outage, backoff never resets | Go |
| 14 | bundle.pem non-atomic write; roots.pem downloaded once, unpinned | Go |
| 15 | Terminal: stale `deny <id>` falls back to the single pending request; >64KB stdin line kills input silently; unsanitized resource strings (ANSI/newline prompt spoof) | Go + red team |

## P2 — robustness / polish
- Idle deadline cleared after headers (slow body holds fd); leaf cache unbounded, host not lowercased.
- `ExitCode()` -1 on signal; shutdown doesn't drain hijacked conns; audit close while handlers write.
- CONNECT bare IPv6 without port → `[[::1]]:443`; `req.Write` adds Go User-Agent on upgrade; `isUpgrade` reads first Connection line only.
- Clients ignoring proxy env (JVM, old Node, aws-sdk-js v3 without agent) → document + `JAVA_TOOL_OPTIONS`.
- Notifier goroutine ordering (Closed may print before Notify).

## Rule packs (cloud API expert)
- 33/47 OK against official docs, 1 WRONG (#8), 13 UNVERIFIED: railway.project.delete arg, github.ref/environment, rds snapshot, ec2 terminate, cloudformation, DynamoDB target prefix, DigitalOcean droplet/volume, Fly `api.machines.dev` host.
- `backboard.railway.app` likely stale (CLI uses `.com` only) — harmless to keep.
- Proposed new rules (doc-confirmed): railway `volumeInstanceBackupDelete`, vercel env delete, supabase branch reset, cloudflare KV namespace delete, aws Secrets Manager DeleteSecret, ECR DeleteRepository, Route53 DeleteHostedZone, github repo transfer, fly machine delete.

## Launch blockers (DX)
1. No prebuilt binaries; go.mod requires Go ≥1.26.2; deps marked `// indirect` (`go mod tidy` diff).
2. README overclaims "can't approve itself" (see #1); PocketOS story has no source link; `twokey env` on fresh home omits bundle vars.
3. ntfy topic regenerated each session → persist (`~/.twokey/ntfy-topic`, 0600) + QR/link.
4. Missing: demo GIF (vhs tape), CI (vet, race on 3 OSes, tidy check), goreleaser/brew/scoop, CONTRIBUTING (rule packs), SECURITY.md, cmd/twokey tests.
5. Error polish: friendly "nothing listening" message, distinct exit code, `replay` w/o args lists scenarios, `ca path` should not create a CA.
6. Consider single-terminal mode `twokey run --phone -- claude`.

## Verified OK by reviewers
Aliases/fragments/batches/GET/`@skip` GraphQL handling; fail-closed on persisted/gzip/multipart; trailing-dot + IPv6 normalisation; dial uses CONNECT target; Peek watcher + read-deadline safe; broker resolve/expire race safe; name-constrained CA + leaf params; no data races (`-race -count=3`).

## Unresolved
- Railway schema introspection (`projectDelete` arg); GitHub GraphQL input field names; DigitalOcean droplet/volume paths; DynamoDB X-Amz-Target prefix doc.
- Product decision: single-terminal phone-only mode? ntfy auth (self-hosted / access token) vs topic-as-secret?
