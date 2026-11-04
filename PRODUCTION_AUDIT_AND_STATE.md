# Production audit & state (working file — folded into CHANGELOG/ARCHITECTURE at the end)

Branch: `feat/production-hardening` · started 2026-11-04 · design: `docs/superpowers/specs/2026-11-04-production-launch-design.md`

## What twokey is

Local CLI (Go, ~10.8k LOC, 5 direct deps). A selective-MITM HTTPS proxy + Postgres/MySQL wire guards
that hold destructive cloud/DB operations made by AI agents until a human approves (terminal or
phone via ntfy). Not a server/service: no listener beyond 127.0.0.1, no accounts, no database.

## Target shape (what "production-grade" means for this kind of tool)

- Fail closed everywhere; bounded memory/time on every input an agent controls.
- Releases built with a patched toolchain, signed, with provenance + SBOM; install channels that
  actually work and are smoke-tested after each release.
- Fuzz-tested parsers that decide hold vs pass; vuln + static analysis in CI.
- Documented stability contract (1.x), CHANGELOG, architecture doc, per-agent docs.

Out of scope by design: Dockerfile for twokey itself (it must run on the host to reach the OS
trust store and the user's terminal; `--strict` already builds its containers), metrics endpoint /
tracing (no long-running service to scrape; the audit log is the observability surface),
telemetry of any kind.

## Baseline (2026-11-04)

- `go vet` clean; `go test ./...` all pass.
- govulncheck: 20 called stdlib vulns (go1.26.2) → fixed by requiring go 1.26.10.
- staticcheck: 3× ST1018 in `internal/approval/observe_test.go`.
- Release secret mismatch: repo has `HOMEBREW_TAP_TOKEN`, workflow reads `TAP_GITHUB_TOKEN`;
  `scoop-bucket` repo missing → brew/scoop install advertised in README does not work.

## Master checklist

- [ ] Phase 1: Core — toolchain/deps, config & flag validation, error handling (from audits)
- [ ] Phase 2: Security — audit findings (bypass, fail-open, injection, secret leakage)
- [ ] Phase 3: Resiliency — limits, timeouts, graceful shutdown, races (from audits)
- [ ] Phase 4: Observability — audit log robustness, `doctor`/`version` diagnostics
- [ ] Phase 5: Testing — fuzz targets for decoders/sqlclass/protocol readers, regression tests
- [ ] Phase 6: Packaging & docs — release pipeline (secret, signing, attestations, SBOM, smoke
      test), CI (govulncheck, staticcheck, CodeQL, pinned actions), README + ARCHITECTURE +
      compatibility + agents docs, CHANGELOG

## Audit results (2026-11-05, reports in plans/reports/audit-261104-2351-*.md)

- proxy/rules: 0 critical, 6 medium (AWS form decode fail-open, dot-segment paths, WebSocket
  upgrade uninspected, allow laundering decode failures, multi-Action, client watcher blind >60s).
- approval/CLI: 1 high (project allow file auto-trusted → agent can pre-approve future sessions),
  phoneTopic recursion, ntfy over http / topic leakage, grants ignore body, no audit rotation,
  unbounded pending holds, Clean misses zero-width/tag chars.
- DB guards/CA: MySQL compression bypass, Postgres E'' string hides statements, MySQL comment
  semantics, nested/opaque statements (CTE, EXPLAIN ANALYZE, DO, CALL), pre-read allocation DoS,
  CA name constraints allow IPs.
- Fixes in progress by three parallel implementers, one per scope (no shared files).

## Log

- Phase 1: go directive 1.26.0 → 1.26.10 (govulncheck: 0 called vulns). x/crypto v0.58.0 has 1
  uncalled vuln, fix only in an untagged pseudo-version → accepted. gofmt + staticcheck clean.
- Phase 6 (part): release pipeline signed/attested/SBOM + smoke tests; CI pinned + lint + fuzz;
  CodeQL + Scorecard; CHANGELOG backfilled; docs/architecture.md, docs/compatibility.md.
  goreleaser `check` + local snapshot build of all 6 targets verified; snapshot binary runs.
- Agents on this machine: Claude Code 2.1.318 only (native exe) → live-verify it at the end;
  others documented as untested.
