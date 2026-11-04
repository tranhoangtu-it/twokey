# Changelog

All notable changes to twokey. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/) — see [docs/compatibility.md](docs/compatibility.md)
for what counts as a breaking change.

## [Unreleased]

A production-hardening release: three independent security audits (proxy/rules, approval/CLI,
database guards/CA), every finding reproduced with a failing test and fixed.

### Changed (you may notice)
- **`.twokey-allow.yaml` must be trusted before it is used.** Run `twokey allow trust` after
  reviewing it; a changed file is ignored again until re-trusted. An agent (or a cloned repo) can
  write that file, so it could previously pre-approve operations for future sessions.
  `--allow FILE` counts as trust; `twokey allow revoke` forgets it.
- `resource: "*"` in an allow rule no longer covers requests whose resource is unknown.
- ntfy server must be `https://` (plain `http://` only for localhost); topics must be 16–64
  characters. Both are startup errors now.
- `--timeout` must be greater than 0 and at most 1h.
- More SQL is held: destructive statements inside `WITH`, `EXPLAIN ANALYZE`, `COPY (…)`, `MERGE`,
  `PREPARE` and routine bodies; `DO`, `CALL`, `COPY … PROGRAM` and dynamic `EXECUTE` are held as
  uninspectable. A Postgres string containing a backslash is read both ways (can add holds).
- MySQL clients that request protocol compression are refused (compressed packets were not
  inspected). Denied Postgres statements abort an open transaction, like a permission error.
- WebSocket upgrades on hosts with GraphQL/AWS/JSON rules are held.

### Security
- Require Go 1.26.10: builds with older toolchains included 20 reachable standard-library
  vulnerabilities (`net/http`, `crypto/tls`, `crypto/x509`, `net/url`, …).
- Proxy bypasses closed: malformed AWS form bodies, repeated `Action` values, `..`/`//` path
  segments, method-override headers, upgrades spliced before a `101`, allow rules laundering
  undecodable bodies, held requests forwarded after the agent left (watcher stopped after 60 s).
- SQL bypasses closed: Postgres `E''` strings hiding later statements, MySQL `/*! … */`
  executable and non-nesting comments, nested destructive statements, multi-object `DROP` where
  an allow rule covered only the first object; a classifier panic on some inputs.
- Timed grants also bind to a digest of the request body and query.
- Name-constrained CAs created from now on exclude all IP addresses (`twokey ca reset` to get one).
- `approval.Clean` also neutralizes zero-width and Unicode tag characters; `notify-send` text is
  markup-escaped; the ntfy topic is redacted from logs and banners.

### Added
- `twokey allow trust|revoke`.
- Releases are signed (keyless Sigstore bundle for `checksums.txt`), carry GitHub build-provenance
  attestations and an SPDX SBOM per archive; README explains how to verify.
- After every release, CI installs twokey through brew, scoop and `go install` and runs it; a broken
  channel opens an issue.
- CI: gofmt, staticcheck, govulncheck, fuzzing (rules, GraphQL, AWS, paths, SQL, wire readers),
  CodeQL and OpenSSF Scorecard; all actions pinned by commit SHA.
- Docs: architecture, 1.x compatibility promise, agent status, configuration reference, runbook,
  code of conduct. Rule-engine benchmarks.

### Fixed
- Homebrew and Scoop publishing read the `HOMEBREW_TAP_TOKEN` secret that the repository actually has.
- Resource limits: at most 100 pending holds (overflow denied as `overload`), request heads over
  1 MiB rejected, GraphQL expansion capped, database buffers grow only as bytes arrive, idle
  tunnels and database connections time out, per-connection panic recovery in the guards.
- The audit log rotates at 20 MiB (keeps 3); `twokey log` streams it; denials at shutdown are
  logged before the log closes; database guards close their connections on shutdown.
- The 403 text states the real reason (timeout, overload, shutdown, agent gone, human).
- An empty `ntfy-topic` file no longer crashes phone mode with infinite recursion.
- The `--strict` gateway image is pinned by digest and removed when the agent exits.

## [0.6.2] - 2026-11-04
### Fixed
- Windows: remove certificates from the Root store with `certutil` and verify they are gone.

## [0.6.1] - 2026-11-04
### Added
- `twokey ca untrust --retired` removes only CAs replaced by a rotation.

## [0.6.0] - 2026-11-04
### Added
- 126 fixture-verified rules across 31 providers.
- `json:` matcher: hold calls that differ from routine ones only in a body field.

## [0.5.0] - 2026-11-04
### Added
- `twokey setup` one-command onboarding; `twokey uninstall` and `ca untrust`.
- Rule fixtures for every builtin rule and `twokey rules test`; observe mode; `twokey log`.
- Timed approvals (`approve N --for 15m`) and desktop notifications.
- Railway backup restore, scheduled project/workspace deletes, DigitalOcean bulk deletes, GCP
  regional disks, MongoDB Atlas Flex clusters.
### Security
- Protected single-entry DACL on the CA key on Windows; timed approvals bound to the exact request.

## [0.4.0] - 2026-11-04
### Added
- MySQL upstream TLS; `--upstream-tls-skip-verify` for both database guards.
- Hetzner, Linode, Vultr, Upstash, Cloudflare Pages rules.

## [0.3.0] - 2026-11-04
### Added
- `--strict` mode (Docker, internal network, gateway only), MySQL guard, 8 more providers.

## [0.2.0] - 2026-11-04
### Added
- Postgres guard, JVM support, `.twokey-allow.yaml` allow rules.

## [0.1.1] - 2026-11-03
### Fixed
- Schannel curl on Windows accepts local-CA certificates (revocation best effort).

## [0.1.0] - 2026-11-03
### Added
- Selective-MITM proxy that holds destructive requests; protocol-aware rule engine (REST,
  GraphQL, AWS); name-constrained local CA; terminal and ntfy approvals; `up`, `run`, `env`,
  `doctor`, `replay`, `explain`, `rules`, `ca`.

[Unreleased]: https://github.com/tranhoangtu-it/twokey/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/tranhoangtu-it/twokey/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/tranhoangtu-it/twokey/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/tranhoangtu-it/twokey/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tranhoangtu-it/twokey/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tranhoangtu-it/twokey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tranhoangtu-it/twokey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tranhoangtu-it/twokey/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tranhoangtu-it/twokey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tranhoangtu-it/twokey/releases/tag/v0.1.0
