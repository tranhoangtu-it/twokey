# Changelog

All notable changes to twokey. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/) — see [docs/compatibility.md](docs/compatibility.md)
for what counts as a breaking change.

## [Unreleased]

### Security
- Require Go 1.26.10: builds with older toolchains included 20 reachable standard-library
  vulnerabilities (`net/http`, `crypto/tls`, `crypto/x509`, `net/url`, …).

### Added
- Releases are signed (keyless Sigstore bundle for `checksums.txt`), carry GitHub build-provenance
  attestations and an SPDX SBOM per archive.
- After every release, CI installs twokey through brew, scoop and `go install` and runs it; a broken
  channel opens an issue.

### Fixed
- Homebrew and Scoop publishing read the `HOMEBREW_TAP_TOKEN` secret that the repository actually has.

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
