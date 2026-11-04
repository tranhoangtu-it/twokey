---
phase: 6
title: "Packaging docs and release"
status: pending
priority: P2
dependencies: [2, 3, 4, 5]
effort: "S"
---

# Phase 6: Packaging, docs, release

## Overview
One-command install on every OS and a release documenting the new trust story.

## Requirements
- goreleaser `brews` → `tranhoangtu-it/homebrew-tap`, `scoops` → `tranhoangtu-it/scoop-bucket`, via `TAP_GITHUB_TOKEN`; `skip_upload: auto` until secret exists.
- README: install (brew, scoop, go install, binaries); Quick start = `twokey setup` → `twokey run --phone -- claude`; sections for observe, log, timed approvals, desktop notifications, uninstall.
- SECURITY.md: uninstall + key ACL. CONTRIBUTING.md: fixtures.
- v0.5.0 tag after PR merge (user merges).

## Related Code Files
- Modify: `.goreleaser.yaml`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`

## Implementation Steps (TDD)
1. Test first: add `goreleaser check` to CI; local `goreleaser release --snapshot --clean` produces archives + formula/manifest.
2. Configure brews/scoops; write docs.
3. User creates repos + secret, merges PR, tags `v0.5.0`.
4. Verify: assets published; `scoop install twokey` on Windows; `twokey version` = 0.5.0; doctor green.

## Success Criteria
- [ ] `goreleaser check` green in CI
- [ ] Formula + scoop manifest published on tag
- [ ] Scoop install verified live on Windows

## Progress (2026-11-04)
- Done: goreleaser `homebrew_casks` + `scoops` (skipped until `TAP_GITHUB_TOKEN` exists), CI `goreleaser check` job, README/SECURITY/CONTRIBUTING, PR #8.
- Waiting on maintainer: create the two repos + secret, merge PR #8, tag `v0.5.0`; then verify Scoop install.
- Local `goreleaser check` was blocked by the session's permission classifier; CI runs it instead.

## Risk Assessment
Missing token/repos → release job fails on taps; mitigated by `skip_upload: auto` and documented one-time setup.
