---
title: twokey v0.5 — trust and adoption
description: >-
  Make twokey trustworthy and easy to try: clean uninstall, CA key ACL, verified
  rules, one-command setup, observe mode, log viewer, desktop notifications,
  timed approvals, packaging.
status: pending
priority: P1
branch: feat/v0.5
tags:
  - tdd
  - trust
  - dx
  - release
blockedBy: []
blocks: []
created: '2026-11-04T12:23:50.126Z'
createdBy: 'ck:plan'
source: skill
---

# twokey v0.5 — trust and adoption

## Overview
Source: [brainstorm report](../reports/brainstorm-261104-1917-twokey-v0-5-trust-and-adoption-report.md).
Core is solid (v0.4: HTTPS proxy, pg/mysql guards, strict mode, 68 rules); adoption is ~0. This round
closes trust gaps and cuts time-to-aha. **TDD:** every phase writes failing tests first, then code,
then `go vet ./... && go test -race ./...` green before the phase is checked off.

Out of scope (YAGNI): remote rule-pack updates, web dashboard, team approvals, kubectl plugin, new protocols.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Refactor proxy.go](./phase-01-refactor-proxy-go.md) | Completed |
| 2 | [CA trust hardening and uninstall](./phase-02-ca-trust-hardening-and-uninstall.md) | Completed |
| 3 | [Rule fixtures and rules test](./phase-03-rule-fixtures-and-rules-test.md) | Completed |
| 4 | [Setup observe and log](./phase-04-setup-observe-and-log.md) | Completed |
| 5 | [Desktop notifications and timed approvals](./phase-05-desktop-notifications-and-timed-approvals.md) | Completed |
| 6 | [Packaging docs and release](./phase-06-packaging-docs-and-release.md) | Pending |

Order: 1 first (locks proxy behavior). 2–4 independent; 5 after 4 (both touch broker). 6 last. One branch `feat/v0.5` from origin/main.

## Acceptance (whole plan)
- Fresh machine → first held request in ≤ 2 commands (`twokey setup`, `twokey run …`).
- `twokey uninstall` leaves no twokey certificate in the Windows user Root store (verified live).
- Every builtin rule has a fixture; CI fails when one is missing.
- `go vet` clean, `go test -race ./...` green on ubuntu/macos/windows; release v0.5.0 published.

## Open questions
- Homebrew tap / Scoop bucket need two public repos (`tranhoangtu-it/homebrew-tap`, `tranhoangtu-it/scoop-bucket`) and a `TAP_GITHUB_TOKEN` secret — user must create (phase 6).
