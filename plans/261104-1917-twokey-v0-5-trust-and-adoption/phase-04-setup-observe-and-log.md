---
phase: 4
title: Setup observe and log
status: completed
priority: P1
dependencies:
  - 1
effort: S
---

# Phase 4: Setup, observe mode, log viewer

## Overview
Cut time-to-aha and make trying twokey risk-free: `twokey setup`, `--observe`, `twokey log`.

## Requirements
- `twokey setup [--yes] [--trust]`: ca init → prompt "Trust the twokey CA? [y/N]" (Windows/macOS) → create phone topic, print subscribe URL + terminal QR → doctor summary. Non-TTY/`--yes`: no prompts; trust only with `--trust`.
- `--observe` on `up`, `run`, `pg`, `mysql`: matches audited `by: "observe"`, forwarded; terminal prints `WOULD HOLD … (observe mode — NOT PROTECTED)`; banner shows mode.
- `twokey log [-n 20] [--provider P] [--denied] [--since 24h] [--json]` over `~/.twokey/audit.jsonl`.

## Architecture
- Observe = mode on `approval.Broker` (Decide returns approved, By "observe", after notifying printers) — single switch point, so HTTPS proxy and SQL guards get it via `proxy.check` / `sqlhold`.
- QR: `rsc.io/qr` (small, BSD) rendered with half-block characters.
- `cmd/twokey/log.go`: streaming JSONL reader + filters.

## Related Code Files
- Modify: `internal/approval/broker.go`, `cmd/twokey/proxy_runtime.go`, `cmd_pg.go`, `serve.go`, `main.go`
- Create: `cmd/twokey/setup.go`, `cmd/twokey/log.go`, tests

## Implementation Steps (TDD)
1. Tests first: `TestObserveModeForwardsAndAudits` (proxy: DELETE reaches upstream, audit by=observe); `TestBrokerObserve`; `TestLogFilters` (fixture JSONL); `TestSetupNonInteractive` (temp TWOKEY_HOME, `--yes` → CA + topic exist, no trust command run).
2. Implement.
3. Live: fresh home → `twokey setup --yes` → `twokey run --observe -- <probe>` forwarded → `twokey log` shows OBSERVED.

## Success Criteria
- [ ] Fresh home reaches first hold in 2 commands
- [ ] Observe never blocks, always audits
- [ ] `log` filters correct; `--json` round-trips

## Risk Assessment
Observe left on by accident → banner + every line says NOT PROTECTED; `doctor` reports mode.
