---
phase: 5
title: Desktop notifications and timed approvals
status: completed
priority: P2
dependencies:
  - 1
  - 4
effort: M
---

# Phase 5: Desktop notifications and timed approvals

## Overview
Less approval friction without weakening safety: desktop notification on hold; short, narrowly scoped timed approvals.

## Requirements
- Desktop notifier (default on, `--no-desktop`): Windows toast via PowerShell WinRT, macOS `osascript`, Linux `notify-send`. Best-effort goroutine, 5 s timeout, errors logged once, never blocks broker. Text passed as argv/env — never interpolated into script code.
- Timed approval: terminal `approve <id> <confirm> --for 15m` (max 1h) → grant {rule id, exact resource, expiry}. Later holds with same rule id AND identical non-empty resource auto-approve `by: "grant"`, audited. Never for uninspectable or empty resource. `grants` lists, `revoke <n>` removes. In-memory only.

## Architecture
- `internal/approval/desktop.go` + `desktop_windows.go`, `_darwin.go`, `_linux.go` implementing `Notifier`.
- `internal/approval/grants.go`: mutex-guarded `Grants` with `Match/Add/List/Revoke`, injectable clock; Broker.Decide checks grants first.

## Related Code Files
- Create: `internal/approval/desktop*.go`, `grants.go`, tests
- Modify: `internal/approval/broker.go`, `terminal.go`, `cmd/twokey/proxy_runtime.go`

## Implementation Steps (TDD)
1. Tests first: `TestGrantMatchesExactRuleAndResource`, `TestGrantExpires` (fake clock), `TestGrantNeverCoversUninspectableOrEmpty`, `TestGrantMaxDuration`, `TestTerminalApproveFor`, `TestDesktopNotifierNeverBlocks`, `TestDesktopArgsNotInterpolated`.
2. Implement grants, terminal parsing, notifiers.
3. Live Windows: hold → toast; `approve 1 res --for 5m` → identical request auto-approved, audit by=grant.

## Success Criteria
- [ ] Grants exact-scoped, ≤ 1h, audited, in-memory
- [ ] Notifier cannot stall holds; no injection path
- [ ] Toast verified live on Windows

## Risk Assessment
- Over-approval → exact match, short TTL, visible `grants`, audit.
- WinRT toast unavailable on some builds → silent fallback, logged once.
