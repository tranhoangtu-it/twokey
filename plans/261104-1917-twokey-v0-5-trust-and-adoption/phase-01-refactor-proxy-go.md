---
phase: 1
title: "Refactor proxy.go"
status: pending
priority: P2
dependencies: []
effort: "S"
---

# Phase 1: Refactor proxy.go

## Overview
Split `internal/proxy/proxy.go` (664 LOC) by concern with zero behavior change, so later phases edit small focused files.

## Requirements
- Functional: identical behavior; exported API (`Options`, `New`, `ServeHTTP`, `HealthPath`) unchanged.
- Non-functional: each file < 300 LOC; no new dependencies.

## Architecture
- `proxy.go` — Options, Server, New, ServeHTTP, handleLocal, handleConnect, tunnel.
- `intercept.go` — intercept loop, clientWatcher, upgrade handling.
- `check.go` — handle, check (rules + allow + broker), bufferBody, decodeForInspection.
- `response.go` — writeResponse, hop headers, blockedResponse, jsonResponse, eofTracker, lingerClose.

## Related Code Files
- Modify: `internal/proxy/proxy.go`
- Create: `internal/proxy/intercept.go`, `check.go`, `response.go`
- Tests: `internal/proxy/proxy_test.go` (regression lock)

## Implementation Steps (TDD)
1. Lock behavior: `go test -race -count=5 ./internal/proxy/` green; add a characterization test for any uncovered path (plain-HTTP request to a watched host is held).
2. Move whole functions verbatim into new files.
3. `gofmt`, `go vet`, rerun `-race -count=5`.

## Success Criteria
- [ ] Every file in `internal/proxy` < 300 LOC
- [ ] Tests green before and after
- [ ] `go doc ./internal/proxy` output unchanged

## Risk Assessment
Accidental edit during move → move whole functions only; check `git diff --stat` (removed ≈ added).
