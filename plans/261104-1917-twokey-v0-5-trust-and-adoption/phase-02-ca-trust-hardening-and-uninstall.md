---
phase: 2
title: "CA trust hardening and uninstall"
status: pending
priority: P1
dependencies: [1]
effort: "S"
---

# Phase 2: CA trust hardening and uninstall

## Overview
A tool that installs a root CA must protect the key on every OS and remove itself cleanly. Adds Windows ACL on `ca-key.pem`, `twokey ca untrust`, `twokey uninstall [--purge]`.

## Requirements
- Windows `ca-key.pem`: inheritance removed, current user only (`icacls`); Unix 0600 (existing).
- `twokey ca untrust`: remove every cert twokey created (current `ca.pem` + all `ca.old*.pem`) by **SHA-1 thumbprint**, never by subject name. Windows `certutil -user -delstore Root <tp>`; macOS `security delete-certificate -Z <sha1>`; Linux prints instructions.
- `twokey uninstall`: untrust + remove `twokey-gw-*` containers and `twokey-strict` network (if Docker reachable); `--purge` deletes `~/.twokey`. Idempotent, prints what it removed.
- Rotation keeps history: `ca.old.<unix>.pem` so all past CAs are untrustable.

## Architecture
- `internal/ca`: `Thumbprints(dir)`, `restrictKeyACL(path)` (windows file; no-op elsewhere), rotation naming.
- `cmd/twokey/uninstall.go`: `cmdUninstall`, `untrustAll` with injectable command runner.

## Related Code Files
- Modify: `internal/ca/ca.go`, `cmd/twokey/main.go`, `cmd/twokey/serve.go` (doctor ACL check), `README.md`, `SECURITY.md`
- Create: `internal/ca/acl_windows.go`, `internal/ca/acl_other.go`, `cmd/twokey/uninstall.go`, tests

## Implementation Steps (TDD)
1. Tests first: `TestThumbprintsIncludeRotatedCAs` (rotate twice → 3 thumbprints); `TestUntrustBuildsExactCommands` (fake runner, thumbprint-only argv); `TestUninstallIsIdempotent`; Windows-only `TestKeyACLRestricted`.
2. Implement until green.
3. Live: `twokey ca trust` → `certutil -user -store Root` shows twokey → `twokey uninstall` → none remain.

## Success Criteria
- [ ] New tests green with `-race`
- [ ] Live: zero twokey certs in user Root store after uninstall
- [ ] `doctor` warns when key ACL is too open (Windows)

## Risk Assessment
- Deleting wrong cert → thumbprint match from files twokey wrote only.
- certutil may show a GUI confirm for user-store delete → document; run interactively.
