---
phase: 3
title: "Rule fixtures and rules test"
status: pending
priority: P1
dependencies: [1]
effort: "M"
---

# Phase 3: Rule fixtures and rules test

## Overview
Every builtin rule gets a recorded example request plus a safe sibling, so a wrong host/path/mutation name is caught by CI instead of silently not holding. `twokey rules test` gives contributors the same check.

## Requirements
- Fixture: `internal/rules/testdata/<rule-id>.http` — raw HTTP request, header comment `# source: <official doc URL or CLI source>`, then `###` and a request that must NOT hold.
- Test: every rule in builtin packs has a fixture; held request matches exactly that rule id; safe request does not hold.
- CLI: `twokey rules test [--rules DIR] [--fixtures DIR]`; exit 1 on failure.
- Correct the previously unverified rules against official docs while writing fixtures.

## Architecture
- `internal/rules/fixture.go`: `ParseFixture`, `CheckFixtures(engine, dir) []Failure`.
- `cmd/twokey`: `rules test` wraps CheckFixtures.

## Related Code Files
- Create: `internal/rules/fixture.go`, `fixture_test.go`, `internal/rules/testdata/*.http` (one per rule)
- Modify: `cmd/twokey/main.go`, packs with corrected rules, `CONTRIBUTING.md`

## Implementation Steps (TDD)
1. Write `TestEveryBuiltinRuleHasPassingFixture` (red) and `TestParseFixture` cases.
2. Implement parser + checker.
3. Write fixtures per provider from official API references; fix rules that disagree.
4. Add `rules test` CLI + test; update CONTRIBUTING.

## Success Criteria
- [ ] 100% builtin rules have fixtures, enforced by test
- [ ] Each fixture cites a source
- [ ] `twokey rules test --rules ./sample` works on a user pack

## Risk Assessment
Docs drift / undocumented hosts → note uncertainty in `# source:`; prefer CLI source over blogs. Time-box per provider.
