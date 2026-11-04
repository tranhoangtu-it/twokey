# twokey 1.0: production launch — design

Status: draft for maintainer approval · 2026-11-04

## Intent

twokey works (v0.6.2: 126 rules / 31 providers, Postgres/MySQL guards, strict mode, CI + e2e on
Linux/macOS/Windows) and the repo is already public. What is missing is a **launch**: a stranger
should find it, install it with one command, see it hold a real destructive call, and trust it
enough to leave it on while an agent holds production credentials. "Production-ready" here means
that path works without the maintainer's help, and that releases are stable and verifiable.

## Who it is for

A solo developer or small team running coding agents (Claude Code, Cursor agent, Codex, Aider,
opencode) with real credentials: Railway, AWS, GitHub, Vercel, a production Postgres. They have read
about the April 2026 PocketOS wipe, or nearly had one of their own. They find twokey from a Show HN /
Reddit (r/ClaudeAI, r/cursor) / X post whose hook is the `replay pocketos` demo.

## The first 10 minutes (the acceptance path)

1. Install with one line: `brew install --cask tranhoangtu-it/tap/twokey`, `scoop install twokey`,
   or `go install …@latest`, never a manual download.
2. `twokey replay pocketos`: sees the hold without any setup.
3. `twokey setup`: CA, optional phone, runtime check, told exactly what was changed on the machine.
4. `twokey run -- claude` (or their agent) on a real project; `twokey doctor` says what is covered.
5. The first real hold is approved or denied in the terminal or on the phone, and the agent gets a
   clear answer.
6. If they don't like it, `twokey uninstall --purge` leaves no certificate or files behind.

Success = every step works as the README says on clean Windows, macOS and Linux machines, verified
live (not only in unit tests, per the v0.6.1 lesson).

## Goals

### G1. Install works as advertised
Today the README advertises brew and scoop, but neither works: the repo secret is named
`HOMEBREW_TAP_TOKEN` while `release.yml` reads `TAP_GITHUB_TOKEN`, and `scoop-bucket` does not exist.
- Make the workflow read the secret that exists (`HOMEBREW_TAP_TOKEN`) for both brew and scoop, and
  rename the env var in `.goreleaser.yaml` comments to match. *(builder's call: rename in code rather
  than ask the maintainer to recreate the secret)*
- The maintainer creates `tranhoangtu-it/scoop-bucket` (public, empty) and makes sure the token has
  `contents:write` on both tap repos.
- Add a post-release CI job that installs from each channel (brew on macOS + Linux, scoop on
  Windows, `go install` everywhere) and runs `twokey version` and `twokey replay pocketos`. Brew and
  scoop can only install a release that is already public, so this job **alarms, it does not gate**:
  on failure the job fails and opens a GitHub issue labelled `release`; the fix is a patch release.
  No staging tap or rc promotion. *(builder's call)*
- Windows install command stays `scoop bucket add twokey https://github.com/tranhoangtu-it/scoop-bucket`
  then `scoop install twokey`; getting into ScoopInstaller/Extras is not a 1.0 goal. *(builder's call)*
- Package-manager uninstall: goreleaser's cask hooks moved to a new DSL (v2.19) that could not be
  verified without a Mac, and scoops has no pre-uninstall hook, so no hook ships. The cask caveats
  and the README runbook say to run `twokey uninstall` before `brew`/`scoop uninstall`.
  *(builder's call, revised during implementation)*

### G2. Verifiable releases
- GitHub artifact attestations (`actions/attest-build-provenance`) for every archive and
  `checksums.txt`, plus cosign keyless signing of `checksums.txt` via goreleaser `signs:`.
- SBOM per archive (goreleaser `sboms:` with syft).
- README "Verify a download" section: `gh attestation verify` and the cosign command.
- macOS notarization: **out of scope** for 1.0 (needs a paid Apple Developer account); keep the
  `xattr` note. The brew cask should strip quarantine itself (goreleaser `hooks.post.install`) so
  brew users never hit Gatekeeper.

### G3. A stability promise (v1.0.0)
Write `docs/compatibility.md` listing what 1.x will not break without a major version:
CLI commands and flags, exit codes (0/2/125), rule YAML schema and matcher syntax, `.twokey-allow.yaml`,
`audit.jsonl` fields, environment variables `run` sets, `~/.twokey` layout, the 403 JSON body shape.
Rule packs may *add* rules in minor releases (and so rotate the CA, as today); removing or loosening
a builtin rule is a breaking change. Add `CHANGELOG.md` (Keep a Changelog format), backfilled from
v0.5.0, and make goreleaser's release notes point to it. The maintainer tags v1.0.0 when G1–G6 are
done; G7 (launch kit) is prepared alongside and used after the tag.

### G4. Security hygiene a security tool is judged by
- `govulncheck` and CodeQL (Go) in CI; OpenSSF Scorecard workflow + badge.
- Pin GitHub Actions by commit SHA; least-privilege `permissions:` per job.
- Go native fuzz tests for the parsers that decide hold vs pass: GraphQL decoder, AWS
  Query/`X-Amz-Target` decoder, `json:` body matcher, `sqlclass`, path templates. Fuzz targets
  assert invariants (no panic; malformed input on a watched endpoint ⇒ uninspectable/held, never
  silently allowed). Run each for a short time in CI; longer locally.
- Branch protection on `main` (required CI checks, no force push): maintainer action, documented.

### G5. First-run polish found by walking the path
Walk the 10-minute path live on Windows (this machine), and on macOS/Linux via CI runners or a
throwaway VM, with a throwaway `TWOKEY_HOME`. Fix every point of friction found (unclear message,
missing hint, wrong README command). Known candidates to check, not presumed bugs:
- `setup` explains what it changes and how to undo it.
- `doctor` output reads as an actionable checklist.
- Messages when the agent binary is not found, port is taken, Docker missing for `--strict`.

### G6. Docs that answer "will it work with my agent"
- `docs/agents.md`: one short section per agent (Claude Code, Cursor agent, Codex CLI, Aider,
  opencode, plain scripts), stating the exact command and any runtime caveat (Node version, Go tools
  needing `ca trust`). Only list what was verified; mark the rest "untested".
- `docs/threat-model.md`: move the README threat model there at full length; keep a short README
  summary with the link. README stays the landing page; no separate docs site.
- `docs/rules.md`: writing your own rules (moved from README detail), linking `CONTRIBUTING.md`.

### G7. Repo presentation and launch kit
- Repo topics, homepage URL, Discussions enabled (Q&A + Ideas), `CODE_OF_CONDUCT.md`
  (Contributor Covenant), social preview image.
- Demo GIF rendered from the existing `demo.tape` (vhs) and embedded at the top of the README.
- `docs/launch/`: drafts of a Show HN post, one Reddit post, one X thread, written for the persona
  above and honest about the threat model. **The maintainer posts them**; nothing is posted
  automatically.

## Non-goals

- New providers or rules (welcome later; not a launch blocker).
- A hosted service, account, dashboard, or telemetry of any kind.
- A docs website, GUI, or IDE extension.
- Kubernetes interception, HTTP/2 between agent and twokey, Docker Hub rules.
- Windows code signing / macOS notarization (cost; revisit after launch).

## Anti-goals (would make this a failure even if it "works")

- Weakening any invariant in `CLAUDE.md` to smooth onboarding: fail-closed on uninspectable
  requests, `approval.Clean` for request-derived text, grants/allow never covering unknown
  resources.
- Marketing that implies twokey stops a malicious agent outside `--strict`.
- An install or uninstall path that leaves a trusted CA behind on someone's machine.
- Claiming an agent or platform works without having run it.

## Constraints

- Go 1.25, module `github.com/tranhoangtu-it/twokey`; `go vet ./... && go test -race ./...` and the
  e2e suite stay green on all three OSes.
- Tests first; conventional commits without AI attribution; one branch + PR per goal (or small
  group of goals); never push to `main`. The maintainer merges and tags.
- Use a throwaway `TWOKEY_HOME` for manual runs; never touch the maintainer's `~/.twokey`.

## Maintainer actions (cannot be done from the repo)

1. Create public repo `tranhoangtu-it/scoop-bucket`; confirm `HOMEBREW_TAP_TOKEN` can write to it
   and to `homebrew-tap`.
2. Enable branch protection on `main` once the new CI checks exist.
3. Upload the social preview image (GitHub has no API for it).
4. Tag v1.0.0, then post the launch drafts.

## Order

G1 → G2 (both touch the release pipeline; ship as a v0.7.0 release to prove the channels) →
G4 → G5 → G6 → G3 (compatibility doc + CHANGELOG written last, describing what actually shipped)
→ maintainer tags v1.0.0 → G7 launch posts. G7 repo-presentation items can land any time.

## Left to the builder

PR boundaries, fuzz corpus contents and CI fuzz duration, exact wording of docs and launch drafts,
which friction fixes from G5 are worth making (each must be small and tested), Scorecard findings
that are cheap to fix vs. documented as accepted.
