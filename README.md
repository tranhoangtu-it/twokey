# twokey

[![ci](https://github.com/tranhoangtu-it/twokey/actions/workflows/ci.yml/badge.svg)](https://github.com/tranhoangtu-it/twokey/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/tranhoangtu-it/twokey)](https://github.com/tranhoangtu-it/twokey/releases/latest)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**A two-person rule for AI agents.** A local proxy that holds destructive cloud API calls
(`volumeDelete`, `DeleteDBInstance`, `DELETE /repos/…`) until a human approves them — in another
window or on your phone. Built for accidents: an agent can't approve its own request by mistake.
It is not a sandbox against a malicious agent ([threat model](#threat-model--read-this)).

```text
$ twokey replay pocketos --live

⏸  HOLD #1  POST https://backboard.railway.com/graphql/v2
   CRITICAL railway.volume.delete  operation=volumeDelete  resource="pg-data-prod"
            Deletes a Railway volume. This is the call behind the April 2026 PocketOS production wipe.
   → approve 1 pg-data-prod     |     deny 1
deny 1
   #1 DENIED by terminal (denied by human)
```

## Why

On April 25, 2026 a coding agent working on a *staging* task deleted PocketOS's production
database volume — and its backups — in about nine seconds
([report](https://abc7.com/post/rogue-ai-agent-cursor-goes-haywire-deletes-tech-companys-database/19008099/)).
It didn't run `rm -rf` or `DROP TABLE`. It made one HTTPS call to Railway's GraphQL API.

| Guard | Why it misses this |
|---|---|
| Bash hooks / command deny-lists | See the command string, not the effect. `curl`, a Python one-liner or an SDK call sails through. |
| SQL proxies | The deletion never touched SQL. It was a cloud control-plane API call. |
| "Block HTTP DELETE" egress rules | GraphQL mutations are all `POST`. |

twokey sits on the network path and **understands the protocols**: REST method + path,
GraphQL mutations (aliases, fragments, batches, GET), and AWS actions (`Action=` and
`X-Amz-Target`). Only hosts with rules are inspected; everything else — including your LLM API
traffic — is tunneled untouched.

## Try it in 5 seconds (no setup, no network)

```sh
twokey replay pocketos
twokey explain --method DELETE --url https://api.github.com/repos/acme/prod-api   # exit 2 = held
```

## Install

```sh
brew install --cask tranhoangtu-it/tap/twokey                                  # macOS / Linux
scoop bucket add twokey https://github.com/tranhoangtu-it/scoop-bucket && scoop install twokey   # Windows
go install github.com/tranhoangtu-it/twokey/cmd/twokey@latest                  # Go ≥ 1.26.10
```

or download a binary from [Releases](https://github.com/tranhoangtu-it/twokey/releases)
(Linux, macOS, Windows; amd64/arm64). The macOS binary is not notarized yet: if Gatekeeper blocks
it, run `xattr -d com.apple.quarantine "$(which twokey)"`.

### Verify a download

Every release archive has a GitHub build-provenance attestation, `checksums.txt` is signed with
Sigstore (keyless, by this repository's release workflow), and each archive ships an SPDX SBOM:

```sh
gh attestation verify twokey_<version>_linux_amd64.tar.gz --repo tranhoangtu-it/twokey
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/tranhoangtu-it/twokey/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Use it

```sh
twokey setup                  # once: local CA, phone approvals (scan the QR), runtime check
twokey run --phone -- claude  # or codex, cursor-agent, aider, opencode…
```

**Not sure yet? Observe first.** `twokey run --observe -- claude` holds nothing: it prints and
audits every call it *would* have held, so you can see what twokey catches in your real workflow.
Observe mode protects nothing — the banner says so.

**Two terminals, approve by typing** (plus the phone, if you want):

```sh
twokey up --phone             # terminal 1: proxy + approval prompt
twokey run -- claude          # terminal 2
twokey doctor                 # check that curl / python / node / go are covered
```

When the agent tries something destructive, the request **waits**. In the `twokey up` window you
approve by typing the resource name (`approve 1 pg-data-prod`); on your phone you get an
[ntfy](https://ntfy.sh) push with **Approve / Deny** buttons. Nobody answers within 2 minutes →
denied (`--timeout`, from 1s up to 1h). If the agent gives up while waiting, the request is dropped —
approving later does nothing. At most 100 requests wait at once; beyond that new ones are denied
immediately (`decided_by: overload`). The ntfy server must use `https://` (plain `http://` only for
`localhost`), and the topic must be at least 16 characters; twokey refuses to start otherwise and
never prints the full topic outside `twokey phone` / `twokey setup`.
A denied request returns `403` with a JSON body written for the model:

> twokey blocked a destructive request (denied by a human): railway volumeDelete on pg-data-prod.
> Do not retry, rephrase, or work around this request… ask the user to approve it or run it themselves.

A desktop notification pops up as well (Windows toast, macOS, `notify-send`; `--no-desktop` to
turn it off) — it only tells you something is waiting; approving still needs the terminal or phone.

**Doing the same cleanup several times?** `approve 3 pr-41-preview --for 15m` also pre-approves
*the identical operation* — same rule, same resource, same host or database and, for SQL, the same
statement — for up to an hour (`grants` lists them, `revoke <id>` removes one; they vanish when
twokey exits). Unknown resources and requests twokey could not read can never be pre-approved.
If the resource name itself ends in `--for <duration>`, typing it exactly approves once.

Every hold is appended to `~/.twokey/audit.jsonl` (mode 0600; rotated at 20 MiB to
`audit.jsonl.1` … `.3`; very long URLs or SQL are truncated in the log); read it with `twokey log`
(`--denied`, `--provider railway`, `--since 24h`, `--json`), which also reads the rotated files.

## What's covered

`twokey rules` lists all 126 rules across 31 providers:

- **Clouds:** AWS (RDS/Aurora/DocumentDB/Neptune, EC2, DynamoDB, S3, Lambda, EKS, CloudFormation,
  Secrets Manager, ECR, Route 53, EFS, ElastiCache, Redshift, OpenSearch, KMS key deletion,
  AWS Backup), Google Cloud (Storage, Cloud SQL, Compute, BigQuery, Firestore, Spanner, GKE,
  Memorystore, projects), Azure (resource groups and resources), DigitalOcean, Hetzner, Linode, Vultr
- **App platforms:** Railway, Vercel, Fly.io, Render, Heroku, Netlify, Cloudflare (incl. Pages, R2, D1)
- **Databases:** Supabase, Neon, PlanetScale, Turso, MongoDB Atlas, Upstash, Redis Cloud, Aiven,
  ClickHouse Cloud, Elastic Cloud, Databricks (Unity Catalog), Pinecone
- **Code & delivery:** GitHub (REST + GraphQL), GitLab, Bitbucket, Terraform Cloud (incl. destroy
  runs), npm (unpublish)

Rules are small YAML files:

```yaml
- id: railway.volume.delete
  hosts: [backboard.railway.com, backboard.railway.app]
  path: /graphql/{endpoint}
  graphql: { mutations: [volumeDelete] }
  resource: "{volumeId}"
  severity: critical
```

Matchers: `methods` + `path` (`{x}` one segment, `{x...}` the rest), `graphql.mutations`,
`aws.actions` (Query `Action=` or JSON `X-Amz-Target`), and `json: { field, equals }` for calls that
differ from routine ones only in the body — e.g. a Terraform Cloud run with `"is-destroy": true`.
Resources can use path, GraphQL/AWS arguments, `{query.<key>}` and `{json.<dotted.path>}`.

Every builtin rule ships a fixture: the destructive request copied from the provider's official
API reference, plus look-alike requests that must pass — CI fails without one. Load your own rules
with `--rules ./my-rules` and check them with `twokey rules test --rules ./my-rules`.
**Adding a provider is the best first PR** — see [CONTRIBUTING.md](CONTRIBUTING.md).

### Pre-approve what's safe in this project

Put a `.twokey-allow.yaml` in the project directory (or pass `--allow FILE`) and matching
operations go through without asking — still logged to the audit trail:

```yaml
allow:
  - rule: vercel.project.delete
    resource: "pr-*-preview"        # * matches anything, including "/"
    reason: preview deployments are disposable
  - rule: "postgres.truncate"
    resource: "test_*"
```

Every entry needs an explicit `resource` (`"*"` matches any named resource). Requests twokey
could not read, and requests whose resource it could not determine, are never pre-approved.

The project directory is where the agent works, so the agent (or a repo you cloned) can write this
file. twokey therefore ignores `./.twokey-allow.yaml` until you have reviewed it and run:

```sh
twokey allow trust            # trust ./.twokey-allow.yaml as it is now (prints its entries)
twokey allow revoke           # stop using it
```

Trust is recorded by absolute path and SHA-256 in `~/.twokey/allow-trusted.json`; if the file changes,
twokey ignores it again and its banner says so (`allow IGNORED … run twokey allow trust`). Passing
`--allow FILE` explicitly counts as trust for that run. Under `--strict` the file is mounted
read-only into the container.

## Guard a database (Postgres, MySQL)

Agents often talk to the database directly. Put twokey in between:

```sh
twokey pg --upstream db.internal:5432 --upstream-tls   # listens on 127.0.0.1:6543
DATABASE_URL=postgres://user:pass@127.0.0.1:6543/app?sslmode=disable twokey run -- claude

twokey mysql --upstream db.internal:3306 --upstream-tls  # listens on 127.0.0.1:3307
```

The local hop between agent and guard is plaintext (that is what lets twokey read it); the hop to
the database can use TLS: `--upstream-tls` verifies the server certificate, while
`--upstream-tls-skip-verify` only encrypts (like `sslmode=require`, e.g. for self-signed certs).
With MySQL `caching_sha2_password` and a plaintext upstream, clients may need
`--get-server-public-key` for the first login.

`DROP …`, `TRUNCATE`, `DELETE`/`UPDATE` without `WHERE`, `ALTER TABLE … DROP` and
`MERGE … THEN DELETE` are held — in simple and extended (prepared-statement) protocol, also when
nested in `WITH`, `EXPLAIN ANALYZE`, `COPY (…)`, `PREPARE` or routine/trigger/event bodies, and
ignoring look-alikes inside strings, comments and dollar-quoted bodies. A denied statement returns
a normal database error to the agent and the session stays usable; the database never sees it.
Held as uninspectable (allow rules never cover them): `DO` blocks, `CALL`, `COPY … PROGRAM`,
dynamic `EXECUTE`/`PREPARE … FROM @var`, SQL the guard cannot tokenize, and statements over 1 MiB.
Clients must connect without TLS or compression on the local hop (MySQL `--compress` is refused).
Functions called from `SELECT` run code twokey cannot see.

## How it works

```mermaid
flowchart LR
    A["agent + its tools<br/>(twokey run)"] -- HTTPS_PROXY --> P{"host has rules?"}
    P -- no --> T["blind tunnel<br/>(LLM API, npm, …)"]
    P -- yes --> D["TLS via local CA<br/>decode REST · GraphQL · AWS"]
    D -- "not destructive" --> F["upstream"]
    D -- "destructive or unreadable" --> H["hold"]
    H -- "approve (terminal / phone)" --> F
    H -- "deny · timeout · agent gone" --> X["403 for the model"]
```

Details, package map and security properties: [docs/architecture.md](docs/architecture.md).

`twokey run` sets `HTTPS_PROXY` plus CA-trust variables for each runtime
(`NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`), replaces `NO_PROXY` with localhost only, removes
`TWOKEY_NTFY_*` from the agent's environment, and starts your agent; every child process
inherits this. For hosts that have rules, twokey terminates TLS with a certificate from a local CA
in `~/.twokey`, decodes each request (including gzip/deflate bodies) and forwards or holds it.
Requests it cannot read on a watched endpoint (persisted GraphQL queries, unknown encodings) are
held — it fails closed.

- The local CA is **name-constrained** to the rule packs' domains (`github.com`, `amazonaws.com`,
  `railway.com`, …): even a leaked `ca-key.pem` cannot impersonate other sites. After adding rules
  for new domains, run `twokey ca reset` (and `twokey ca trust` again if you used it).
- WebSocket upgrades on watched hosts are checked against the rules and spliced only after the
  server answers `101`. On hosts whose rules look at request bodies (GraphQL, AWS, JSON) an
  upgrade is held, because the frames that follow cannot be inspected.
- Bypass resistance: dot segments and `//` in paths are resolved before matching, method-override
  headers (`X-HTTP-Method-Override` and friends, `_method`) are evaluated too, every AWS `Action`
  value is checked, and request heads over 1 MiB are rejected.

### Platform notes

- **Windows / macOS:** Go programs (`gh`, `terraform`, `flyctl`) and Windows `curl` (Schannel)
  use the OS trust store and ignore `SSL_CERT_FILE`. Run `twokey ca trust` once (user store,
  no admin). `twokey doctor` tells you exactly which runtimes need it. On Windows, `twokey run`
  also gives curl a `CURL_HOME` config with `ssl-revoke-best-effort` (your own `.curlrc` is
  kept): Schannel otherwise rejects local-CA certificates, which have no revocation endpoint.
- **Node:** needs ≥ 22.21 or ≥ 24.5 (`NODE_USE_ENV_PROXY`).
- **JVM:** `twokey run` sets `JAVA_TOOL_OPTIONS` (proxy properties + a PKCS#12 truststore with
  the twokey CA), which covers `HttpURLConnection` and SDKs that honor the standard proxy
  properties. `twokey doctor` checks it when `java` is installed.
- **Kubernetes:** not intercepted on purpose. `kubectl` trusts only the CA in your kubeconfig
  and often authenticates with client certificates, so a TLS-intercepting proxy would break it.
  Use `--strict` plus RBAC/admission policies for clusters.
- **Not covered:** clients that ignore proxy settings entirely. Between the agent and twokey,
  intercepted hosts speak HTTP/1.1 (HTTP/2-only clients such as gRPC are not supported there).

### Exit codes

`explain`: 0 = passes, 2 = would be held. `run`: the agent's exit status, or 125 if twokey itself
failed (e.g. no proxy running).

### Performance

Deciding hold-or-pass costs about 30–40 µs per request on a watched host with all 126 rules loaded
(Ryzen 7 7800X3D, `go test ./internal/rules -bench . -benchmem`); unwatched hosts are a plain TCP
tunnel. The added latency is the local TLS hop, not the rules.

## Configuration reference

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `--addr` | `up`, `run` | `127.0.0.1:7171` | Proxy address (loopback only) |
| `--timeout` | `up`, `run --phone`, `pg`, `mysql` | `2m` | Deny holds nobody answers in time (max `1h`) |
| `--phone` | `up`, `run`, `pg`, `mysql` | off | Also approve from your phone via ntfy |
| `--observe` | `up`, `run` | off | Log what would be held, hold nothing |
| `--strict` / `--image` | `run` | off | Run the agent in Docker with twokey as its only egress |
| `--rules DIR` | `up`, `run --phone`, `rules`, `explain` | — | Extra rule packs (YAML) |
| `--allow FILE` | `up`, `run --phone`, `pg`, `mysql` | trusted `./.twokey-allow.yaml` | Pre-approved operations |
| `--no-desktop` | `up`, `run --phone` | off | No desktop notification on a hold |
| `--ntfy-server` | `up`, `phone`, `pg`, `mysql` (`run --phone`: `TWOKEY_NTFY_SERVER`) | `https://ntfy.sh` | ntfy server (https; http only for localhost) |
| `TWOKEY_HOME` | env | `~/.twokey` | CA, phone topic, trust list, audit log |
| `TWOKEY_NTFY_SERVER`, `TWOKEY_NTFY_TOPIC` | env | — | Phone channel; never passed to the agent |

Stability of all of the above across 1.x: [docs/compatibility.md](docs/compatibility.md).
Which agents have been checked end to end: [docs/agents.md](docs/agents.md).

## Operations runbook

| Situation | Do this |
|---|---|
| An agent's call went through that should have been held | `twokey doctor` (is that runtime routed and trusting the CA?), then `twokey explain --method M --url U` — exit 0 means no rule covers it: open an issue or add a rule |
| Upgraded and Go tools / Windows curl fail TLS | The CA rotated: `twokey setup --yes --trust`, then `twokey ca untrust --retired` |
| A hold you did not expect | `twokey log -n 20` shows rule, resource and who decided; pre-approve safe ones in `.twokey-allow.yaml` + `twokey allow trust` |
| Allow file changed and is now `IGNORED` | Review the diff, then `twokey allow trust` |
| Lost the phone / topic leaked | `twokey phone --rotate`, scan the new QR |
| Proxy port already in use | Another `twokey up` is running, or pass `--addr 127.0.0.1:<port>` to both `up` and `run` |
| Remove twokey | `twokey uninstall --purge`, then remove the binary (`brew uninstall` / `scoop uninstall`) |

## Strict mode: no way around the guard

```sh
twokey up                                              # terminal 1 (or add --phone below)
twokey run --strict --image node:22 -- npx @anthropic-ai/claude-code
```

The agent runs in a Docker container on an `--internal` network with no route to the internet.
Its only way out is a tiny gateway container that forwards to twokey on your machine — so unsetting
`HTTPS_PROXY`, raw sockets or a stray SDK simply have nowhere to go. The project directory is
mounted at `/work`; only the CA certificate and trust bundles are mounted, never the CA key or the
phone topic. Each run gets its own gateway (`alpine/socat`, pinned by digest), removed when the
agent exits. Requires Docker (Docker Desktop on Windows/macOS).

## Threat model — read this

By default twokey protects you from **accidents**: an agent that guesses wrong, misreads an
environment, or "cleans up" the wrong thing. Without `--strict` it is **not** a sandbox against a
deliberately malicious agent, which runs as your user and could unset `HTTPS_PROXY` or read
`~/.twokey` — use `--strict` for that. Either way: scope your cloud tokens and keep backups
somewhere a single API call can't reach. See [SECURITY.md](SECURITY.md).

Upgrading: when a release adds providers, twokey creates a new local CA (old ones are kept as
`~/.twokey/ca.old.*.pem`). If you used `twokey ca trust`, run it again (`twokey setup --yes --trust`
does it), then `twokey ca untrust --retired` to remove the old CAs from the OS store.

Uninstalling: `twokey uninstall` removes every twokey CA from the OS trust store (by exact
thumbprint) and any strict-mode Docker objects; add `--purge` to delete `~/.twokey` too.
`twokey ca untrust` does only the trust-store part.

## Documentation

[Architecture](docs/architecture.md) · [Agents](docs/agents.md) ·
[Compatibility promise](docs/compatibility.md) · [Changelog](CHANGELOG.md) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md)

## Roadmap

More providers and rules — PRs welcome (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## License

MIT
