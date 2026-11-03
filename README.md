# twokey

**A two-person rule for AI agents.** A local proxy that holds destructive cloud API calls
(`volumeDelete`, `DeleteDBInstance`, `DELETE /repos/…`) until you approve them — in another
window or on your phone. Your agent can't approve itself.

```text
$ twokey replay pocketos --live

⏸  HOLD #1  POST https://backboard.railway.com/graphql/v2
   CRITICAL railway.volume.delete  operation=volumeDelete  resource=pg-data-prod
            Deletes a Railway volume. This is the call behind the April 2026 PocketOS production wipe.
   → approve 1 pg-data-prod     |     deny 1
deny 1
   #1 DENIED by terminal (denied by human)
```

## Why

On April 25, 2026 a coding agent working on a *staging* task deleted PocketOS's production
database volume — and its backups — in about nine seconds. It didn't run `rm -rf` or `DROP TABLE`.
It made one HTTPS call to Railway's GraphQL API. Existing guards missed it:

| Guard | Why it misses |
|---|---|
| Bash hooks / command deny-lists | See the command string, not the effect. `curl`, a Python one-liner or an SDK call sails through. |
| SQL proxies | The deletion never touched SQL. It was a cloud control-plane API call. |
| "Block HTTP DELETE" egress rules | GraphQL mutations are all `POST`. |

twokey sits on the network path and **understands the protocols**: REST method + path,
GraphQL mutation names (aliases, fragments and batches included), and AWS actions
(`Action=` and `X-Amz-Target`). Only hosts with rules are inspected; everything else —
including your LLM API traffic — is tunneled untouched.

## Quick start

```sh
go install github.com/tranhoangtu-it/twokey/cmd/twokey@latest

# terminal 1: proxy + approval prompt (optionally your phone)
twokey up --ntfy-topic "$(twokey ntfy-topic)"

# terminal 2: run any agent through it
twokey run -- claude          # or codex, cursor-agent, aider, opencode…

# check that curl / python / node / go in your environment are covered
twokey doctor
```

When the agent tries something destructive, the request **waits**. You get a prompt in the
`twokey up` window (type the resource name to approve) and, with `--ntfy-topic`, a push
notification with **Approve / Deny** buttons via [ntfy](https://ntfy.sh). Nobody answers within
2 minutes → denied. A denied request returns `403` with a JSON body written for the model:

> twokey blocked a destructive request (denied by a human): railway volumeDelete on pg-data-prod.
> Do not retry, rephrase, or work around this request… ask the user to approve it or run it themselves.

Every hold is appended to `~/.twokey/audit.jsonl`.

## What's covered (v0.1)

`twokey rules` lists them all — 35 rules across Railway, AWS (RDS, EC2, DynamoDB,
CloudFormation, S3, Lambda, EKS), GitHub (REST + GraphQL), Vercel, Supabase, Neon, Fly.io,
Cloudflare and DigitalOcean. Rules are small YAML files:

```yaml
- id: railway.volume.delete
  hosts: [backboard.railway.com, backboard.railway.app]
  path: /graphql/v2
  graphql: { mutations: [volumeDelete] }
  resource: "{volumeId}"
  severity: critical
```

Test a rule without any network: `twokey explain --method DELETE --url https://api.github.com/repos/acme/api`
(exit code 2 = would be held). Load your own packs with `--rules ./my-rules`.
**Adding a provider is the best first PR.**

## How it works

`twokey run` sets `HTTPS_PROXY` plus CA-trust variables for each runtime
(`NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`) and starts your agent. Every child process inherits them.
For hosts that have rules, twokey terminates TLS with a certificate from a local CA it generates
in `~/.twokey`, parses each request, and either forwards it or holds it. Requests it cannot parse
on a watched GraphQL endpoint (e.g. persisted queries) are held too — it fails closed.

- The local CA is **name-constrained** to the domains in your rule packs (`github.com`,
  `amazonaws.com`, `railway.com`, …): even a leaked `ca-key.pem` cannot impersonate other sites.
  If you add rules for new domains, run `twokey ca reset` (and `twokey ca trust` again if you used it).
- `twokey run` replaces any existing `NO_PROXY` (keeping only localhost) so an entry like
  `.amazonaws.com` can't silently route around the guard.
- If the agent disconnects while a request is held, the request is dropped — approving it
  afterwards does nothing.
- WebSocket upgrades on watched hosts are checked against the rules, then passed through.

### Platform notes

- **Windows / macOS:** Go programs (`gh`, `terraform`, `flyctl`) and Windows `curl` (Schannel)
  use the OS trust store and ignore `SSL_CERT_FILE`. Run `twokey ca trust` once (user store,
  no admin). `twokey doctor` tells you exactly which runtimes need it.
- **Node:** needs ≥ 22.21 or ≥ 24.5 (`NODE_USE_ENV_PROXY`).
- HTTP/1.1 is used between the agent and twokey on intercepted hosts; upstream may be HTTP/2.

## Threat model — read this

twokey protects you from **accidents**: an agent that guesses wrong, misreads an environment,
or "cleans up" the wrong thing. It is **not** a sandbox against a deliberately malicious agent,
which runs as your user and could unset `HTTPS_PROXY` or read the CA key. For that, run the agent
in a container/VM whose only network egress is twokey. Also: scope your cloud tokens and keep
backups somewhere a single API call can't reach.

## Roadmap

Postgres wire protocol (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`) · `--strict` sandbox mode ·
more providers · per-project allow rules.

## License

MIT
