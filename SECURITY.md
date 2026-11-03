# Security

## Reporting

Please report vulnerabilities privately via GitHub's
[security advisories](https://github.com/tranhoangtu-it/twokey/security/advisories/new),
not in public issues. Expect a first response within a few days.

## In scope

- A request that performs an operation covered by a rule, sent by an ordinary tool, CLI or SDK
  through `twokey run`, that is **not** held (bypass of matching or interception).
- A way for the agent's normal process environment to approve its own hold.
- Proxy bugs that corrupt or leak traffic, or crash twokey.
- Problems with the local CA (key handling, name constraints, leaf certificates).

## Out of scope (by design — see the threat model in the README)

- An agent that deliberately disables twokey: unsetting `HTTPS_PROXY`, reading files in
  `~/.twokey` (CA key, phone topic), or talking to the cloud from outside the process tree.
  Use a container/VM whose only egress is twokey for that threat.
- Operations no rule covers yet — please open an issue or a PR adding the rule instead.

## How twokey protects its own secrets

- The local CA is name-constrained to the domains in the rule packs, so a leaked
  `ca-key.pem` cannot be used to impersonate other sites.
- The phone-approval topic is stored in `~/.twokey/ntfy-topic` (mode 0600), never on the
  command line, and `TWOKEY_NTFY_*` variables are stripped from the agent's environment.
- On Windows, file modes are not enforced; `~/.twokey` relies on your user profile's ACL.
