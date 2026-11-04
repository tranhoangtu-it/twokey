# Using twokey with your agent

twokey does not care which agent you run: `twokey run -- <agent>` sets proxy and CA variables, and
every tool the agent starts (a shell, `curl`, Python, Node, Go CLIs, SDKs) inherits them. What
matters is the **runtime of the tool that makes the destructive call**, so check that with
`twokey doctor` once per machine.

The agent's own traffic to its model provider (`api.anthropic.com`, `api.openai.com`, …) is on no
rule's host list, so it is tunneled untouched — twokey never sees your API key or prompts.

## Status

| Agent | Command | Status |
|---|---|---|
| Claude Code | `twokey run -- claude` | **Verified** 2026-11-05 on Windows 11 with Claude Code 2.1.318 (native build): a `DELETE https://api.github.com/repos/…` issued by its Bash tool was held as `github.repo.delete`, denied, and the agent received the 403 explanation. |
| Codex CLI | `twokey run -- codex` | Untested. Node-based tools need Node ≥ 22.21 / ≥ 24.5. |
| Cursor agent | `twokey run -- cursor-agent` | Untested. |
| Aider | `twokey run -- aider` | Untested. Python tools use `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`, which `run` sets. |
| opencode | `twokey run -- opencode` | Untested. |
| Your own scripts | `twokey run -- python deploy.py` | Covered by the e2e suite in CI on Linux, macOS and Windows (Python `urllib`). |

"Untested" means nobody has run that agent through twokey yet, not that it is known to fail. If you
do, please open an issue or PR with the result so this table can say "verified".

## Per-runtime notes

- **Go CLIs** (`gh`, `terraform`, `flyctl`) and **Windows curl** read the OS trust store: run
  `twokey ca trust` once (user store, no admin). `twokey doctor` says which runtimes need it.
- **Node:** needs ≥ 22.21 or ≥ 24.5 (`NODE_USE_ENV_PROXY`).
- **JVM:** covered through `JAVA_TOOL_OPTIONS` for clients that honor the standard proxy properties.
- **Database clients:** point `DATABASE_URL` at `twokey pg` / `twokey mysql`; the agent's runtime
  does not matter there.

## Making it impossible to bypass

An agent running as you could unset `HTTPS_PROXY`. If that is in your threat model, run it with
`twokey run --strict --image <image> -- <agent>`: the container's only network path is twokey.
See the README's threat model.
