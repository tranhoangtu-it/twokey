# Contributing

The most valuable contribution is a **rule**: one destructive API operation twokey should hold.

## Add a rule in 5 minutes

1. Find the provider pack in `internal/rules/packs/<provider>.yaml` (or create one).
2. Add a rule. Every matcher you set must match:

```yaml
- id: vercel.env.delete            # <provider>.<resource>.<verb>, unique
  hosts: [api.vercel.com]          # glob; * matches anything, including dots
  methods: [DELETE]                # optional
  path: /{version}/projects/{project}/env/{id}   # {x} = one segment, {x...} = rest
  # graphql: { mutations: [volumeDelete] }       # top-level mutation field names
  # aws: { actions: [DeleteDBInstance] }          # Query Action= or X-Amz-Target suffix
  # unless_query: [policy]                        # skip when any of these query keys is present
  resource: "{project}/{id}"       # shown to the human; {a|b} = first non-empty
  severity: critical               # critical | high
  message: Deletes a project environment variable.
```

3. Prove it, without any network or credentials:

```sh
go run ./cmd/twokey explain --method DELETE --url https://api.vercel.com/v9/projects/p/env/e
echo $?   # 2 = would be held
```

4. Add a fixture `internal/rules/testdata/<rule-id>.http` — CI fails without one. Copy the
   request from the provider's **official API reference** and cite it:

   ```http
   # source: https://vercel.com/docs/rest-api/reference/endpoints/projects/remove-an-environment-variable
   # resource: my-app/env_123
   DELETE https://api.vercel.com/v9/projects/my-app/env/env_123
   ###
   # safe: reading it must not be held
   GET https://api.vercel.com/v9/projects/my-app/env/env_123
   ```

   Then `go test ./...`. For your own packs: `twokey rules test --rules ./my-packs`.
5. In the PR, link the provider's official API reference for the endpoint.

Rules must match what the provider's **official CLI and SDKs actually send** (host, API version,
GraphQL path). If you're unsure, run the CLI through `twokey up` and look at the hold.

## Code changes

- `go vet ./... && go test -race ./...` must pass; CI runs on Linux, macOS and Windows.
- End-to-end tests run the real binary (`twokey up` + `twokey run` + a human answer, and `twokey pg`
  in front of a real Postgres): `go test -tags e2e ./e2e/` (needs Python and network; set
  `TWOKEY_E2E_PG=host:port` of a disposable Postgres with user `postgres` / password `postgres` for the
  database test). CI runs them on all three OSes.
- Keep the threat model in mind (README): accidents, not a malicious agent.
- Bypasses of an existing rule are security issues — see [SECURITY.md](SECURITY.md).
