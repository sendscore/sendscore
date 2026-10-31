# AGENTS.md

SendScore's engine and CLI (Go, MIT). The self-hosted app lives in sendscore/sendscore-app and imports `engine` and `verdict` from here.

- `verdict/`: the JSON contract (`sendscore.verdict/v1`). Never rename or repurpose a field within a schema version: add a field, or bump `Schema`.
- `engine/`: one file per category of checks (`auth.go`, `unsub.go`, `structure.go`, `content.go`, `links.go`), `compare.go` for issue to issue changes, and `rollup.go` for the overall verdict, ready_to_send, top fixes, and summary.
- `mcpserver/`: the MCP tools, over a `Backend` interface. `HTTPBackend` calls an app's JSON API (used by `sendscore mcp`); the app serves the same tools over its database at `/api/mcp`.
- `conformance/`: what every language package must return, written by the CLI (`go test . -run TestConformance -update`).
- `packages/`: thin wrappers in TypeScript, Python, PHP, Rust, Ruby, Elixir, Java, and .NET. They run the CLI and never reimplement a check. All share one version (`packages_test.go`), and none has an install script.
- `cmd/`: the cobra CLI (`check`, `diff`, `mcp`). Exit codes 0, 1, and 2 for the verdict, then sysexits: 64 usage, 65 not an email, 66 unreadable input, 70 internal, and 74 output. Give every error that is not a usage error its code with `withCode`.

Rules:

- Checks are deterministic. No AI in the engine, no guessing at a provider's filtering, and never a claim of inbox placement.
- Every check returns evidence. Every failure and warning with a fix says who fixes it (`you` or `provider`).
- A check that cannot run is `skipped` with a reason, never passed.
- Never fetch unsubscribe, confirm, or preference links, and keep `SafeHTTPClient` refusing non-public addresses.
- DNS goes through `engine.Resolver` so tests use a fake; tests sign real DKIM with a generated key.
- The text report passes every string from the message, DNS, or a server through `safe` before printing it.
- Never use an environment variable as a flag default, because cobra prints defaults in `--help`. Read it after parsing.
- `go.mod` pins the toolchain. Raise it when a Go patch release fixes a vulnerability that govulncheck reports.
- Run `make check` before committing. No em or en dashes anywhere (`dashes_test.go`). Use the Oxford comma in prose.
- Commits: short one-line messages, no attribution lines.
