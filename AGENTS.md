# AGENTS.md

SendScore's engine and CLI (Go, MIT). The hosted app lives in sendscore/sendscore-app and imports `engine` and `verdict` from here.

- `verdict/`: the JSON contract (`sendscore.verdict/v1`). Never rename or repurpose a field within a schema version: add a field, or bump `Schema`.
- `engine/`: one file per category of checks (`auth.go`, `unsub.go`, `structure.go`, `content.go`, `links.go`), `compare.go` for issue to issue changes, and `rollup.go` for the overall verdict, ready_to_send, top fixes, and summary.
- `cmd/`: the cobra CLI (`check`, `diff`). Exit codes 0, 1, 2, and 64, as in Preflight.

Rules:

- Checks are deterministic. No AI in the engine, no guessing at a provider's filtering, and never a claim of inbox placement.
- Every check returns evidence. Every failure and warning with a fix says who fixes it (`you` or `provider`).
- A check that cannot run is `skipped` with a reason, never passed.
- Never fetch unsubscribe, confirm, or preference links, and keep `SafeHTTPClient` refusing non-public addresses.
- DNS goes through `engine.Resolver` so tests use a fake; tests sign real DKIM with a generated key.
- Run `make check` before committing. No em or en dashes anywhere (`dashes_test.go`). Use the Oxford comma in prose.
- Commits: short one-line messages, no attribution lines.
