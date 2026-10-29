# SendScore

Check a newsletter email before it goes out, and every issue after.

SendScore reads one received message and returns a verdict: SPF, DKIM, DMARC and alignment, one-click unsubscribe, structure, unrendered merge tags, links, and what changed since the previous issue. Every check is deterministic and shows the evidence it looked at, and every failure says who can fix it: you, or your email platform.

It reports what the message proves. Receipt at SendScore is not inbox placement at Gmail or anyone else, and SendScore never claims it is.

This repository is the engine and the command line. The hosted service at [sendscore.ai](https://sendscore.ai) adds test addresses, monitoring, a delivery heartbeat, history, alerts, an API, and MCP tools for agents, all built on this engine.

## Install

```sh
go install github.com/sendscore/sendscore@latest
```

Or build from a clone with `make build`, which writes `bin/sendscore`.

## Use

```sh
sendscore check issue.eml              # a readable report
sendscore check --json issue.eml       # the verdict as JSON
sendscore check --previous last.eml issue.eml
sendscore diff before.eml after.eml    # what changed between two issues
```

Save a message as `.eml` from your mail client ("Show original" and "Download" in Gmail, "Save As" in Apple Mail), or pipe one in with `sendscore check -`.

A saved file does not record which server delivered it, so SPF, reverse DNS, and TLS are skipped unless you pass the envelope:

```sh
sendscore check --ip 203.0.113.10 --mail-from bounce@mail.example.com --tls yes issue.eml
```

Messages sent to a SendScore address carry all of it.

Other flags:

- `--links` fetches every link and image. Off by default: it is slow, and it touches your tracking links. Unsubscribe, confirm, and preference links are never fetched, and private and loopback addresses are refused.
- `--offline` makes no DNS lookups. Checks that need DNS are skipped, not failed.

Exit codes: `0` every check passed, `1` warnings only, `2` a check failed, `64` usage error. `diff` exits `1` when a change made a check worse.

## MCP

`sendscore mcp` runs SendScore's MCP tools over stdio for Claude Code, Claude Desktop, or any MCP client:

```sh
claude mcp add sendscore -- sendscore mcp
```

The tools are `get_test_address`, `wait_for_message`, `get_report`, and `compare_to_previous`. They call a SendScore app's API: `SENDSCORE_URL` (default `https://app.sendscore.ai`, or your own instance) and `SENDSCORE_TOKEN` when the app requires one. The hosted app also serves the same tools as a remote connector at `https://app.sendscore.ai/api/mcp`.

An agent's loop: get a test address, send the issue's preview to it from the email platform, wait for the verdict, and fix what `top_fixes` lists before scheduling.

## What it checks

| Category | Checks |
| --- | --- |
| Authentication | `auth.spf`, `auth.spf_lookups`, `auth.dkim`, `auth.dkim_key`, `auth.dmarc_record`, `auth.dmarc`, `auth.alignment`, `auth.ptr`, `auth.tls` |
| Unsubscribe | `unsub.header`, `unsub.one_click`, `unsub.signed`, `unsub.visible` |
| Structure | `struct.mime`, `struct.plain_text`, `struct.html_size`, `struct.headers`, `struct.from_domain` |
| Content | `content.placeholders`, `content.links`, `content.images`, `content.insecure_links`, `content.image_alt` |
| Changes | `changes.regressions` (with `--previous`) |

Statuses are `pass`, `warn`, `fail`, `info`, and `skipped` (with a reason). The verdict is `fail` if anything fails, `warn` if anything warns, and `pass` otherwise. `ready_to_send` is false when an authentication or unsubscribe check fails; content problems are reported without blocking.

## Use it from Go

```go
v, err := engine.Analyze(ctx, raw, engine.Options{
	Envelope: engine.Envelope{RemoteIP: ip, MailFrom: from},
})
```

`verdict` holds the JSON contract (`sendscore.verdict/v1`). Each verdict carries a `fingerprint`, and `engine.Compare` lists the changes between two fingerprints, so an issue can be compared with the last one without keeping the old message.

## Develop

```sh
make check    # gofmt, go vet, go test
```

No em or en dashes anywhere in the repository; a test enforces it.

## License

MIT
