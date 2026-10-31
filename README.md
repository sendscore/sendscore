# SendScore

Check a newsletter email before it goes out, and every issue after.

SendScore reads one received message and returns a verdict: SPF, DKIM, DMARC and alignment, one-click unsubscribe, structure, unrendered merge tags, links, and what changed since the previous issue. Every check is deterministic and shows the evidence it looked at, and every failure says who can fix it: you, or your email platform.

It reports what the message proves. Receipt at SendScore is not inbox placement at Gmail or anyone else, and SendScore never claims it is.

This repository is the engine and the command line, which need no server or account. The [SendScore app](https://github.com/sendscore/sendscore-app) is a separate server you run yourself, built on this engine. It adds test addresses, monitoring, a delivery heartbeat, history, alerts, an API, and MCP tools for agents, and it needs a host that can receive mail on port 25.

There is no hosted version right now. If you would use one, [open an issue](https://github.com/sendscore/sendscore/issues) and say so.

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

`diff` and `--previous` compare only what the messages themselves carry: signing domains and selectors, the Return-Path, unsubscribe headers, link hosts, the number of links and images, and size. They make no DNS lookups for the older message and do not compare authentication results, because re-checking last week's message against today's DNS would show today's answer, not the one it got when it was sent. To see whether a DNS change broke authentication, check a new message.

Save a message as `.eml` from your mail client ("Show original" and "Download" in Gmail, "Save As" in Apple Mail), or pipe one in with `sendscore check -`.

A saved file does not record which server delivered it, so SPF, reverse DNS, and TLS are skipped unless you pass the envelope:

```sh
sendscore check --ip 203.0.113.10 --mail-from bounce@mail.example.com --tls yes issue.eml
```

Messages sent to a SendScore address carry all of it.

Other flags:

- `--links` fetches every link and image. Off by default: it is slow, and it touches your tracking links. Unsubscribe, confirm, and preference links are never fetched, and private and loopback addresses are refused.
- `--offline` makes no DNS lookups. Checks that need DNS are skipped, not failed.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Every check passed. |
| `1` | Warnings only. `diff` exits `1` when a change made a check worse. |
| `2` | A check failed. |
| `64` | Usage error, such as an unknown flag or a bad `--ip`. |
| `65` | The input is not an email message, or is larger than 25 MB. |
| `66` | The input file cannot be read. |
| `70` | Internal error. |
| `74` | The report cannot be written. |

## MCP

`sendscore mcp` runs SendScore's MCP tools over stdio for Claude Code, Claude Desktop, or any MCP client. It needs a running [SendScore app](https://github.com/sendscore/sendscore-app), so run your own first.

```sh
claude mcp add sendscore --env SENDSCORE_URL=https://sendscore.example.com --env SENDSCORE_TOKEN=ss_live_... -- sendscore mcp
```

The tools are `get_test_address`, `wait_for_message`, `get_report`, and `compare_to_previous`. They call a SendScore app's API, which needs an API token on every request. Create one on the Account page of the app and set it as `SENDSCORE_TOKEN`. `SENDSCORE_URL` is the address of your app, and is required. The app also serves the same tools as a remote connector at `/api/mcp`.

An agent's loop: get a test address, send the issue's preview to it from the email platform, wait for the verdict, and fix what `top_fixes` lists before scheduling.

One `wait_for_message` call waits up to 50 seconds; if nothing has arrived it answers `not_received`, and the agent calls it again. After fixing something and sending a new preview to the same address, pass the previous report's ID as `after_report_id` so the wait returns only the new report.

## What it checks

| Category | Checks |
| --- | --- |
| Authentication | `auth.spf`, `auth.spf_lookups`, `auth.dkim`, `auth.dkim_key`, `auth.dmarc_record`, `auth.dmarc`, `auth.alignment`, `auth.ptr`, `auth.tls` |
| Unsubscribe | `unsub.header`, `unsub.one_click`, `unsub.signed`, `unsub.visible` |
| Structure | `struct.mime`, `struct.plain_text`, `struct.html_size`, `struct.headers`, `struct.from_domain` |
| Content | `content.placeholders`, `content.links`, `content.images`, `content.insecure_links`, `content.image_alt`, `content.subject`, `content.preheader`, `content.text_ratio`, `content.shorteners`, `content.link_text`, `content.active`, `content.blocklists` |
| Changes | `changes.regressions` (with `--previous`) |

Statuses are `pass`, `warn`, `fail`, `info`, and `skipped` (with a reason). The verdict is `fail` if anything fails, `warn` if anything warns, and `pass` otherwise. `ready_to_send` is false when an authentication or unsubscribe check fails, and when DMARC could not be evaluated (for example because DNS lookups failed or `--offline` was used). In that case the verdict is at least `warn`, the summary says authentication could not be checked, and the first fix is to run the check again. Content problems are reported without blocking.

There is no list of "spam words". Mailbox providers filter on reputation, authentication, and engagement, so a word list would flag ordinary copy while claiming to know a filter's decision. The content checks look for things with a factual basis instead, such as links to domains on Spamhaus DBL or SURBL, URL shorteners, link text that names a different domain from the link, image-only issues, missing preview text, and scripts, forms, or attachments.

`content.blocklists` only runs when you ask for it, because the free Spamhaus and SURBL zones are for non-commercial use:

- `--spamhaus-key KEY` (or `SENDSCORE_SPAMHAUS_DQS_KEY`) uses Spamhaus DBL through Data Query Service, which allows commercial use.
- `--surbl-zone ZONE` (or `SENDSCORE_SURBL_ZONE`) uses a SURBL data feed zone.
- `--public-blocklists` uses the free public zones, for non-commercial use only. Spamhaus refuses these through large public DNS resolvers.

Each list's test domain is looked up first to prove the list is answering. The check only passes when every list answered for every domain. A refusal, a timeout, or more than 100 domains makes it `skipped` with the reason, never a pass.

## Use it from Go

```go
v, err := engine.Analyze(ctx, raw, engine.Options{
	Envelope: engine.Envelope{RemoteIP: ip, MailFrom: from},
})
```

`verdict` holds the JSON contract (`sendscore.verdict/v1`). Each verdict carries a `fingerprint`, and `engine.Compare` lists the changes between two fingerprints, so an issue can be compared with the last one without keeping the old message.

## Develop

```sh
make check    # gofmt, go vet, go test -race, and govulncheck
```

`go.mod` pins the Go toolchain, so builds use a release with the current security fixes even when an older Go is installed.

No em or en dashes anywhere in the repository; a test enforces it.

## License

MIT
