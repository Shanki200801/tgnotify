# tgnotify

Telegram alerts and tap-to-approve buttons for any project. It comes in three forms: a single Go binary that any language can shell out to, plus native **Go**, **Python** and **TypeScript** libraries. None of them have runtime dependencies, and all three share one config file.

```bash
tgnotify send -title "Backup" -level success "Nightly backup finished"
tgnotify run -- ./train.sh                     # pings you with exit code + duration (+ output tail on failure)
tgnotify ask "Deploy to prod?" Yes No          # blocks, prints the tapped option
```

## Setup (once per machine)

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token.
2. Run `tgnotify setup`. Paste the token, then send your bot any message. The chat id is detected and saved to `~/.config/tgnotify/config.json` (mode 0600). A test message confirms it works.

Alternatively, set `TGNOTIFY_TOKEN` and `TGNOTIFY_CHAT_ID` (or `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`) in the environment. This is handy for CI and servers.

## Install

| What | Command |
|---|---|
| CLI (Go ≥1.18) | `go install github.com/shanki200801/tgnotify/cmd/tgnotify@latest`, or `just install` from a clone |
| Go library | `go get github.com/shanki200801/tgnotify` |
| Python ≥3.8 | `uv add "tgnotify @ git+https://github.com/shanki200801/tgnotify#subdirectory=python"`, or `pip install -e path/to/tgnotify/python` |
| Node ≥18 / TS | `npm install github:shanki200801/tgnotify` (builds on install), or `npm install path/to/tgnotify` |

## CLI

```
tgnotify setup
tgnotify send [-title T] [-level info|success|warn|error] [-silent] [-html] [-button "Text|url"]... [text]   # stdin if no text
tgnotify file [-caption C] <path>
tgnotify ask [-timeout 10m] [-json] <question> <opt>...      # exit 0 + prints choice; exit 2 on timeout
tgnotify prompt <question> <opt>...                           # non-blocking; prints message_id
tgnotify collect [message_id]...                              # answers as JSON lines
tgnotify run [-title T] [-tail 15] -- <cmd> [args]...         # exits with the command's code
```

Flags must come **before** positional arguments.

## Libraries

**Python**
```python
import tgnotify
tgnotify.notify("Scraped 42 jobs", title="job-hunt", level="info", buttons={"Open": "https://..."})
tgnotify.send_file("report.pdf", "Weekly report")
choice = tgnotify.ask("Ship it?", ["Yes", "No"], timeout=600)   # "Yes" | "No" | None

c = tgnotify.Client()                       # or Client(token, chat_id)
mid = c.prompt("Apply to Acme — Backend Eng?", ["Approve", "Skip"])
...                                         # later, e.g. the next cron run
for a in c.collect(mid): print(a.message_id, a.choice)
```

**TypeScript / Node**
```ts
import { notify, ask, Client } from "tgnotify";
await notify("Build failed", { title: "CI", level: "error" });
const choice = await ask("Ship it?", ["Yes", "No"], { timeoutMs: 600_000 }); // string | null
const c = new Client();
const id = await c.prompt("Approve?", ["Yes", "No"]);
const answers = await c.collect(id);
```

**Go**
```go
tgnotify.Notify("Deploy done", tgnotify.Options{Title: "prod", Level: "success"})
c, _ := tgnotify.New()
a, err := c.Ask(ctx, "Ship it?", []string{"Yes", "No"}, 10*time.Minute, tgnotify.Options{})
id, _ := c.Prompt(ctx, "Approve?", []string{"Yes", "No"}, tgnotify.Options{})
answers, _ := c.Collect(ctx, id)
```

## Approvals in batch jobs (prompt → collect)

`ask` blocks, which is fine for interactive scripts. A daily cron job should instead send its buttons with `prompt` and pick up the taps on its next run with `collect`. Taps are recorded in `~/.config/tgnotify/state.json`, which holds the update offset plus answers not collected yet. That means:

- Any tool that polls (CLI, Python, TS or Go) saves every tap it sees. A tap meant for another prompt is kept for whoever collects it.
- **Telegram keeps unfetched updates for about 24h.** Run `collect` (or anything that polls) at least once a day, or taps are lost.
- Only one poller can run per bot. If another process is long-polling or a webhook is set, you get a clear `409 conflict` error. Use a separate bot for anything that needs webhooks.
- A tap is accepted only from the configured chat. After a tap, the buttons collapse to `✔ <choice>`.
- In prompt→collect mode, nothing confirms a tap until the next `collect` runs, so the buttons stay live until then. If someone taps more than once, the **latest** tap per message wins.
- The state file is shared by every project on the machine, so always pass message ids to `collect`. Called with no ids, it takes every project's answers.

## Recipes

- **[Telegram one-time-code login](docs/telegram-login.md):** protect a personal web app with a code sent to your Telegram. Covers the security model, a Cloudflare Worker reference, a Python port and a test checklist.

## Contract (shared by all implementations)

| | |
|---|---|
| Config | env `TGNOTIFY_TOKEN`/`TGNOTIFY_CHAT_ID` (fallback `TELEGRAM_*`) override `$TGNOTIFY_CONFIG` or `~/.config/tgnotify/config.json` (`{"token","chat_id"}`, 0600) |
| State | `$TGNOTIFY_STATE` or `~/.config/tgnotify/state.json`: `{"offset": int, "answers": [Answer]}` |
| Answer | `{message_id, nonce, index, choice, user, at}` |
| API base | `TGNOTIFY_API_BASE` (tests point this at a local stub) |
| Messages | HTML parse mode, text escaped unless `html`. Level icons: ℹ️ ✅ ⚠️ 🚨. Split at 4000 chars on newlines, never inside an entity. Buttons go on the last chunk. Link previews off. |
| Callback data | `tg:<8-hex nonce>:<option index>` (≤64 bytes); `tg:done` marks an answered prompt |
| Errors | 429 → wait `retry_after` and retry (3×). 409 → conflict error. The token is redacted from every error |

## Security

- **The bot token is a password.** Anyone who has it can message your chat as the bot and read its updates. Keep it in `~/.config/tgnotify/config.json` (written with mode 0600) or in environment or CI secrets, and never in a repo. If it leaks, revoke it with @BotFather → `/revoke`.
- The token is redacted from all error messages. The library never logs request URLs.
- A button tap is accepted only from the configured `chat_id`. Taps from other chats that message your bot are ignored.
- Messages are sent with HTML parse mode, and text is escaped unless you pass `html`/`-html`. Don't pass untrusted input with `html`.
- No runtime dependencies, so there's no third-party supply chain in Go, Python or Node. Network calls go only to `api.telegram.org`, or to `TGNOTIFY_API_BASE` if you set it.
- Run `tgnotify setup` in a real terminal. Don't paste the token into chat tools or shared logs.

## Develop

`just test` runs the Go, Python and TS suites, all against a local stub. No real Telegram calls are made.
