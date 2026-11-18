# CLAUDE.md — tgnotify

Telegram alerts + tap-to-approve buttons, plus a one-time-code web login. **Public repo** `Shanki200801/tgnotify` (MIT). README.md is the user manual and the cross-language contract; this file is for agents picking the work up cold.

## Shape

| Path | What |
|---|---|
| `tgnotify.go` (+`tgnotify_test.go`) | Go library (module `github.com/shanki200801/tgnotify`, Go ≥1.18) |
| `cmd/tgnotify/main.go` (+test) | Go CLI: `setup`, `send`, `file`, `ask`, `prompt`, `collect`, `run`. Flags must precede positionals |
| `python/src/tgnotify/__init__.py` | Python lib (≥3.8, stdlib only, hatchling) |
| `python/src/tgnotify/login.py` | `tgnotify.login`: Telegram one-time-code login (framework-agnostic `Login`, `MemoryStore`, `MemoryLimiter`) |
| `ts/index.ts` | TS/Node lib (Node ≥18) → `dist/` via `tsc` on `prepare` |
| `ts/login.ts` | `tgnotify/login` export: `createLogin`, `memoryStore`, `memoryLimiter`, `kvStore`, `cfRateLimiter`, `guard()`. Web-standard APIs only; must **not** import `./index.ts` (keeps Workers bundles free of `node:` imports) |
| `docs/telegram-login.md` | Login recipe: flow, security model, known gap, usage for Workers/Node/Flask, test checklist |
| `justfile` | `just test` (go + py + ts), `just install` (CLI → `~/.local/bin`) |

**Zero runtime dependencies in every language. Keep it that way** (no supply chain is a stated security property).

## Contract (all three implementations must agree — change all or none)

- Config: env `TGNOTIFY_TOKEN`/`TGNOTIFY_CHAT_ID` (fallback `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`) override `$TGNOTIFY_CONFIG` or `~/.config/tgnotify/config.json` (0600). Values are whitespace-trimmed (v0.1.1 fix: `jq -r` newline broke a CI token).
- State: `$TGNOTIFY_STATE` or `~/.config/tgnotify/state.json` = `{offset, answers[]}`; any poller saves every tap it sees; latest tap per message wins; taps only accepted from the configured chat.
- Callback data `tg:<8-hex nonce>:<idx>`; `tg:done` for collapsed prompts.
- HTML parse mode, escaped unless `html`; split at 4000 chars on newlines; 429 → retry_after ×3; 409 → ConflictError.
- **The token is redacted from every error**, including URL-escaped forms. Never log request URLs.
- Login spec (TS = Python): 6-digit rejection-sampled code, 300 s TTL; ≤5 sends/60 s app-wide; ≤5 verifies/60 s per challenge (challenge deleted on overflow → ≤25 guesses/code); 30-day HMAC session `b64u(JSON{exp}).b64u(HMAC)`; secret ≥32 chars or fail closed; constant-time compares; store holds HMAC(secret, id:code), never the code. Limiter must be atomic — Cloudflare KV is **not** (that was job-hunt's bug); use `cfRateLimiter` (`[[ratelimits]]` binding, per-location) or a Durable Object.

## Testing

`just test` — all suites run against a local stub via `TGNOTIFY_API_BASE`; never hit real Telegram in tests. TS: `npm test` (tsc + `node --test ts/test/*.test.mjs`). Python: `uv run --with pytest --with-editable . pytest` in `python/`.

## Releases & consumers

- Tags: `v0.1.0`, `v0.1.1`. **The login toolkit (PR #1, merged into main as 13fe8a7) is not tagged yet** — cut `v0.2.0` (bump `package.json` + `python/pyproject.toml`) before consumers pin it.
- Consumer: private `job-hunt` repo pins Python `tgnotify` at `rev = "v0.1.1"` (`[tool.uv.sources]`, `subdirectory = "python"`). Its Worker (`web/src/worker.ts`) has its own older login copy with the KV attempt-count race; migrating it to `tgnotify/login` is an open item there.

## Rules

- Security matters here (public repo, handles bot tokens). Never commit or print tokens/chat ids; never paste them into tests or docs (use obvious fakes like `123:ABC`).
- Commits use the GitHub noreply identity (configured). End commit messages with the Co-Authored-By line the harness gives. Use PRs for non-trivial changes.
- WSL git 2.34 rejects `~/.gitconfig`'s `merge.conflictstyle=zdiff3` on switch/pull/merge (even with `-c`). Workaround: `grep -vi conflictstyle ~/.gitconfig > $SCRATCH/gitconfig; GIT_CONFIG_GLOBAL=$SCRATCH/gitconfig git ...`.
- Keep README's Contract table and `docs/telegram-login.md` in sync with code changes.
