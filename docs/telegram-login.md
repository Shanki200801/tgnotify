# Telegram one-time-code login

A reusable login for **single-owner web apps**. The app sends a 6-digit code to your Telegram chat through your tgnotify bot, you type it in, and you get a signed session cookie. It replaces passwords or a paid identity provider in personal tools (dashboards, admin pages, home-lab apps).

It was first built for `job-hunt` (a Cloudflare Worker). The code now ships in this repo as a toolkit, so other projects can import it instead of copying it:

- **TypeScript / Node 19+ / Cloudflare Workers:** `import { createLogin } from "tgnotify/login"` (`ts/login.ts`)
- **Python 3.8+ (stdlib only):** `from tgnotify.login import Login` (`python/src/tgnotify/login.py`)

Go is not covered.

> **Scope.** One owner, one Telegram chat. It is not multi-user auth. Whoever controls the Telegram account controls the app.

---

## How it works

```
Browser                         App (server)                        Telegram
   │  GET /anything                 │                                   │
   │ ─────────────────────────────▶ │ no valid session → 302 /login     │
   │  POST /auth/send               │                                   │
   │ ─────────────────────────────▶ │ rate-limit sends                  │
   │                                │ code = random 6 digits            │
   │                                │ id   = random challenge id        │
   │                                │ store HMAC(secret, id:code), TTL  │
   │                                │ sendMessage(chat_id, code, IP) ─▶ │ 📱 code arrives
   │ ◀── Set-Cookie: challenge=id ─ │                                   │
   │  POST /auth/verify {code}      │                                   │
   │ ─────────────────────────────▶ │ count attempt (limiter)           │
   │                                │ HMAC(secret, id:code) == stored ? │
   │ ◀── Set-Cookie: session=… ──── │ delete challenge; sign session    │
   │  GET / (cookie)                │ verify HMAC + exp → serve         │
```

**Pieces**

| Piece | What it is |
|---|---|
| `token`, `chatId` | The bot token and chat id tgnotify uses. Sending a message doesn't interfere with tgnotify's `getUpdates` polling. |
| `secret` | A random key of 32+ chars. It signs sessions and hashes stored codes. **Rotating it logs out every session.** |
| `store` | Short-lived challenge storage: `challenge id → HMAC`, with a TTL. |
| `limiter` | Atomic fixed-window counter: `hit(key, limit, window) → allowed`. **It must be strongly consistent** (see "Known gap"). |

**Defaults (the same in TS and Python)**

| Setting | Value | Why |
|---|---|---|
| Code | 6 digits, CSPRNG, uniform (rejection sampled) | Typable on a phone |
| Code TTL | 300 s | Short window for guessing |
| Verify attempts | ≤ 5 per 60 s per challenge. On overflow the challenge is deleted, so ≤ 25 guesses per code | ≤ 25 / 10⁶ success chance per code |
| Code sends | ≤ 5 per 60 s, app-wide | Stops Telegram spam and code farming. Each send pings you. |
| Session | 30 days, `HttpOnly; Secure; SameSite=Strict; Path=/` | Not readable by JS, not sent cross-site |
| Session format | `base64url(JSON{exp}) "." base64url(HMAC-SHA256(secret, payload))` | Stateless and verifiable |

---

## Security model

**Protects against:**
- **Anyone without your Telegram account.** They can't get a code. A code request still pings you, with the requester's IP.
- **Guessing codes**, as long as attempts are counted atomically (see below).
- **Stolen or tampered cookies.** Cookies are HMAC-signed with an expiry, and `HttpOnly` blocks theft through XSS.
- **CSRF.** `SameSite=Strict` on the cookies, and `/auth/*` POSTs must come from the site's own origin with `Content-Type: application/json`.
- **Leaked storage.** The store holds `HMAC(secret, id:code)`, never the plain code.
- **Inline-script XSS holes in the login page.** The login script is a separate file (`/login.js`) and the page sends a strict CSP.

**Does not protect against:**
- A compromised Telegram account or unlocked phone. Turn on Telegram 2FA (a cloud password).
- Malware in your browser profile. Session cookies are bearer tokens.
- Revoking one session alone. Sessions are stateless; rotating `secret` revokes all of them.

**Requirements (the toolkit enforces 1–3):**
1. **Fail closed.** If the token, chat id or secret is missing, or the secret is shorter than 32 chars, nothing is served except a "Login is not configured" notice.
2. **Constant-time compares** for both the HMAC signature and the code hash.
3. **Public routes:** `/login`, `/login.js`, `/auth/send`, `/auth/verify`, `/auth/logout`. Unauthenticated page requests get a 302 to `/login`; `/api/*` gets 401.
4. **Never log or echo** codes, cookies, the token or the secret. The challenge cookie carries only a random id. Telegram error text is never returned to the client.
5. **HTML-escape** the app name and requester info in the Telegram message (`parse_mode: HTML`).
6. **Proxies and origin.** The requester IP is informational only. If you're behind a proxy that rewrites the host, set `publicOrigin` / `public_origin`.

### Why the limiter must be atomic

The first version (job-hunt) counted attempts in Workers KV. KV is eventually consistent (reads can be stale for about 60 s), so parallel `/auth/verify` requests against one challenge each read `n = 0`, and the cap doesn't hold. A fast attacker could try thousands of codes in one window.

The toolkit avoids this by counting in the **limiter**, not in KV:
- **Cloudflare:** the Rate Limiting binding (`cfRateLimiter`). Counters live within one Cloudflare location, which is enough for a personal tool.
- **Single Node or Python process:** `memoryLimiter` / `MemoryLimiter`. Its check and count run in one synchronous step (TS) or under one lock (Python).
- **Multiple servers:** implement `RateLimiter.hit` on Redis (`INCR` + `EXPIRE`), or on SQL (`UPDATE … SET n = n + 1 … RETURNING n`), or on a Durable Object.

Generation uses rejection sampling, not `uint32 % 1e6`, to avoid modulo bias.

---

## TypeScript (Node 19+, Cloudflare Workers, Deno, Bun)

Web-standard APIs only (WebCrypto, `fetch`, `Request`/`Response`), no npm dependencies, and it does not import the Node-only `index.ts`, so Workers bundles stay clean.

```bash
npm install github:shanki200801/tgnotify
```

**Cloudflare Worker**

`wrangler.toml`
```toml
kv_namespaces = [{ binding = "AUTH", id = "<kv namespace id>" }]

[[ratelimits]]
name = "AUTH_LIMIT"
namespace_id = "1001"
simple = { limit = 5, period = 60 }     # must match the 5-per-60s defaults
```

Secrets: `wrangler secret put TG_TOKEN`, `TG_CHAT_ID`, `SESSION_SECRET` (for example `openssl rand -base64 48`).

`src/index.ts`
```ts
import { createLogin, kvStore, cfRateLimiter } from "tgnotify/login";

interface Env { TG_TOKEN: string; TG_CHAT_ID: string; SESSION_SECRET: string;
                AUTH: KVNamespace; AUTH_LIMIT: { limit(o: { key: string }): Promise<{ success: boolean }> } }

export default {
  async fetch(req: Request, env: Env) {
    const login = createLogin({
      appName: "My App",
      token: env.TG_TOKEN, chatId: env.TG_CHAT_ID, secret: env.SESSION_SECRET,
      store: kvStore(env.AUTH),
      limiter: cfRateLimiter(env.AUTH_LIMIT),
    });
    const blocked = await login.guard(req);   // serves /login, /login.js, /auth/*; 302/401 otherwise
    if (blocked) return blocked;
    // ...your routes
    return new Response("hello");
  },
};
```

**Node (Express, Fastify, plain `http`)**

`createLogin` returns a Web `Response`, so for Node you convert it. Use the in-memory store and limiter, which are fine for one process (use Redis for several):

```ts
import { createLogin, memoryStore, memoryLimiter } from "tgnotify/login";

const login = createLogin({
  appName: "My App", token: process.env.TG_TOKEN!, chatId: process.env.TG_CHAT_ID!,
  secret: process.env.SESSION_SECRET!, store: memoryStore(), limiter: memoryLimiter(),
});

// in your request handler, with a Web Request built from the Node request:
const blocked = await login.guard(webReq);
if (blocked) { /* copy status, headers (all Set-Cookie values), and body onto res */ }
```

**Options** (all optional except the ones shown in the example): `codeTtlSec`, `sessionDays`, `sendsPerMinute`, `attemptsPerMinute`, `sessionCookie` / `challengeCookie` (names; change them if two apps share a domain), `publicOrigin`, `apiBase` (tests).

`login.isLoggedIn(req)` returns a boolean if you want to check a session yourself.

---

## Python (stdlib only, framework-agnostic)

`Login.guard` takes plain values and returns a `Response` (status, body, headers) that you map onto your framework.

```python
from tgnotify.login import Login

login = Login(app_name="My App", token=TOKEN, chat_id=CHAT_ID, secret=SECRET)

def guard(method, path, headers, body, url_origin):
    # headers: dict with lowercase keys; body: bytes; url_origin: "https://app.example"
    return login.guard(method, path, headers, body, url_origin)   # None → proceed
```

**Flask**
```python
from flask import Flask, request, Response as FResponse
app = Flask(__name__)

@app.before_request
def _auth():
    r = login.guard(request.method, request.path,
                    {k.lower(): v for k, v in request.headers.items()},
                    request.get_data(), request.host_url.rstrip("/"))
    if r is not None:
        return FResponse(r.body, r.status, headers=r.headers)   # keeps repeated Set-Cookie
```

**FastAPI** works the same way: call `guard` in a middleware, with `await request.body()` for the body, and copy `headers` into a `Response`.

Notes:
- Sending uses `tgnotify.Client`, so the token is redacted from errors. A Telegram failure returns 502 without the error text.
- `MemoryStore` and `MemoryLimiter` are lock-guarded and exact within one process. For several worker processes, pass your own `store=` / `limiter=` objects with the same `get/put/delete` and `hit` methods, backed by Redis or SQL.
- The Python login page (`LOGIN_SCRIPT`) mirrors the TS one, so the two stay in sync when either changes.

---

## Test checklist

Offline tests cover the logic (`just test`): sessions (valid, expired, forged), fail-closed config, origin/JSON checks, the full send→verify flow, single-use codes, per-challenge attempt caps under parallel load, send limits, expiry, logout, CSP headers and the escaped app name.

Against a deployed instance, `B=https://your-app`:

```bash
c() { curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "$@"; }
c $B/                                                                                 # 302 → /login
c $B/api/anything                                                                     # 401
c $B/login                                                                            # 200
c -X POST -H 'Origin: https://evil.example' -H 'Content-Type: application/json' -d '{}' $B/auth/send   # 403
c -X POST -H "Origin: $B" -H 'Content-Type: application/json' -d '{"code":"123456"}' $B/auth/verify   # 400 (no challenge)
c -H 'Cookie: tg_session=eyJleHAiOjk5OTk5OTk5OTl9.AAAA' $B/api/anything                               # 401 (forged)
```

Then by hand:
- [ ] A real login: request a code, it arrives on Telegram with your IP, and entering it lands you in the app.
- [ ] **Wrong code ×6 in parallel** (`xargs -P 20`) is capped: you get 401 five times, then 429, and the challenge is gone.
- [ ] Six **Send** clicks within a minute: the sixth gets 429.
- [ ] Rotating the secret logs you out.
- [ ] Removing a secret makes the app serve "not configured" and no data.

---

## Operations

- **Log out everywhere:** rotate `SESSION_SECRET` and redeploy.
- **Reusing your tgnotify bot:** sending codes is safe while tgnotify is polling `getUpdates`. Use a **separate bot** only if you want login codes in a different chat.
- **Telegram down:** you can't log in, and existing sessions keep working. For break-glass access, keep a second login method behind a separate secret.
- **Node 18:** `globalThis.crypto` is not on by default there, so run with `--experimental-global-webcrypto` or use Node 19+.

## Changelog

- **v2 (this repo, Nov 2026):** the login is now a toolkit (`tgnotify/login` for TS, `tgnotify.login` for Python). It has pluggable stores and limiters, a Cloudflare adapter, and a shipped login page with CSP. The spec was unified: sends ≤ 5 per 60 s, verify ≤ 5 per 60 s per challenge. The earlier Python sketch used 1 send per 60 s and 5 attempts total, which is now gone.
- **v1 (job-hunt, Nov 2026):** KV-only attempt counting (has the concurrency gap above) and `uint32 % 1e6` code generation.
