# Telegram one-time-code login

A small, reusable pattern for **single-owner web apps**: the app sends a 6-digit code to your Telegram chat through your tgnotify bot, you type it in, and you get a signed session cookie. It replaces passwords or a paid identity provider in personal tools (dashboards, admin pages, home-lab apps).

It was first built for the `job-hunt` web app (a Cloudflare Worker). This document is the handoff: how it works, the security model, a reference implementation with the known gaps fixed, how to port it, and how to test it.

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
   │                                │ store HMAC(secret, id:code), n=0  │
   │                                │ sendMessage(chat_id, code, IP) ─▶ │ 📱 code arrives
   │ ◀── Set-Cookie: challenge=id ─ │                                   │
   │  POST /auth/verify {code}      │                                   │
   │ ─────────────────────────────▶ │ rate-limit + count attempts       │
   │                                │ HMAC(secret, id:code) == stored ? │
   │ ◀── Set-Cookie: session=… ──── │ delete challenge; sign session    │
   │  GET / (cookie)                │ verify HMAC + exp → serve         │
```

**Pieces**

| Piece | What it is |
|---|---|
| `TG_TOKEN`, `TG_CHAT_ID` | The same bot token and chat id that tgnotify uses (`~/.config/tgnotify/config.json` / `TGNOTIFY_*`). Sending a message doesn't interfere with tgnotify's `getUpdates` polling. |
| `SESSION_SECRET` | A random key of 32+ chars. It signs sessions and hashes stored codes. **Rotating it logs out every session.** |
| Challenge store | Short-lived storage: `challenge id → {hmac, attempts}` with a 5-min TTL. |
| Rate limiter | Caps code sends and verify attempts. **It must hold under concurrency** (see "Known gap"). |

**Defaults**

| Setting | Value | Why |
|---|---|---|
| Code | 6 digits, CSPRNG, uniform | Typable on a phone |
| Code TTL | 300 s | Short window for guessing |
| Attempts per code | ≤ 5 per minute, so ≤ 25 over a 5-minute code | At most 25 / 10⁶ (0.0025%) success chance per code |
| Code sends | ≤ 5 per minute | Stops Telegram spam and code farming. Each send pings you. |
| Session | 30 days, `HttpOnly; Secure; SameSite=Strict; Path=/` | Not readable by JS, not sent cross-site |
| Session format | `base64url(JSON{exp}) "." base64url(HMAC-SHA256(secret, payload))` | Stateless and verifiable |

---

## Security model

**Protects against:**
- **Anyone without your Telegram account.** They can't get a code. A code request still pings you, with the requester's IP and city.
- **Guessing codes**, as long as attempts are capped with a consistent counter (see below). With the reference limits, the odds are at most 25 in 10⁶ per code.
- **Stolen or tampered cookies.** Cookies are HMAC-signed with an expiry, and `HttpOnly` blocks theft through XSS.
- **CSRF.** `SameSite=Strict` on the cookies, plus POSTs must come from the site's own origin with `Content-Type: application/json`.
- **Leaked storage.** The store holds `HMAC(secret, id:code)`, never the plain code.

**Does not protect against:**
- A compromised Telegram account or unlocked phone. Turn on Telegram 2FA (a cloud password).
- Malware in your browser profile. Session cookies are bearer tokens.
- Revoking one session alone. Sessions are stateless; rotating `SESSION_SECRET` revokes all of them. Add a session id plus a denylist if you need per-session revocation.

**Requirements:**
1. **Fail closed.** If any secret is missing, or `SESSION_SECRET` is shorter than 32 chars, serve nothing except a "not configured" notice.
2. **Constant-time compares** for both the HMAC signature and the code hash.
3. **Public routes:** `/login`, the login script, `/auth/send`, `/auth/verify` and `/auth/logout`, nothing else. Unauthenticated page requests get a 302 to `/login`, and APIs get 401.
4. **Never log or echo** codes, cookies or the secret. The challenge cookie carries only a random id.
5. **HTML-escape** anything you put into the Telegram message when using `parse_mode: "HTML"`. Header values such as the city can contain `<`.
6. **A strict CSP**, for example `default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'`, with the login script as a separate file rather than inline.

### Known gap in the first (job-hunt) version: attempt counting on KV

`job-hunt` v1 keeps the attempt counter and the send limit in **Workers KV**. KV is eventually consistent: reads can be stale for up to about 60 seconds, and a key accepts about one write per second. So many **parallel** `/auth/verify` requests against one challenge each read `n = 0`, and the 5-attempt cap doesn't hold. A fast attacker could try thousands of codes within one 5-minute window, roughly a 1% chance per 10,000 guesses. It still requires triggering a send first, which pings your Telegram.

**Fix (used below):** count attempts with something strongly consistent. Two options:
- **Cloudflare Rate Limiting binding** (`[[ratelimits]]`): counters live **within one Cloudflare location**. That stops bulk guessing from one client, but an attacker spreading requests across many locations gets a separate budget at each. It's the simplest option and good enough for a personal tool.
- **A Durable Object** per challenge, for strict, globally consistent counting: exactly N attempts per code, everywhere.

Off Cloudflare, use Redis `INCR` with `EXPIRE`, or a SQL row updated with `UPDATE … SET n = n + 1 … RETURNING n`.

Also generate the code with **rejection sampling** instead of `uint32 % 1e6`. The bias from the modulo is tiny, but it's free to remove.

---

## Reference implementation (Cloudflare Worker, TypeScript)

This is a drop-in module with the gap above fixed. It needs no npm dependencies.

`wrangler.toml`

```toml
kv_namespaces = [{ binding = "AUTH", id = "<kv namespace id>" }]   # challenges (TTL'd)

[[ratelimits]]                 # strongly limits verify attempts + sends
name = "AUTH_LIMIT"
namespace_id = "1001"
simple = { limit = 5, period = 60 }
```

Secrets: `wrangler secret put TG_TOKEN`, `TG_CHAT_ID` and `SESSION_SECRET` (for example `openssl rand -base64 48`).

`src/tglogin.ts`

```ts
export interface AuthEnv {
  TG_TOKEN?: string;
  TG_CHAT_ID?: string;
  SESSION_SECRET?: string;
  AUTH: KVNamespace;
  AUTH_LIMIT: { limit(o: { key: string }): Promise<{ success: boolean }> };
}

const APP = "My App";              // shown in the Telegram message
const COOKIE = "app_session";
const CHALLENGE = "app_challenge";
const SESSION_DAYS = 30, CODE_TTL = 300, MAX_ATTEMPTS = 5;

const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => atob(s.replace(/-/g, "+").replace(/_/g, "/"));
const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

async function hmac(secret: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
function safeEq(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function sixDigits() { // rejection sampling: uniform 000000–999999
  const max = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  for (;;) { const x = crypto.getRandomValues(new Uint32Array(1))[0]; if (x < max) return String(x % 1_000_000).padStart(6, "0"); }
}
function readCookie(req: Request, name: string) {
  for (const part of (req.headers.get("Cookie") || "").split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return null;
}
const json = (data: unknown, status = 200, extra: HeadersInit = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra } });
const cookieAttrs = (maxAge: number) => `Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

export const authConfigured = (env: AuthEnv) =>
  !!(env.TG_TOKEN && env.TG_CHAT_ID && env.SESSION_SECRET && env.SESSION_SECRET.length >= 32);

export async function isLoggedIn(req: Request, env: AuthEnv): Promise<boolean> {
  if (!authConfigured(env)) return false;
  const c = readCookie(req, COOKIE);
  const [payload, sig] = (c || "").split(".");
  if (!payload || !sig || !safeEq(sig, await hmac(env.SESSION_SECRET!, payload))) return false;
  try { const p = JSON.parse(fromB64u(payload)); return typeof p.exp === "number" && p.exp * 1000 > Date.now(); }
  catch { return false; }
}

async function sendCode(req: Request, env: AuthEnv) {
  if (!(await env.AUTH_LIMIT.limit({ key: "send" })).success) return json({ error: "Too many requests, wait a minute." }, 429);
  const code = sixDigits();
  const id = b64u(crypto.getRandomValues(new Uint8Array(18)));
  await env.AUTH.put(`ch:${id}`, await hmac(env.SESSION_SECRET!, `${id}:${code}`), { expirationTtl: CODE_TTL });
  const cf = (req as any).cf || {};
  const from = escapeHtml([req.headers.get("CF-Connecting-IP"), cf.city, cf.country].filter(Boolean).join(", ") || "unknown");
  const r = await fetch(`https://api.telegram.org/bot${env.TG_TOKEN!.trim()}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: env.TG_CHAT_ID!.trim(), parse_mode: "HTML",
      text: `🔐 <b>${escapeHtml(APP)} login code: ${code}</b>\nValid ${CODE_TTL / 60} min. Requested from ${from}.\nIf this wasn't you, ignore it.` }),
  });
  if (!r.ok) return json({ error: "Couldn't send the code." }, 502);
  return json({ ok: true }, 200, { "Set-Cookie": `${CHALLENGE}=${id}; ${cookieAttrs(CODE_TTL)}` });
}

async function verifyCode(req: Request, env: AuthEnv) {
  const id = readCookie(req, CHALLENGE);
  const body: any = await req.json().catch(() => null);
  const code = String(body?.code || "").replace(/\D/g, "");
  if (!id || code.length !== 6) return json({ error: "Request a code first." }, 400);
  // Strongly limited: parallel guesses can't exceed MAX_ATTEMPTS per challenge per period.
  if (!(await env.AUTH_LIMIT.limit({ key: `verify:${id}` })).success) {
    await env.AUTH.delete(`ch:${id}`);
    return json({ error: "Too many attempts. Request a new code." }, 429);
  }
  const stored = await env.AUTH.get(`ch:${id}`);
  if (!stored) return json({ error: "Code expired. Request a new one." }, 400);
  if (!safeEq(stored, await hmac(env.SESSION_SECRET!, `${id}:${code}`))) return json({ error: "Wrong code." }, 401);
  await env.AUTH.delete(`ch:${id}`);
  const payload = b64u(enc.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400 })));
  const h = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
  h.append("Set-Cookie", `${COOKIE}=${payload}.${await hmac(env.SESSION_SECRET!, payload)}; ${cookieAttrs(SESSION_DAYS * 86400)}`);
  h.append("Set-Cookie", `${CHALLENGE}=; ${cookieAttrs(0)}`);
  return new Response(JSON.stringify({ ok: true }), { headers: h });
}

/**
 * Call first in your fetch handler. Returns a Response for auth routes or
 * unauthenticated requests, or null when the request may proceed.
 * You serve /login (HTML + a same-origin script) yourself; this lets it through.
 */
export async function guard(req: Request, env: AuthEnv, publicPaths = ["/login", "/login.js"]): Promise<Response | null> {
  const url = new URL(req.url);
  if (req.method === "POST" && (req.headers.get("Origin") !== url.origin ||
      !(req.headers.get("Content-Type") || "").startsWith("application/json")))
    return json({ error: "bad request" }, 403);
  if (!authConfigured(env)) return new Response("Login is not configured.", { status: 403 });
  if (req.method === "POST" && url.pathname === "/auth/send") return sendCode(req, env);
  if (req.method === "POST" && url.pathname === "/auth/verify") return verifyCode(req, env);
  if (url.pathname === "/auth/logout")
    return new Response(null, { status: 302, headers: { Location: "/login", "Set-Cookie": `${COOKIE}=; ${cookieAttrs(0)}` } });
  if (publicPaths.includes(url.pathname)) return null;
  if (await isLoggedIn(req, env)) return null;
  return req.method === "GET" && !url.pathname.startsWith("/api/")
    ? new Response(null, { status: 302, headers: { Location: "/login" } })
    : json({ error: "not logged in" }, 401);
}
```

Usage:

```ts
import { guard, type AuthEnv } from "./tglogin";
export default {
  async fetch(req: Request, env: AuthEnv & { /* your bindings */ }) {
    const blocked = await guard(req, env);
    if (blocked) return blocked;
    // ... your routes; `/login` and `/login.js` are yours to serve
  },
};
```

The login page needs two steps: a **Send code** button that does `POST /auth/send`, then a numeric input (`inputmode="numeric" autocomplete="one-time-code"`) that does `POST /auth/verify {code}` and redirects to `/` on success. Both requests send `Content-Type: application/json`. Use [job-hunt's `web/src/login.html` and `login.js.txt`](https://github.com/Shanki200801/job-hunt/tree/main/web/src) as a starting point. That repo is private; copy the files over when reusing them.

---

## Porting to other stacks

The algorithm doesn't depend on the stack. Replace three things:

| Need | Cloudflare | Python (FastAPI/Flask) | Go | Node (Express) |
|---|---|---|---|---|
| Send to Telegram | `fetch` sendMessage | `tgnotify.Client().send(text, html=True)` | `tgnotify.Client.Send` | `tgnotify` `Client.send` |
| Challenge store with TTL | KV | Redis `SETEX`, or SQLite with an `expires_at` column | Redis or `sync.Map` + expiry (single process) | Redis or an in-memory `Map` (single process) |
| Consistent counter | `[[ratelimits]]` / Durable Object | Redis `INCR` + `EXPIRE` | Redis `INCR`, or a mutex-guarded map | Redis `INCR` |
| HMAC + constant-time compare | WebCrypto + `safeEq` | `hmac.new(...).digest()` + `hmac.compare_digest` | `crypto/hmac` + `hmac.Equal` | `crypto.createHmac` + `crypto.timingSafeEqual` |

**Python sketch.** The send and verify logic uses tgnotify; storage is in-process. For a real deployment, use Redis.

```python
import base64, hashlib, hmac, json, secrets, time, threading
import tgnotify

SECRET = "<32+ random chars>"
TTL, MAX_ATTEMPTS, SESSION_DAYS = 300, 5, 30
_lock, _challenges, _last_send = threading.Lock(), {}, [0.0]

def _h(msg: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest()).decode().rstrip("=")

def send_code(requester_ip: str) -> str | None:
    with _lock:
        if time.time() - _last_send[0] < 60:
            return None                                          # → 429
        _last_send[0] = time.time()
        code, cid = f"{secrets.randbelow(10**6):06d}", secrets.token_urlsafe(18)
        _challenges[cid] = {"h": _h(f"{cid}:{code}"), "n": 0, "exp": time.time() + TTL}
    tgnotify.notify(f"Login code: {code}\nValid 5 min. From {requester_ip}.", title="My App", level="info")
    return cid                                                    # → challenge cookie

def verify_code(cid: str, code: str) -> str | None:
    with _lock:                                                  # strongly consistent in one process
        ch = _challenges.get(cid)
        if not ch or ch["exp"] < time.time() or ch["n"] >= MAX_ATTEMPTS:
            _challenges.pop(cid, None); return None
        ch["n"] += 1
        if not hmac.compare_digest(ch["h"], _h(f"{cid}:{code}")):
            return None
        del _challenges[cid]
    payload = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + SESSION_DAYS * 86400}).encode()).decode().rstrip("=")
    return f"{payload}.{_h(payload)}"                            # → session cookie

def session_ok(cookie: str | None) -> bool:
    try:
        payload, sig = (cookie or "").split(".")
        if not hmac.compare_digest(sig, _h(payload)):
            return False
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"] > time.time()
    except Exception:
        return False
```

Set the cookies with `httponly=True, secure=True, samesite="strict", path="/"`. Keep the Origin and JSON check on POSTs.

---

## Test checklist

Run these against a deployed instance. `B=https://your-app`.

```bash
c() { curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "$@"; }
c $B/                                   # 302 → /login
c $B/api/anything                       # 401
c $B/login                              # 200
c -X POST -H 'Origin: https://evil.example' -H 'Content-Type: application/json' -d '{}' $B/auth/send   # 403
c -X POST -H "Origin: $B" -H 'Content-Type: application/json' -d '{"code":"123456"}' $B/auth/verify   # 400 (no challenge)
c -H 'Cookie: app_session=eyJleHAiOjk5OTk5OTk5OTl9.AAAA' $B/api/anything                             # 401 (forged)
```

Then:
- [ ] A correctly signed but **expired** cookie gets 401. Mint one locally with the test secret in `wrangler dev`.
- [ ] A real login: request a code, it arrives on Telegram with your IP, entering it lands you in the app.
- [ ] **Wrong code ×6** in parallel (`xargs -P 20`) is capped. You get 429 and the challenge is gone. This is the KV-gap regression test.
- [ ] Two **Send** clicks within a minute: the second gets 429.
- [ ] Rotating `SESSION_SECRET` logs you out.
- [ ] Removing a secret makes the app serve "not configured" and no data.

## Operations

- **Log out everywhere:** rotate `SESSION_SECRET`, for example `openssl rand -base64 48 | tr -d '\n=+/' | gh secret set …`, then redeploy.
- **Reusing your tgnotify bot:** sending codes is safe while tgnotify is polling `getUpdates`. Use a **separate bot** only if you want login codes in a different chat.
- **Telegram down:** you can't log in, and existing sessions keep working. If you need break-glass access, keep a second login method behind a separate secret.

## Changelog

- **v1 (job-hunt, Nov 2026):** KV-only attempt counting (has the concurrency gap above) and `uint32 % 1e6` code generation.
- **This doc:** Rate Limiting binding for sends and verify attempts, rejection-sampled codes, HTML-escaped requester info, a cookie parser without regex, and a `guard()` helper.
