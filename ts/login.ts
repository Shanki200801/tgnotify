/**
 * tgnotify/login: Telegram one-time-code login for single-owner apps.
 *
 * The app DMs a 6-digit code through your bot; the user types it in and gets a
 * signed, HttpOnly session cookie. Web-standard APIs only (WebCrypto, fetch,
 * Request/Response), so it runs on Node 19+, Cloudflare Workers, Deno and Bun.
 * It does not import ./index.ts, so Workers bundles stay clean.
 *
 *   import { createLogin, memoryStore, memoryLimiter } from "tgnotify/login";
 *   const login = createLogin({
 *     appName: "My App", token, chatId, secret,      // secret: 32+ chars
 *     store: memoryStore(), limiter: memoryLimiter(), // see kvStore / cfRateLimiter
 *   });
 *   export default { async fetch(req) {
 *     const blocked = await login.guard(req);          // serves /login, /login.js, /auth/*
 *     if (blocked) return blocked;
 *     // ...your routes
 *   } };
 *
 * Spec (identical in the Python module):
 *   code      6 digits, uniform (rejection sampled), valid 300 s
 *   sends     at most 5 per 60 s, app-wide
 *   verify    at most 5 attempts per 60 s per challenge; the challenge is deleted on overflow
 *             (so at most 25 guesses per code over its 300 s life)
 *   session   30 days, HMAC-signed, stateless
 */

export const MIN_SECRET_LENGTH = 32;

// ---- pluggable interfaces ---------------------------------------------------

/** Short-lived key/value storage for challenges. Values are HMAC digests, never codes. */
export interface ChallengeStore {
  get(id: string): Promise<string | null>;
  put(id: string, value: string, ttlSec: number): Promise<void>;
  delete(id: string): Promise<void>;
}

/**
 * Counts one hit on `key`. Resolves true if the hit is within `limit` per `windowSec`.
 * The count and the check must be one atomic step, or parallel requests can overshoot.
 */
export interface RateLimiter {
  hit(key: string, limit: number, windowSec: number): Promise<boolean>;
}

export interface LoginConfig {
  appName: string;
  token: string;
  chatId: string | number;
  /** Telegram API base; override for tests. */
  apiBase?: string;
  /** Signs sessions and hashes codes. Rotating it logs everyone out. */
  secret: string;
  store: ChallengeStore;
  limiter: RateLimiter;
  codeTtlSec?: number;          // default 300
  sessionDays?: number;         // default 30
  sendsPerMinute?: number;      // default 5
  attemptsPerMinute?: number;   // default 5, per challenge
  sessionCookie?: string;       // default "tg_session"
  challengeCookie?: string;     // default "tg_challenge"
  /** Expected Origin for POSTs. Set this behind a proxy that rewrites the host. */
  publicOrigin?: string;
  now?: () => number;           // ms, default Date.now
  fetch?: typeof fetch;         // default globalThis.fetch
}

// ---- small helpers ----------------------------------------------------------

const enc = new TextEncoder();

function b64u(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64u(s: string): string {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(b + "=".repeat((4 - (b.length % 4)) % 4));
}

/** Escape text for Telegram HTML parse mode. */
export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function hmac(secret: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg))));
}

/** Constant-time string compare. Lengths are fixed (HMAC output), so the early return leaks nothing useful. */
export function safeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** Uniform 000000–999999 via rejection sampling (no modulo bias). */
export function sixDigitCode(): string {
  const max = 4294967296 - (4294967296 % 1_000_000); // largest multiple of 1e6 ≤ 2^32
  const a = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(a);
    if (a[0] < max) return String(a[0] % 1_000_000).padStart(6, "0");
  }
}

function readCookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("Cookie") || "").split(";")) {
    const t = part.trim();
    const i = t.indexOf("=");
    if (i > 0 && t.slice(0, i) === name) return t.slice(i + 1);
  }
  return null;
}

const json = (data: unknown, status = 200, extra: HeadersInit = {}) =>
  new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });

const cookieAttrs = (maxAge: number) =>
  `Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

// ---- session -----------------------------------------------------------------

/** Build a signed session token: base64url(JSON{exp}) "." HMAC. */
export async function signSession(secret: string, expSec: number): Promise<string> {
  const payload = b64u(enc.encode(JSON.stringify({ exp: expSec })));
  return `${payload}.${await hmac(secret, payload)}`;
}

/** True only for a correctly signed, unexpired token. */
export async function checkSession(secret: string, token: string | null, nowMs: number): Promise<boolean> {
  const [payload, sig, extra] = (token || "").split(".");
  if (!payload || !sig || extra !== undefined || secret.length < MIN_SECRET_LENGTH) return false;
  if (!safeEq(sig, await hmac(secret, payload))) return false;
  try {
    const p = JSON.parse(fromB64u(payload));
    return typeof p.exp === "number" && p.exp * 1000 > nowMs;
  } catch {
    return false;
  }
}

// ---- built-in stores (single process) -----------------------------------------

/** In-memory store. Fine for one process; use kvStore or Redis across instances. */
export function memoryStore(now: () => number = Date.now): ChallengeStore {
  const m = new Map<string, { v: string; exp: number }>();
  return {
    async get(id) {
      const e = m.get(id);
      if (!e) return null;
      if (e.exp <= now()) { m.delete(id); return null; }
      return e.v;
    },
    async put(id, v, ttl) { m.set(id, { v, exp: now() + ttl * 1000 }); },
    async delete(id) { m.delete(id); },
  };
}

/** In-memory fixed-window limiter. Synchronous, so each hit is atomic in one process. */
export function memoryLimiter(now: () => number = Date.now): RateLimiter {
  const m = new Map<string, { n: number; reset: number }>();
  return {
    async hit(key, limit, windowSec) {
      const t = now();
      let e = m.get(key);
      if (!e || e.reset <= t) {
        if (m.size > 10_000) for (const [k, v] of m) if (v.reset <= t) m.delete(k);
        e = { n: 0, reset: t + windowSec * 1000 };
        m.set(key, e);
      }
      e.n++;
      return e.n <= limit;
    },
  };
}

/** Minimal shape of a Workers KV namespace. */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/** Challenge store on Workers KV. KV can be stale for ~60 s, so keep counting in the limiter, not here. */
export function kvStore(ns: KVLike, prefix = "tglogin:"): ChallengeStore {
  return {
    get: (id) => ns.get(prefix + id),
    put: (id, v, ttl) => ns.put(prefix + id, v, { expirationTtl: Math.max(60, ttl) }),
    delete: (id) => ns.delete(prefix + id),
  };
}

/**
 * Workers Rate Limiting binding (`[[ratelimits]]`). Its limit and period come from
 * wrangler.toml, so set `simple = { limit = 5, period = 60 }` to match the defaults.
 * Counters are per Cloudflare location.
 */
export function cfRateLimiter(binding: { limit(o: { key: string }): Promise<{ success: boolean }> }): RateLimiter {
  return { hit: async (key) => (await binding.limit({ key })).success };
}

// ---- login page (no inline JS, so a strict CSP works) ------------------------

/** The login script served at /login.js. It talks to /auth/send and /auth/verify. */
export const LOGIN_SCRIPT = `(function () {
  var msg = document.getElementById("msg");
  var sendBtn = document.getElementById("send");
  var form = document.getElementById("verify");
  var code = document.getElementById("code");
  function show(text, ok) { msg.textContent = text; msg.className = ok ? "ok" : "err"; }
  function post(path, body) {
    return fetch(path, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, body: j }; });
    });
  }
  sendBtn.addEventListener("click", function () {
    sendBtn.disabled = true; show("Sending…", true);
    post("/auth/send", {}).then(function (r) {
      if (r.body.ok) { form.hidden = false; code.focus(); show("Code sent to Telegram.", true); }
      else show(r.body.error || "Could not send the code.", false);
    }).catch(function () { show("Network error.", false); })
      .then(function () { sendBtn.disabled = false; });
  });
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var value = code.value.replace(/\\D/g, "");
    post("/auth/verify", { code: value }).then(function (r) {
      if (r.body.ok) { location.replace("/"); }
      else { show(r.body.error || "Wrong code.", false); code.select(); }
    }).catch(function () { show("Network error.", false); });
  });
})();
`;

/** The login page. `appName` is escaped. Styles are inline; the script is /login.js. */
export function loginPageHtml(appName: string): string {
  const name = escapeHtml(appName);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in · ${name}</title>
<style>
  :root { color-scheme: light dark; --fg: #1b1b1f; --bg: #fafafa; --accent: #2a6df4; --err: #c62828; --ok: #2e7d32; }
  @media (prefers-color-scheme: dark) { :root { --fg: #eee; --bg: #121214; --accent: #7aa6ff; --err: #ff8a80; --ok: #81c784; } }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--fg);
         font: 16px/1.4 system-ui, sans-serif; padding: 16px; box-sizing: border-box; }
  main { width: 100%; max-width: 360px; }
  h1 { font-size: 1.4rem; margin: 0 0 .5rem; }
  p { margin: .5rem 0 1rem; opacity: .85; }
  button, input { font: inherit; width: 100%; box-sizing: border-box; padding: .75rem; border-radius: 8px; border: 1px solid #8884; }
  button { background: var(--accent); color: #fff; border: 0; cursor: pointer; margin-top: .5rem; }
  button:disabled { opacity: .6; cursor: default; }
  input { background: transparent; color: var(--fg); letter-spacing: .4em; text-align: center; font-size: 1.4rem; }
  label { display: block; margin-top: 1rem; font-size: .9rem; opacity: .8; }
  #msg { min-height: 1.4em; margin-top: 1rem; }
  #msg.ok { color: var(--ok); } #msg.err { color: var(--err); }
</style>
</head>
<body>
<main>
  <h1>${name}</h1>
  <p>We'll send a one-time code to your Telegram.</p>
  <button id="send" type="button">Send code</button>
  <form id="verify" hidden>
    <label for="code">Code from Telegram</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
    <button type="submit">Sign in</button>
  </form>
  <p id="msg" role="status"></p>
</main>
<script src="/login.js"></script>
</body>
</html>
`;
}

// ---- the login ---------------------------------------------------------------

export interface Login {
  /** True when the config is complete (secret ≥ 32 chars, Telegram set). */
  readonly configured: boolean;
  /** True for a valid, unexpired session cookie. */
  isLoggedIn(req: Request): Promise<boolean>;
  /**
   * Call first in your fetch handler. Returns a Response for login routes or for
   * unauthenticated requests, or null when the request may proceed.
   */
  guard(req: Request): Promise<Response | null>;
}

export function createLogin(cfg: LoginConfig): Login {
  const ttl = cfg.codeTtlSec ?? 300;
  const sessionSec = (cfg.sessionDays ?? 30) * 86400;
  const sendLimit = cfg.sendsPerMinute ?? 5;
  const attemptLimit = cfg.attemptsPerMinute ?? 5;
  const sessionName = cfg.sessionCookie ?? "tg_session";
  const challengeName = cfg.challengeCookie ?? "tg_challenge";
  const now = cfg.now ?? Date.now;
  const fetchFn = cfg.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const apiBase = (cfg.apiBase || "https://api.telegram.org").replace(/\/+$/, "");
  const token = (cfg.token || "").trim();
  const chatId = String(cfg.chatId ?? "").trim();
  const configured = !!(token && chatId && cfg.secret && cfg.secret.length >= MIN_SECRET_LENGTH);

  async function sendCode(req: Request): Promise<Response> {
    if (!(await cfg.limiter.hit("send", sendLimit, 60)))
      return json({ error: "Too many requests, wait a minute." }, 429);
    const code = sixDigitCode();
    const id = b64u(crypto.getRandomValues(new Uint8Array(18)));
    await cfg.store.put(id, await hmac(cfg.secret, `${id}:${code}`), ttl);

    const cf = (req as Request & { cf?: { city?: string; country?: string } }).cf || {};
    const from = escapeHtml([req.headers.get("CF-Connecting-IP"), cf.city, cf.country]
      .filter(Boolean).join(", ") || "unknown");
    const r = await fetchFn(`${apiBase}/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        parse_mode: "HTML",
        text: `🔐 <b>${escapeHtml(cfg.appName)} login code: ${code}</b>\n` +
          `Valid ${Math.round(ttl / 60)} min. Requested from ${from}.\n` +
          `If this wasn't you, ignore it.`,
      }),
    });
    // The response body can contain the token or the code, so it is never read or returned.
    if (!r.ok) return json({ error: "Couldn't send the code." }, 502);
    return json({ ok: true }, 200, { "Set-Cookie": `${challengeName}=${id}; ${cookieAttrs(ttl)}` });
  }

  async function verifyCode(req: Request): Promise<Response> {
    const id = readCookie(req, challengeName);
    const body = (await req.json().catch(() => null)) as { code?: unknown } | null;
    const code = String(body?.code ?? "").replace(/\D/g, "");
    if (!id || code.length !== 6) return json({ error: "Request a code first." }, 400);

    // Count the attempt before checking the code. On overflow, drop the challenge.
    if (!(await cfg.limiter.hit(`verify:${id}`, attemptLimit, 60))) {
      await cfg.store.delete(id);
      return json({ error: "Too many attempts. Request a new code." }, 429);
    }
    const stored = await cfg.store.get(id);
    if (!stored) return json({ error: "Code expired. Request a new one." }, 400);
    if (!safeEq(stored, await hmac(cfg.secret, `${id}:${code}`)))
      return json({ error: "Wrong code." }, 401);

    await cfg.store.delete(id);
    const session = await signSession(cfg.secret, Math.floor(now() / 1000) + sessionSec);
    const h = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
    h.append("Set-Cookie", `${sessionName}=${session}; ${cookieAttrs(sessionSec)}`);
    h.append("Set-Cookie", `${challengeName}=; ${cookieAttrs(0)}`);
    return new Response(JSON.stringify({ ok: true }), { headers: h });
  }

  const htmlHeaders = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; " +
      "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
  };

  const login: Login = {
    configured,

    async isLoggedIn(req) {
      if (!configured) return false;
      return checkSession(cfg.secret, readCookie(req, sessionName), now());
    },

    async guard(req) {
      const url = new URL(req.url);
      const path = url.pathname;

      if (path.startsWith("/auth/")) {
        if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
        const origin = cfg.publicOrigin ?? url.origin;
        if (req.headers.get("Origin") !== origin ||
            !(req.headers.get("Content-Type") || "").startsWith("application/json"))
          return json({ error: "bad request" }, 403);
      }

      // Fail closed: nothing is served (except this notice) until the config is complete.
      if (!configured)
        return new Response("Login is not configured.", { status: 503, headers: { "Content-Type": "text/plain" } });

      if (req.method === "GET" && path === "/login")
        return new Response(loginPageHtml(cfg.appName), { headers: htmlHeaders });
      if (req.method === "GET" && path === "/login.js")
        return new Response(LOGIN_SCRIPT, {
          headers: { ...htmlHeaders, "Content-Type": "text/javascript; charset=utf-8" },
        });

      if (path === "/auth/send") return sendCode(req);
      if (path === "/auth/verify") return verifyCode(req);
      if (path === "/auth/logout")
        return json({ ok: true }, 200, { "Set-Cookie": `${sessionName}=; ${cookieAttrs(0)}` });

      if (await login.isLoggedIn(req)) return null;
      return req.method === "GET" && !path.startsWith("/api/")
        ? new Response(null, { status: 302, headers: { Location: "/login" } })
        : json({ error: "not logged in" }, 401);
    },
  };
  return login;
}
