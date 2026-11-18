import assert from "node:assert/strict";
import { test } from "node:test";
import * as L from "../../dist/login.js";

const SECRET = "x".repeat(40);
const ORIGIN = "https://app.example";

// Fake Telegram: records sendMessage texts and extracts the code from them.
function telegram({ ok = true } = {}) {
  const sent = [];
  const fetch = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return new Response(JSON.stringify({ ok }), { status: ok ? 200 : 500 });
  };
  const codeFromLast = () => sent.at(-1).body.text.match(/login code: (\d{6})/)[1];
  return { sent, fetch, codeFromLast };
}

function setup(over = {}) {
  const tg = telegram(over.tg);
  const login = L.createLogin({
    appName: "Test <App>",
    token: " 123:ABC \n",
    chatId: "42",
    secret: SECRET,
    store: L.memoryStore(),
    limiter: L.memoryLimiter(),
    fetch: tg.fetch,
    ...over.cfg,
  });
  return { login, tg };
}

const post = (path, body, headers = {}) =>
  new Request(ORIGIN + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, ...headers },
    body: JSON.stringify(body ?? {}),
  });
const get = (path, headers = {}) => new Request(ORIGIN + path, { headers });
const cookieFrom = (res, name) => {
  for (const c of res.headers.getSetCookie()) {
    if (c.startsWith(name + "=")) return c.split(";")[0].slice(name.length + 1);
  }
  return null;
};
const challengeHeader = (res) => `tg_challenge=${cookieFrom(res, "tg_challenge")}`;

async function sendAndCode(login, tg) {
  const res = await login.guard(post("/auth/send"));
  assert.equal(res.status, 200);
  return { challenge: challengeHeader(res), code: tg.codeFromLast() };
}

test("codes are always 6 digits", () => {
  for (let i = 0; i < 2000; i++) assert.match(L.sixDigitCode(), /^\d{6}$/);
});

test("session: valid, expired, forged, malformed", async () => {
  const now = Date.now();
  const good = await L.signSession(SECRET, Math.floor(now / 1000) + 60);
  assert.equal(await L.checkSession(SECRET, good, now), true);
  const expired = await L.signSession(SECRET, Math.floor(now / 1000) - 1);
  assert.equal(await L.checkSession(SECRET, expired, now), false);
  const [p] = good.split(".");
  const forged = `${p}.AAAA`;
  assert.equal(await L.checkSession(SECRET, forged, now), false);
  assert.equal(await L.checkSession(SECRET, good + ".extra", now), false);
  assert.equal(await L.checkSession(SECRET, null, now), false);
  assert.equal(await L.checkSession("short", good, now), false);
});

test("fails closed when the config is incomplete", async () => {
  for (const cfg of [{ secret: "short" }, { secret: "" }, { token: "" }]) {
    const { login } = setup({ cfg });
    assert.equal(login.configured, false);
    const res = await login.guard(get("/"));
    assert.equal(res.status, 503);
    assert.equal(await res.text(), "Login is not configured.");
  }
});

test("unauthenticated pages redirect; APIs get 401", async () => {
  const { login } = setup();
  const page = await login.guard(get("/dashboard"));
  assert.equal(page.status, 302);
  assert.equal(page.headers.get("Location"), "/login");
  assert.equal((await login.guard(get("/api/x"))).status, 401);
  assert.equal(await login.guard(get("/login")).then((r) => r.status), 200);
});

test("cross-origin or non-JSON /auth POSTs get 403", async () => {
  const { login, tg } = setup();
  const evil = await login.guard(post("/auth/send", {}, { Origin: "https://evil.example" }));
  assert.equal(evil.status, 403);
  const form = await login.guard(new Request(ORIGIN + "/auth/send", {
    method: "POST", headers: { Origin: ORIGIN, "Content-Type": "text/plain" }, body: "{}",
  }));
  assert.equal(form.status, 403);
  assert.equal(tg.sent.length, 0, "nothing sent to Telegram");
});

test("full flow: send, verify with the code, get a session", async () => {
  const { login, tg } = setup();
  const { challenge, code } = await sendAndCode(login, tg);
  assert.equal(tg.sent[0].url, "https://api.telegram.org/bot123:ABC/sendMessage");
  assert.equal(tg.sent[0].body.chat_id, "42");
  assert.match(tg.sent[0].body.text, /Test &lt;App&gt; login code/, "app name is HTML-escaped");

  const res = await login.guard(post("/auth/verify", { code }, { Cookie: challenge }));
  assert.equal(res.status, 200);
  const session = cookieFrom(res, "tg_session");
  assert.ok(session);
  const sc = res.headers.getSetCookie().find((c) => c.startsWith("tg_session="));
  assert.match(sc, /HttpOnly/);
  assert.match(sc, /Secure/);
  assert.match(sc, /SameSite=Strict/);

  const home = await login.guard(get("/", { Cookie: `tg_session=${session}` }));
  assert.equal(home, null, "authenticated request is allowed through");
  // the code is single use
  const again = await login.guard(post("/auth/verify", { code }, { Cookie: challenge }));
  assert.equal(again.status, 400);
});

test("wrong code is 401; no challenge is 400", async () => {
  const { login, tg } = setup();
  const { challenge, code } = await sendAndCode(login, tg);
  const wrong = code === "000000" ? "111111" : "000000";
  const r = await login.guard(post("/auth/verify", { code: wrong }, { Cookie: challenge }));
  assert.equal(r.status, 401);
  const none = await login.guard(post("/auth/verify", { code }, {}));
  assert.equal(none.status, 400);
});

test("sends are rate-limited to 5 per minute", async () => {
  const { login } = setup();
  for (let i = 0; i < 5; i++) assert.equal((await login.guard(post("/auth/send"))).status, 200);
  assert.equal((await login.guard(post("/auth/send"))).status, 429);
});

test("parallel guesses are capped at 5 per challenge (KV-gap regression)", async () => {
  const { login, tg } = setup();
  const { challenge, code } = await sendAndCode(login, tg);
  const wrong = code === "000000" ? "111111" : "000000";
  const results = await Promise.all(
    Array.from({ length: 40 }, () => login.guard(post("/auth/verify", { code: wrong }, { Cookie: challenge }))),
  );
  const statuses = results.map((r) => r.status);
  assert.equal(statuses.filter((s) => s === 401).length, 5, `statuses: ${statuses}`);
  assert.equal(statuses.filter((s) => s === 429).length, 35);
  // the challenge is gone and the window is exhausted, so even the right code is refused
  const right = await login.guard(post("/auth/verify", { code }, { Cookie: challenge }));
  assert.equal(right.status, 429);
});

test("expired challenge is rejected", async () => {
  let t = 1_000_000;
  const store = L.memoryStore(() => t);
  const { login, tg } = setup({ cfg: { store, now: () => t, limiter: L.memoryLimiter(() => t) } });
  const { challenge, code } = await sendAndCode(login, tg);
  t += 301_000;
  const r = await login.guard(post("/auth/verify", { code }, { Cookie: challenge }));
  assert.equal(r.status, 400);
});

test("logout clears the session cookie", async () => {
  const { login } = setup();
  const r = await login.guard(post("/auth/logout"));
  assert.equal(r.status, 200);
  assert.match(r.headers.get("Set-Cookie"), /^tg_session=; .*Max-Age=0/);
});

test("login page and script are served with a strict CSP and escaped name", async () => {
  const { login } = setup();
  const page = await login.guard(get("/login"));
  const html = await page.text();
  assert.match(html, /Test &lt;App&gt;/);
  assert.doesNotMatch(html, /<script>/, "no inline script");
  assert.match(page.headers.get("Content-Security-Policy"), /script-src 'self'/);
  const js = await login.guard(get("/login.js"));
  assert.equal(js.status, 200);
  assert.match(await js.text(), /\/auth\/verify/);
});

test("Telegram failure returns 502 and does not leak the response", async () => {
  const { login } = setup({ tg: { ok: false } });
  const r = await login.guard(post("/auth/send"));
  assert.equal(r.status, 502);
  assert.deepEqual(await r.json(), { error: "Couldn't send the code." });
});

test("publicOrigin overrides the Origin check behind a proxy", async () => {
  const { login } = setup({ cfg: { publicOrigin: "https://public.example" } });
  const bad = await login.guard(post("/auth/send", {}, { Origin: ORIGIN }));
  assert.equal(bad.status, 403);
  const ok = await login.guard(post("/auth/send", {}, { Origin: "https://public.example" }));
  assert.equal(ok.status, 200);
});

test("memoryLimiter resets after its window", async () => {
  let t = 0;
  const lim = L.memoryLimiter(() => t);
  assert.equal(await lim.hit("k", 1, 60), true);
  assert.equal(await lim.hit("k", 1, 60), false);
  t += 60_001;
  assert.equal(await lim.hit("k", 1, 60), true);
});

test("kvStore prefixes keys and clamps TTL to KV's 60 s minimum", async () => {
  const calls = [];
  const ns = {
    get: async (k) => { calls.push(["get", k]); return "v"; },
    put: async (k, v, o) => { calls.push(["put", k, v, o]); },
    delete: async (k) => { calls.push(["delete", k]); },
  };
  const s = L.kvStore(ns);
  assert.equal(await s.get("abc"), "v");
  await s.put("abc", "h", 10);
  await s.delete("abc");
  assert.deepEqual(calls, [
    ["get", "tglogin:abc"],
    ["put", "tglogin:abc", "h", { expirationTtl: 60 }],
    ["delete", "tglogin:abc"],
  ]);
});
