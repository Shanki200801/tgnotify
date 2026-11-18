"""tgnotify.login: Telegram one-time-code login for single-owner apps. Stdlib only.

The app DMs a 6-digit code through your bot; the user types it in and gets a
signed, HttpOnly session cookie. The same spec and wire format as ``ts/login.ts``.
This module is framework-agnostic: ``Login.guard`` takes plain values and returns
a ``Response`` (status, body, headers) that you map onto Flask, FastAPI, Django
or anything else.

    from tgnotify.login import Login
    login = Login(app_name="My App", token=TOKEN, chat_id=CHAT, secret=SECRET)

    resp = login.guard(method, path, headers, body, url_origin)   # headers: lowercase keys
    if resp is not None:
        return resp                                              # login page, /auth/*, or 302/401
    # ...your routes

Spec:
    code      6 digits, uniform (secrets.randbelow), valid 300 s
    sends     at most 5 per 60 s, app-wide
    verify    at most 5 attempts per 60 s per challenge; the challenge is deleted on overflow
              (so at most 25 guesses per code over its 300 s life)
    session   30 days, HMAC-signed, stateless
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

__all__ = [
    "Login", "Response", "MemoryStore", "MemoryLimiter", "MIN_SECRET_LENGTH",
    "sign_session", "check_session", "six_digit_code", "login_page_html", "LOGIN_SCRIPT",
]

MIN_SECRET_LENGTH = 32


# ---- helpers -----------------------------------------------------------------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hmac(secret: str, msg: str) -> str:
    return _b64u(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest())


def six_digit_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _escape(s: str) -> str:
    return html.escape(s, quote=False)


def sign_session(secret: str, exp: int) -> str:
    payload = _b64u(json.dumps({"exp": exp}).encode())
    return f"{payload}.{_hmac(secret, payload)}"


def check_session(secret: str, token: Optional[str], now: Optional[float] = None) -> bool:
    """True only for a correctly signed, unexpired token."""
    if len(secret) < MIN_SECRET_LENGTH:
        return False
    parts = (token or "").split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False
    payload, sig = parts
    if not hmac.compare_digest(sig, _hmac(secret, payload)):
        return False
    try:
        exp = json.loads(_unb64u(payload))["exp"]
    except Exception:
        return False
    return isinstance(exp, (int, float)) and exp > (now if now is not None else time.time())


# ---- pluggable storage (defaults are single-process) ---------------------------

class MemoryStore:
    """Challenge store with TTL. Lock-guarded, so safe across threads in one process."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock, self._lock, self._m = clock, threading.Lock(), {}

    def get(self, cid: str) -> Optional[str]:
        with self._lock:
            e = self._m.get(cid)
            if e is None:
                return None
            if e[1] <= self._clock():
                del self._m[cid]
                return None
            return e[0]

    def put(self, cid: str, value: str, ttl_sec: int) -> None:
        with self._lock:
            self._m[cid] = (value, self._clock() + ttl_sec)

    def delete(self, cid: str) -> None:
        with self._lock:
            self._m.pop(cid, None)


class MemoryLimiter:
    """Fixed-window limiter. The count and the check happen under one lock, so it is exact."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock, self._lock, self._m = clock, threading.Lock(), {}

    def hit(self, key: str, limit: int, window_sec: int) -> bool:
        with self._lock:
            t = self._clock()
            e = self._m.get(key)
            if e is None or e[1] <= t:
                if len(self._m) > 10_000:
                    self._m = {k: v for k, v in self._m.items() if v[1] > t}
                e = [0, t + window_sec]
                self._m[key] = e
            e[0] += 1
            return e[0] <= limit


# ---- login page (no inline JS, so a strict CSP works) --------------------------

# Keep this in sync with ts/login.ts (LOGIN_SCRIPT and loginPageHtml).
LOGIN_SCRIPT = """(function () {
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
"""

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in · {name}</title>
<style>
  :root {{ color-scheme: light dark; --fg: #1b1b1f; --bg: #fafafa; --accent: #2a6df4; --err: #c62828; --ok: #2e7d32; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --fg: #eee; --bg: #121214; --accent: #7aa6ff; --err: #ff8a80; --ok: #81c784; }} }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--fg);
         font: 16px/1.4 system-ui, sans-serif; padding: 16px; box-sizing: border-box; }}
  main {{ width: 100%; max-width: 360px; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .5rem; }}
  p {{ margin: .5rem 0 1rem; opacity: .85; }}
  button, input {{ font: inherit; width: 100%; box-sizing: border-box; padding: .75rem; border-radius: 8px; border: 1px solid #8884; }}
  button {{ background: var(--accent); color: #fff; border: 0; cursor: pointer; margin-top: .5rem; }}
  button:disabled {{ opacity: .6; cursor: default; }}
  input {{ background: transparent; color: var(--fg); letter-spacing: .4em; text-align: center; font-size: 1.4rem; }}
  label {{ display: block; margin-top: 1rem; font-size: .9rem; opacity: .8; }}
  #msg {{ min-height: 1.4em; margin-top: 1rem; }}
  #msg.ok {{ color: var(--ok); }} #msg.err {{ color: var(--err); }}
</style>
</head>
<body>
<main>
  <h1>{name}</h1>
  <p>We'll send a one-time code to your Telegram.</p>
  <button id="send" type="button">Send code</button>
  <form id="verify" hidden>
    <label for="code">Code from Telegram</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" required>
    <button type="submit">Sign in</button>
  </form>
  <p id="msg" role="status"></p>
</main>
<script src="/login.js"></script>
</body>
</html>
"""


def login_page_html(app_name: str) -> str:
    return _PAGE.format(name=_escape(app_name))


# ---- the login ---------------------------------------------------------------

@dataclass
class Response:
    status: int
    body: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)  # (name, value); repeats allowed


_CSP = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "
        "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
_NO_STORE = ("Cache-Control", "no-store")


def _json(data: Any, status: int = 200, cookies: Tuple[str, ...] = ()) -> Response:
    headers = [("Content-Type", "application/json"), _NO_STORE]
    headers += [("Set-Cookie", c) for c in cookies]
    return Response(status, json.dumps(data), headers)


class Login:
    """Login for one app. Thread-safe with the default stores."""

    def __init__(
        self,
        *,
        app_name: str,
        token: str,
        chat_id: Union[str, int],
        secret: str,
        store: Any = None,
        limiter: Any = None,
        api_base: str = "",
        code_ttl: int = 300,
        session_days: int = 30,
        sends_per_minute: int = 5,
        attempts_per_minute: int = 5,
        session_cookie: str = "tg_session",
        challenge_cookie: str = "tg_challenge",
        public_origin: str = "",
        clock: Callable[[], float] = time.time,
        notifier: Optional[Callable[[str], None]] = None,
    ):
        self.app_name = app_name
        self.token = (token or "").strip()
        self.chat_id = str(chat_id or "").strip()
        self.secret = secret or ""
        self.store = store or MemoryStore(clock)
        self.limiter = limiter or MemoryLimiter(clock)
        self.code_ttl = code_ttl
        self.session_sec = session_days * 86400
        self.sends_per_minute = sends_per_minute
        self.attempts_per_minute = attempts_per_minute
        self.session_cookie = session_cookie
        self.challenge_cookie = challenge_cookie
        self.public_origin = public_origin
        self.clock = clock
        self._api_base = api_base
        self._notifier = notifier
        self.configured = bool(self.token and self.chat_id and len(self.secret) >= MIN_SECRET_LENGTH)

    # -- sending --

    def _notify(self, text: str) -> None:
        if self._notifier is not None:
            self._notifier(text)
            return
        from . import Client  # local import: avoids a cycle at package import time
        Client(self.token, self.chat_id, self._api_base).call(
            "sendMessage", {"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"})

    def _cookie(self, name: str, value: str, max_age: int) -> str:
        return f"{name}={value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"

    def _send_code(self, headers: Mapping[str, str]) -> Response:
        if not self.limiter.hit("send", self.sends_per_minute, 60):
            return _json({"error": "Too many requests, wait a minute."}, 429)
        code = six_digit_code()
        cid = _b64u(secrets.token_bytes(18))
        self.store.put(cid, _hmac(self.secret, f"{cid}:{code}"), self.code_ttl)
        who = ", ".join(x for x in [headers.get("cf-connecting-ip"), headers.get("cf-ipcity"),
                                    headers.get("cf-ipcountry")] if x) or "unknown"
        text = (f"🔐 <b>{_escape(self.app_name)} login code: {code}</b>\n"
                f"Valid {round(self.code_ttl / 60)} min. Requested from {_escape(who)}.\n"
                "If this wasn't you, ignore it.")
        try:
            self._notify(text)
        except Exception:
            # Never echo the Telegram error: it can contain the token.
            return _json({"error": "Couldn't send the code."}, 502)
        return _json({"ok": True}, 200, (self._cookie(self.challenge_cookie, cid, self.code_ttl),))

    def _verify_code(self, cookies: Mapping[str, str], body: bytes) -> Response:
        cid = cookies.get(self.challenge_cookie)
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            data = None
        raw = data.get("code", "") if isinstance(data, dict) else ""
        code = "".join(ch for ch in str(raw) if ch.isdigit() and ch.isascii())
        if not cid or len(code) != 6:
            return _json({"error": "Request a code first."}, 400)

        # Count the attempt before checking the code. On overflow, drop the challenge.
        if not self.limiter.hit(f"verify:{cid}", self.attempts_per_minute, 60):
            self.store.delete(cid)
            return _json({"error": "Too many attempts. Request a new code."}, 429)
        stored = self.store.get(cid)
        if stored is None:
            return _json({"error": "Code expired. Request a new one."}, 400)
        if not hmac.compare_digest(stored, _hmac(self.secret, f"{cid}:{code}")):
            return _json({"error": "Wrong code."}, 401)

        self.store.delete(cid)
        session = sign_session(self.secret, int(self.clock()) + self.session_sec)
        return _json({"ok": True}, 200, (
            self._cookie(self.session_cookie, session, self.session_sec),
            self._cookie(self.challenge_cookie, "", 0),
        ))

    # -- public API --

    def is_logged_in(self, cookies: Mapping[str, str]) -> bool:
        return self.configured and check_session(self.secret, cookies.get(self.session_cookie), self.clock())

    def guard(self, method: str, path: str, headers: Mapping[str, str], body: Union[bytes, str, None],
              url_origin: str) -> Optional[Response]:
        """Return a Response for login routes or unauthenticated requests, or None to proceed.

        ``headers`` must use lowercase keys. ``url_origin`` is the request's own origin,
        e.g. "https://app.example", and is used when ``public_origin`` is not set.
        """
        method = method.upper()
        headers = {k.lower(): v for k, v in headers.items()}
        raw = body.encode() if isinstance(body, str) else (body or b"")
        cookies = _parse_cookies(headers.get("cookie", ""))

        if path.startswith("/auth/"):
            if method != "POST":
                return _json({"error": "method not allowed"}, 405)
            origin = self.public_origin or url_origin
            if headers.get("origin") != origin or not headers.get("content-type", "").startswith("application/json"):
                return _json({"error": "bad request"}, 403)

        # Fail closed: nothing is served except this notice until the config is complete.
        if not self.configured:
            return Response(503, "Login is not configured.", [("Content-Type", "text/plain")])

        if method == "GET" and path == "/login":
            return Response(200, login_page_html(self.app_name), [
                ("Content-Type", "text/html; charset=utf-8"), _NO_STORE, ("Content-Security-Policy", _CSP),
                ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "same-origin")])
        if method == "GET" and path == "/login.js":
            return Response(200, LOGIN_SCRIPT, [
                ("Content-Type", "text/javascript; charset=utf-8"), _NO_STORE, ("Content-Security-Policy", _CSP),
                ("X-Content-Type-Options", "nosniff")])

        if path == "/auth/send":
            return self._send_code(headers)
        if path == "/auth/verify":
            return self._verify_code(cookies, raw)
        if path == "/auth/logout":
            return _json({"ok": True}, 200, (self._cookie(self.session_cookie, "", 0),))

        if self.is_logged_in(cookies):
            return None
        if method == "GET" and not path.startswith("/api/"):
            return Response(302, "", [("Location", "/login")])
        return _json({"error": "not logged in"}, 401)


def _parse_cookies(header: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in header.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k:
            out[k] = v
    return out
