import json
import re
from concurrent.futures import ThreadPoolExecutor

import pytest

from tgnotify import login as L

SECRET = "x" * 40
ORIGIN = "https://app.example"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def make():
    def _make(clock=None, **kw):
        clock = clock or Clock()
        sent = []

        def notifier(text):
            sent.append(text)

        cfg = dict(app_name="Test <App>", token=" 123:ABC \n", chat_id="42", secret=SECRET,
                   clock=clock, notifier=notifier)
        cfg.update(kw)
        login = L.Login(**cfg)
        login.sent = sent
        return login
    return _make


def post(login, path, body=None, headers=None, cookies=None):
    h = {"content-type": "application/json", "origin": ORIGIN}
    h.update(headers or {})
    if cookies:
        h["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return login.guard("POST", path, h, json.dumps(body if body is not None else {}), ORIGIN)


def get(login, path, cookies=None):
    h = {}
    if cookies:
        h["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return login.guard("GET", path, h, b"", ORIGIN)


def cookie_value(resp, name):
    for k, v in resp.headers:
        if k == "Set-Cookie" and v.startswith(name + "="):
            return v.split(";")[0][len(name) + 1:]
    return None


def send_and_code(login):
    resp = post(login, "/auth/send")
    assert resp.status == 200
    code = re.search(r"login code: (\d{6})", login.sent[-1]).group(1)
    return {"tg_challenge": cookie_value(resp, "tg_challenge")}, code


def test_codes_are_six_digits():
    for _ in range(2000):
        assert re.fullmatch(r"\d{6}", L.six_digit_code())


def test_session_valid_expired_forged_malformed():
    now = 1_000_000
    good = L.sign_session(SECRET, now + 60)
    assert L.check_session(SECRET, good, now)
    assert not L.check_session(SECRET, L.sign_session(SECRET, now - 1), now)
    payload = good.split(".")[0]
    assert not L.check_session(SECRET, f"{payload}.AAAA", now)
    assert not L.check_session(SECRET, good + ".extra", now)
    assert not L.check_session(SECRET, None, now)
    assert not L.check_session("short", good, now)


def test_fails_closed_when_config_incomplete(make):
    for over in ({"secret": "short"}, {"secret": ""}, {"token": ""}):
        login = make(**over)
        assert login.configured is False
        r = get(login, "/")
        assert r.status == 503
        assert r.body == "Login is not configured."


def test_unauthenticated_pages_redirect_and_apis_401(make):
    login = make()
    r = get(login, "/dashboard")
    assert r.status == 302
    assert ("Location", "/login") in r.headers
    assert get(login, "/api/x").status == 401
    assert get(login, "/login").status == 200


def test_cross_origin_or_non_json_auth_posts_get_403(make):
    login = make()
    assert post(login, "/auth/send", headers={"origin": "https://evil.example"}).status == 403
    r = login.guard("POST", "/auth/send", {"origin": ORIGIN, "content-type": "text/plain"}, "{}", ORIGIN)
    assert r.status == 403
    assert login.sent == []


def test_full_flow(make):
    login = make()
    cookies, code = send_and_code(login)
    assert "Test &lt;App&gt; login code" in login.sent[-1]
    r = post(login, "/auth/verify", {"code": code}, cookies=cookies)
    assert r.status == 200
    session = cookie_value(r, "tg_session")
    assert session
    sc = [v for k, v in r.headers if k == "Set-Cookie" and v.startswith("tg_session=")][0]
    for attr in ("HttpOnly", "Secure", "SameSite=Strict"):
        assert attr in sc
    assert get(login, "/", cookies={"tg_session": session}) is None
    # the code is single use
    assert post(login, "/auth/verify", {"code": code}, cookies=cookies).status == 400


def test_wrong_code_401_and_no_challenge_400(make):
    login = make()
    cookies, code = send_and_code(login)
    wrong = "000000" if code != "000000" else "111111"
    assert post(login, "/auth/verify", {"code": wrong}, cookies=cookies).status == 401
    assert post(login, "/auth/verify", {"code": code}).status == 400


def test_sends_rate_limited_to_five_per_minute(make):
    login = make()
    for _ in range(5):
        assert post(login, "/auth/send").status == 200
    assert post(login, "/auth/send").status == 429


def test_parallel_guesses_capped_at_five(make):
    """Regression for the KV gap: concurrent guesses must not exceed the per-challenge cap."""
    login = make()
    cookies, code = send_and_code(login)
    wrong = "000000" if code != "000000" else "111111"
    with ThreadPoolExecutor(max_workers=20) as ex:
        statuses = list(ex.map(
            lambda _: post(login, "/auth/verify", {"code": wrong}, cookies=cookies).status, range(40)))
    assert statuses.count(401) == 5, statuses
    assert statuses.count(429) == 35
    # challenge is gone and the window is exhausted
    assert post(login, "/auth/verify", {"code": code}, cookies=cookies).status == 429


def test_expired_challenge_rejected(make):
    clock = Clock()
    login = make(clock=clock)
    cookies, code = send_and_code(login)
    clock.t += 301
    assert post(login, "/auth/verify", {"code": code}, cookies=cookies).status == 400


def test_logout_clears_session(make):
    login = make()
    r = post(login, "/auth/logout")
    assert r.status == 200
    assert any(v.startswith("tg_session=;") and "Max-Age=0" in v for k, v in r.headers if k == "Set-Cookie")


def test_login_page_and_script(make):
    login = make()
    page = get(login, "/login")
    assert "Test &lt;App&gt;" in page.body
    assert "<script>" not in page.body
    csp = dict(page.headers)["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    js = get(login, "/login.js")
    assert js.status == 200 and "/auth/verify" in js.body


def test_telegram_failure_is_502_and_not_echoed(make):
    def boom(_text):
        raise RuntimeError("https://api.telegram.org/bot123:ABC/sendMessage failed")
    login = make(notifier=boom)
    r = post(login, "/auth/send")
    assert r.status == 502
    assert json.loads(r.body) == {"error": "Couldn't send the code."}
    assert "123:ABC" not in r.body


def test_public_origin_overrides_check(make):
    login = make(public_origin="https://public.example")
    assert post(login, "/auth/send", headers={"origin": ORIGIN}).status == 403
    assert post(login, "/auth/send", headers={"origin": "https://public.example"}).status == 200


def test_memory_limiter_window_resets():
    clock = Clock(0)
    lim = L.MemoryLimiter(clock)
    assert lim.hit("k", 1, 60)
    assert not lim.hit("k", 1, 60)
    clock.t += 61
    assert lim.hit("k", 1, 60)
