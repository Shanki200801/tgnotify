import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import tgnotify


class Stub:
    def __init__(self):
        self.calls, self.bodies, self.updates, self.next_id = [], [], [], 100


@pytest.fixture
def env(tmp_path, monkeypatch):
    stub = Stub()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            method = self.path.rsplit("/", 1)[-1]
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.loads(raw) if self.headers["Content-Type"].startswith("application/json") else raw
            stub.calls.append(method)
            stub.bodies.append(body)
            result = True
            if method in ("sendMessage", "sendDocument"):
                stub.next_id += 1
                result = {"message_id": stub.next_id}
            elif method == "getUpdates":
                result, stub.updates = stub.updates, []
            out = json.dumps({"ok": True, "result": result}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("TGNOTIFY_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("TGNOTIFY_CONFIG", str(tmp_path / "config.json"))
    c = tgnotify.Client("SECRET", 42, f"http://127.0.0.1:{srv.server_port}")
    yield stub, c
    srv.shutdown()


def cb(uid, chat, msg, data, label):
    return {"update_id": uid, "callback_query": {
        "id": "cb", "data": data, "from": {"username": "me"},
        "message": {"message_id": msg, "chat": {"id": chat},
                    "reply_markup": {"inline_keyboard": [[{"text": label, "callback_data": data}]]}}}}


def test_format_escapes():
    assert tgnotify.format_message("a<b> & c", "T<1>", "error") == "🚨 <b>T&lt;1&gt;</b>\na&lt;b&gt; &amp; c"


def test_split():
    assert tgnotify.split_text("aaaa&amp;bb", 6)[0] == "aaaa"
    parts = tgnotify.split_text("x" * 10 + "\n" + "y" * 10, 15)
    assert parts[0] == "x" * 10 + "\n"


def test_send_long_buttons_last(env):
    stub, c = env
    ids = c.send("z" * 9000, buttons={"Open": "https://x"})
    assert len(ids) == 3
    assert "reply_markup" not in stub.bodies[0] and "reply_markup" in stub.bodies[2]


def test_send_file(env, tmp_path):
    stub, c = env
    f = tmp_path / "r.txt"
    f.write_text("hello")
    c.send_file(f, "cap", title="T")
    assert stub.calls[-1] == "sendDocument" and b"hello" in stub.bodies[-1]


def test_token_redacted():
    c = tgnotify.Client("SECRET", 1, "http://127.0.0.1:1")
    with pytest.raises(tgnotify.TgNotifyError) as e:
        c.send("hi")
    assert "SECRET" not in str(e.value)


def test_prompt_collect(env):
    stub, c = env
    mid = c.prompt("Apply?", ["Yes", "No"])
    data = stub.bodies[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
    assert data.startswith("tg:") and len(data) <= 64
    stub.updates = [cb(7, 999, mid, data, "Yes"), cb(8, 42, mid, data, "Yes")]
    got = c.collect()
    assert [(a.message_id, a.choice) for a in got] == [(mid, "Yes")]
    assert json.loads(open(os.environ["TGNOTIFY_STATE"]).read())["offset"] == 9


def test_ask_keeps_other_answers(env):
    stub, c = env
    stub.next_id = 200
    stub.updates = [cb(1, 42, 555, "tg:aaaa:0", "Other"), cb(2, 42, 201, "tg:bbbb:1", "No")]
    assert c.ask("Q?", ["Yes", "No"], timeout=3).choice == "No"
    assert [a.choice for a in c.collect(555)] == ["Other"]


def test_config_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("TGNOTIFY_CONFIG", str(tmp_path / "c.json"))
    p = tgnotify.save_config("f", "1")
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    monkeypatch.setenv("TGNOTIFY_CHAT_ID", "99")
    cfg = tgnotify.load_config()
    assert cfg["token"] == "f" and cfg["chat_id"] == "99"


def test_latest_tap_wins(env):
    stub, c = env
    stub.updates = [cb(1, 42, 300, "tg:abcd:0", "Approve"), cb(2, 42, 300, "tg:abcd:1", "Skip")]
    assert [a.choice for a in c.collect(300)] == ["Skip"]
