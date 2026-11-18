"""tgnotify: Telegram alerts + button approvals. Zero dependencies.

Shares config/state files and wire format with the Go CLI and TS package.

    import tgnotify
    tgnotify.notify("Deploy done", title="prod", level="success")
    choice = tgnotify.ask("Ship it?", ["Yes", "No"], timeout=600)
"""

from __future__ import annotations

import html
import json
import mimetypes
import os
import secrets
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

__all__ = [
    "Client", "Answer", "Button", "TgNotifyError", "ConflictError", "AskTimeout",
    "notify", "send_file", "ask", "prompt", "collect", "load_config", "save_config",
    "format_message", "split_text", "escape_html",
]
__version__ = "0.1.1"

DEFAULT_API_BASE = "https://api.telegram.org"
MAX_TEXT = 4000
MAX_CAPTION = 1000
CB_PREFIX = "tg:"
LEVEL_ICON = {"info": "ℹ️", "success": "✅", "warn": "⚠️", "warning": "⚠️", "error": "🚨"}


class TgNotifyError(Exception):
    pass


class ConflictError(TgNotifyError):
    """getUpdates 409: another poller is running or a webhook is set."""


class AskTimeout(TgNotifyError):
    pass


# ---- config ---------------------------------------------------------------

def config_dir() -> Path:
    x = os.environ.get("XDG_CONFIG_HOME")
    return (Path(x) if x else Path.home() / ".config") / "tgnotify"


def config_path() -> Path:
    return Path(os.environ.get("TGNOTIFY_CONFIG") or config_dir() / "config.json")


def state_path() -> Path:
    return Path(os.environ.get("TGNOTIFY_STATE") or config_dir() / "state.json")


def _env(*keys: str) -> str:
    for k in keys:
        if os.environ.get(k):
            return os.environ[k]
    return ""


def load_config() -> dict:
    cfg: dict = {}
    p = config_path()
    if p.exists():
        try:
            cfg = json.loads(p.read_text())
        except ValueError as e:
            raise TgNotifyError(f"bad config {p}: {e}") from None
    cfg["token"] = (_env("TGNOTIFY_TOKEN", "TELEGRAM_BOT_TOKEN") or cfg.get("token", "")).strip()
    cfg["chat_id"] = str(_env("TGNOTIFY_CHAT_ID", "TELEGRAM_CHAT_ID") or cfg.get("chat_id", "")).strip()
    cfg["api_base"] = os.environ.get("TGNOTIFY_API_BASE") or cfg.get("api_base") or DEFAULT_API_BASE
    if not cfg["token"] or not cfg["chat_id"]:
        raise TgNotifyError(
            "not configured; run `tgnotify setup` or set TGNOTIFY_TOKEN and TGNOTIFY_CHAT_ID")
    return cfg


def save_config(token: str, chat_id: str) -> Path:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"token": token, "chat_id": str(chat_id)}, f, indent=2)
        f.write("\n")
    os.chmod(p, 0o600)
    return p


# ---- formatting -----------------------------------------------------------

def escape_html(s: str) -> str:
    return html.escape(s, quote=False)


def format_message(text: str, title: str = "", level: str = "", raw_html: bool = False) -> str:
    head = (LEVEL_ICON.get(level.lower(), "") + " ") if LEVEL_ICON.get(level.lower()) else ""
    if title:
        head += f"<b>{escape_html(title)}</b>"
    body = text if raw_html else escape_html(text)
    if not head:
        return body
    return head.strip() if not body else f"{head}\n{body}"


def split_text(s: str, limit: int = MAX_TEXT) -> list[str]:
    out: list[str] = []
    while len(s) > limit:
        cut = limit
        for i in range(limit, limit // 2, -1):
            if s[i - 1] == "\n":
                cut = i
                break
        for i in range(cut - 1, max(cut - 6, -1), -1):  # don't cut inside &amp;
            if s[i] == ";":
                break
            if s[i] == "&":
                cut = i
                break
        out.append(s[:cut])
        s = s[cut:]
    if s or not out:
        out.append(s)
    return out


@dataclass
class Button:
    text: str
    url: str = ""
    callback_data: str = ""

    def to_api(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class Answer:
    message_id: int
    nonce: str
    index: int
    choice: str
    user: str = ""
    at: int = field(default_factory=lambda: int(time.time()))


def _rows(buttons: Optional[Iterable]) -> list[list[dict]]:
    """Accept [[Button]], [Button], [(text, url)], or {text: url}."""
    if not buttons:
        return []
    if isinstance(buttons, dict):
        buttons = [Button(t, url=u) for t, u in buttons.items()]
    rows = []
    for item in buttons:
        row = item if isinstance(item, list) else [item]
        rows.append([
            b.to_api() if isinstance(b, Button) else Button(*b).to_api() if isinstance(b, tuple) else b
            for b in row
        ])
    return rows


# ---- state ----------------------------------------------------------------

def _load_state() -> dict:
    try:
        s = json.loads(state_path().read_text())
        return {"offset": int(s.get("offset") or 0), "answers": s.get("answers") or []}
    except (OSError, ValueError):
        return {"offset": 0, "answers": []}


def _save_state(s: dict) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, p)


def _take_answers(ids: Sequence[int]) -> list[Answer]:
    s = _load_state()
    want = set(ids)
    latest: dict = {}  # latest tap per message wins
    for a in s["answers"]:
        if not want or a["message_id"] in want:
            latest[a["message_id"]] = a
    got = list(latest.values())
    if got:
        s["answers"] = [a for a in s["answers"] if want and a["message_id"] not in want]
        _save_state(s)
    return [Answer(**a) for a in got]


# ---- client ---------------------------------------------------------------

class Client:
    def __init__(self, token: str = "", chat_id: str | int = "", api_base: str = ""):
        if not (token and chat_id):
            cfg = load_config()
            token, chat_id = token or cfg["token"], chat_id or cfg["chat_id"]
            api_base = api_base or cfg["api_base"]
        self.token = str(token).strip()  # secrets often carry a trailing newline
        self.chat_id = str(chat_id).strip()
        self.api_base = (api_base or os.environ.get("TGNOTIFY_API_BASE") or DEFAULT_API_BASE).rstrip("/")

    def _redact(self, msg: str) -> str:
        if not self.token:
            return msg
        # also cover escaped forms, e.g. errors that repr() the URL
        for form in {self.token, repr(self.token)[1:-1], self.token.encode("unicode_escape").decode()}:
            msg = msg.replace(form, "<token>")
        return msg

    def call(self, method: str, params: Optional[dict] = None, *, _body: Optional[bytes] = None,
             _ctype: str = "application/json", timeout: float = 70) -> Any:
        url = f"{self.api_base}/bot{self.token}/{method}"
        data = _body if _body is not None else json.dumps(params or {}).encode()
        for attempt in range(4):
            req = urllib.request.Request(url, data=data, headers={"Content-Type": _ctype})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    resp = json.loads(r.read())
            except urllib.error.HTTPError as e:
                try:
                    resp = json.loads(e.read())
                except ValueError:
                    raise TgNotifyError(f"{method}: HTTP {e.code}") from None
            except Exception as e:  # never let a URL (with the token) escape unredacted
                raise TgNotifyError(self._redact(f"{method}: {type(e).__name__}: {e}")) from None
            if resp.get("ok"):
                return resp.get("result")
            code = resp.get("error_code")
            if code == 409:
                raise ConflictError(
                    "getUpdates conflict (409): another poller is running or a webhook is set")
            if code == 429 and attempt < 3:
                time.sleep(max(1, (resp.get("parameters") or {}).get("retry_after", 1)))
                continue
            raise TgNotifyError(f"{method} failed ({code}): {resp.get('description')}")

    # -- sending --

    def send(self, text: str = "", *, title: str = "", level: str = "", silent: bool = False,
             html: bool = False, buttons=None, preview: bool = False) -> list[int]:
        chunks = split_text(format_message(text, title, level, html))
        rows = _rows(buttons)
        ids = []
        for i, chunk in enumerate(chunks):
            p: dict = {
                "chat_id": self.chat_id, "text": chunk, "parse_mode": "HTML",
                "disable_notification": silent,
                "link_preview_options": {"is_disabled": not preview},
            }
            if rows and i == len(chunks) - 1:
                p["reply_markup"] = {"inline_keyboard": rows}
            ids.append(self.call("sendMessage", p)["message_id"])
        return ids

    def send_file(self, path: str | os.PathLike, caption: str = "", *, title: str = "",
                  level: str = "", silent: bool = False) -> int:
        path = Path(path)
        boundary = uuid.uuid4().hex
        fields = {"chat_id": self.chat_id}
        if caption or title:
            fields["caption"] = split_text(format_message(caption, title, level), MAX_CAPTION)[0]
            fields["parse_mode"] = "HTML"
        if silent:
            fields["disable_notification"] = "true"
        parts = []
        for k, v in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        fname = path.name.replace('"', "")
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{fname}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n".encode() + path.read_bytes() + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        res = self.call("sendDocument", _body=b"".join(parts),
                        _ctype=f"multipart/form-data; boundary={boundary}")
        return res["message_id"]

    # -- questions --

    def prompt(self, question: str, options: Sequence[str], **kw) -> int:
        """Send buttons now; return message_id. Use collect() later (within ~24h)."""
        if not options:
            raise TgNotifyError("prompt needs at least one option")
        n = secrets.token_hex(4)
        per_row = 2 if len(options) in (2, 4) else 3
        rows: list[list[Button]] = []
        for i, opt in enumerate(options):
            if i % per_row == 0:
                rows.append([])
            rows[-1].append(Button(opt, callback_data=f"{CB_PREFIX}{n}:{i}"))
        return self.send(question, buttons=rows, **kw)[-1]

    def _poll(self, wait: int = 0) -> None:
        s = _load_state()
        p: dict = {"timeout": wait, "allowed_updates": ["callback_query"]}
        if s["offset"]:
            p["offset"] = s["offset"]
        ups = self.call("getUpdates", p, timeout=wait + 15) or []
        for u in ups:
            s["offset"] = max(s["offset"], u["update_id"] + 1)
            cq = u.get("callback_query")
            if not cq or not cq.get("message") or not str(cq.get("data", "")).startswith(CB_PREFIX):
                continue
            msg = cq["message"]
            if str(msg["chat"]["id"]) != self.chat_id:
                continue
            parts = cq["data"][len(CB_PREFIX):].split(":")
            if len(parts) != 2:
                self._quiet("answerCallbackQuery", {"callback_query_id": cq["id"]})
                continue
            choice = next((b["text"] for row in (msg.get("reply_markup") or {}).get("inline_keyboard", [])
                           for b in row if b.get("callback_data") == cq["data"]), "")
            frm = cq.get("from") or {}
            s["answers"].append(asdict(Answer(
                message_id=msg["message_id"], nonce=parts[0], index=int(parts[1]), choice=choice,
                user=frm.get("username") or frm.get("first_name", ""))))
            self._quiet("answerCallbackQuery", {"callback_query_id": cq["id"], "text": f"Got it: {choice}"})
            self._quiet("editMessageReplyMarkup", {
                "chat_id": self.chat_id, "message_id": msg["message_id"],
                "reply_markup": {"inline_keyboard": [[{"text": f"✔ {choice}", "callback_data": CB_PREFIX + "done"}]]},
            })
        _save_state(s)

    def _quiet(self, method: str, params: dict) -> None:
        try:
            self.call(method, params)
        except TgNotifyError:
            pass

    def collect(self, *message_ids: int) -> list[Answer]:
        """Poll once (non-blocking); return and clear answers for ids (all if none)."""
        self._poll(0)
        return _take_answers(message_ids)

    def ask(self, question: str, options: Sequence[str], timeout: float = 600, **kw) -> Answer:
        """Send buttons and block until tapped. Raises AskTimeout."""
        mid = self.prompt(question, options, **kw)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AskTimeout("timed out waiting for an answer")
            self._poll(max(1, int(min(30, left))))
            got = _take_answers([mid])
            if got:
                return got[0]


# ---- module-level shortcuts ------------------------------------------------

def notify(text: str = "", **kw) -> list[int]:
    return Client().send(text, **kw)


def send_file(path, caption: str = "", **kw) -> int:
    return Client().send_file(path, caption, **kw)


def prompt(question: str, options: Sequence[str], **kw) -> int:
    return Client().prompt(question, options, **kw)


def collect(*message_ids: int) -> list[Answer]:
    return Client().collect(*message_ids)


def ask(question: str, options: Sequence[str], timeout: float = 600, **kw) -> Optional[str]:
    """Return the chosen option text, or None on timeout."""
    try:
        return Client().ask(question, options, timeout, **kw).choice
    except AskTimeout:
        return None
