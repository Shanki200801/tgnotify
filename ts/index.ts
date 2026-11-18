/**
 * tgnotify: Telegram alerts + button approvals for Node 18+. Zero runtime deps.
 * Shares config/state files and wire format with the Go CLI and Python package.
 *
 *   import { notify, ask } from "tgnotify";
 *   await notify("Deploy done", { title: "prod", level: "success" });
 *   const choice = await ask("Ship it?", ["Yes", "No"], { timeoutMs: 600_000 });
 */
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";

export const DEFAULT_API_BASE = "https://api.telegram.org";
const MAX_TEXT = 4000;
const MAX_CAPTION = 1000;
const CB_PREFIX = "tg:";
const LEVEL_ICON: Record<string, string> = {
  info: "ℹ️", success: "✅", warn: "⚠️", warning: "⚠️", error: "🚨",
};

export type Level = "info" | "success" | "warn" | "warning" | "error" | "";

export interface Button { text: string; url?: string; callback_data?: string }

export interface SendOptions {
  title?: string;
  level?: Level;
  silent?: boolean;
  /** Text is already Telegram HTML; don't escape. */
  html?: boolean;
  /** Rows of buttons, a flat list (one per row), or { text: url }. */
  buttons?: Button[][] | Button[] | Record<string, string>;
  preview?: boolean;
}

export interface Answer {
  message_id: number; nonce: string; index: number; choice: string; user?: string; at: number;
}

export interface Config { token: string; chat_id: string; api_base: string }

export class TgNotifyError extends Error { name = "TgNotifyError"; }
export class ConflictError extends TgNotifyError { name = "ConflictError"; }
export class AskTimeout extends TgNotifyError { name = "AskTimeout"; }

// ---- config ---------------------------------------------------------------

const env = (...keys: string[]) => keys.map((k) => process.env[k]).find((v) => v) ?? "";
export const configDir = () =>
  join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "tgnotify");
export const configPath = () => process.env.TGNOTIFY_CONFIG || join(configDir(), "config.json");
export const statePath = () => process.env.TGNOTIFY_STATE || join(configDir(), "state.json");

export function loadConfig(): Config {
  let file: Partial<Config> = {};
  const p = configPath();
  if (existsSync(p)) {
    try { file = JSON.parse(readFileSync(p, "utf8")); }
    catch (e) { throw new TgNotifyError(`bad config ${p}: ${(e as Error).message}`); }
  }
  const cfg: Config = {
    token: env("TGNOTIFY_TOKEN", "TELEGRAM_BOT_TOKEN") || file.token || "",
    chat_id: String(env("TGNOTIFY_CHAT_ID", "TELEGRAM_CHAT_ID") || file.chat_id || ""),
    api_base: env("TGNOTIFY_API_BASE") || file.api_base || DEFAULT_API_BASE,
  };
  if (!cfg.token || !cfg.chat_id) {
    throw new TgNotifyError(
      "not configured; run `tgnotify setup` or set TGNOTIFY_TOKEN and TGNOTIFY_CHAT_ID");
  }
  return cfg;
}

export function saveConfig(token: string, chatId: string | number): string {
  const p = configPath();
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p, JSON.stringify({ token, chat_id: String(chatId) }, null, 2) + "\n", { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}

// ---- formatting -----------------------------------------------------------

export const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function formatMessage(text: string, o: SendOptions = {}): string {
  const icon = LEVEL_ICON[(o.level || "").toLowerCase()];
  let head = icon ? icon + " " : "";
  if (o.title) head += `<b>${escapeHtml(o.title)}</b>`;
  const body = o.html ? text : escapeHtml(text);
  if (!head) return body;
  return body ? `${head}\n${body}` : head.trim();
}

export function splitText(s: string, limit = MAX_TEXT): string[] {
  const out: string[] = [];
  let r = Array.from(s);
  while (r.length > limit) {
    let cut = limit;
    for (let i = limit; i > limit / 2; i--) if (r[i - 1] === "\n") { cut = i; break; }
    for (let i = cut - 1; i >= 0 && i > cut - 6; i--) {
      if (r[i] === ";") break;
      if (r[i] === "&") { cut = i; break; }
    }
    out.push(r.slice(0, cut).join(""));
    r = r.slice(cut);
  }
  if (r.length || !out.length) out.push(r.join(""));
  return out;
}

function toRows(b: SendOptions["buttons"]): Button[][] {
  if (!b) return [];
  if (!Array.isArray(b)) return Object.entries(b).map(([text, url]) => [{ text, url }]);
  return (b as Array<Button | Button[]>).map((x) => (Array.isArray(x) ? x : [x]));
}

// ---- state ----------------------------------------------------------------

interface State { offset: number; answers: Answer[] }

function loadState(): State {
  try {
    const s = JSON.parse(readFileSync(statePath(), "utf8"));
    return { offset: Number(s.offset) || 0, answers: s.answers || [] };
  } catch { return { offset: 0, answers: [] }; }
}

function saveState(s: State) {
  const p = statePath();
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p + ".tmp", JSON.stringify(s, null, 2), { mode: 0o600 });
  renameSync(p + ".tmp", p);
}

function takeAnswers(ids: number[]): Answer[] {
  const s = loadState();
  const want = new Set(ids);
  const latest = new Map<number, Answer>(); // latest tap per message wins
  for (const a of s.answers) if (!want.size || want.has(a.message_id)) latest.set(a.message_id, a);
  const got = [...latest.values()];
  if (got.length) {
    s.answers = s.answers.filter((a) => want.size && !want.has(a.message_id));
    saveState(s);
  }
  return got;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- client ---------------------------------------------------------------

export class Client {
  readonly token: string;
  readonly chatId: string;
  readonly apiBase: string;

  constructor(cfg?: Partial<Config>) {
    const c = cfg?.token && cfg?.chat_id ? (cfg as Config) : { ...loadConfig(), ...cfg };
    this.token = c.token;
    this.chatId = String(c.chat_id);
    this.apiBase = (c.api_base || env("TGNOTIFY_API_BASE") || DEFAULT_API_BASE).replace(/\/+$/, "");
  }

  private redact(m: string) { return this.token ? m.split(this.token).join("<token>") : m; }

  async call<T = any>(method: string, params: Record<string, unknown> | FormData = {}): Promise<T> {
    const url = `${this.apiBase}/bot${this.token}/${method}`;
    for (let attempt = 0; ; attempt++) {
      let res: any;
      try {
        const isForm = params instanceof FormData;
        const r = await fetch(url, {
          method: "POST",
          body: isForm ? params : JSON.stringify(params),
          headers: isForm ? undefined : { "Content-Type": "application/json" },
        });
        res = await r.json().catch(() => ({ ok: false, error_code: r.status, description: "non-JSON response" }));
      } catch (e) {
        const cause = (e as any)?.cause?.message ?? "";
        throw new TgNotifyError(this.redact(`${method}: ${(e as Error).message} ${cause}`.trim()));
      }
      if (res.ok) return res.result as T;
      if (res.error_code === 409) {
        throw new ConflictError("getUpdates conflict (409): another poller is running or a webhook is set");
      }
      if (res.error_code === 429 && attempt < 3) {
        await sleep(Math.max(1, res.parameters?.retry_after ?? 1) * 1000);
        continue;
      }
      throw new TgNotifyError(`${method} failed (${res.error_code}): ${res.description}`);
    }
  }

  async send(text = "", o: SendOptions = {}): Promise<number[]> {
    const chunks = splitText(formatMessage(text, o));
    const rows = toRows(o.buttons);
    const ids: number[] = [];
    for (let i = 0; i < chunks.length; i++) {
      const p: Record<string, unknown> = {
        chat_id: this.chatId, text: chunks[i], parse_mode: "HTML",
        disable_notification: !!o.silent,
        link_preview_options: { is_disabled: !o.preview },
      };
      if (rows.length && i === chunks.length - 1) p.reply_markup = { inline_keyboard: rows };
      ids.push((await this.call<{ message_id: number }>("sendMessage", p)).message_id);
    }
    return ids;
  }

  async sendFile(path: string, caption = "", o: SendOptions = {}): Promise<number> {
    const fd = new FormData();
    fd.set("chat_id", this.chatId);
    if (caption || o.title) {
      fd.set("caption", splitText(formatMessage(caption, o), MAX_CAPTION)[0]);
      fd.set("parse_mode", "HTML");
    }
    if (o.silent) fd.set("disable_notification", "true");
    fd.set("document", new Blob([readFileSync(path)]), basename(path));
    return (await this.call<{ message_id: number }>("sendDocument", fd)).message_id;
  }

  /** Send buttons now; returns message_id. Call collect() later (within ~24h). */
  async prompt(question: string, options: string[], o: SendOptions = {}): Promise<number> {
    if (!options.length) throw new TgNotifyError("prompt needs at least one option");
    const n = randomBytes(4).toString("hex");
    const perRow = options.length === 2 || options.length === 4 ? 2 : 3;
    const rows: Button[][] = [];
    options.forEach((text, i) => {
      if (i % perRow === 0) rows.push([]);
      rows[rows.length - 1].push({ text, callback_data: `${CB_PREFIX}${n}:${i}` });
    });
    const ids = await this.send(question, { ...o, buttons: rows });
    return ids[ids.length - 1];
  }

  private async quiet(method: string, p: Record<string, unknown>) {
    try { await this.call(method, p); } catch { /* best effort */ }
  }

  private async poll(wait: number) {
    const s = loadState();
    const p: Record<string, unknown> = { timeout: wait, allowed_updates: ["callback_query"] };
    if (s.offset) p.offset = s.offset;
    const ups = (await this.call<any[]>("getUpdates", p)) || [];
    for (const u of ups) {
      s.offset = Math.max(s.offset, u.update_id + 1);
      const cq = u.callback_query;
      if (!cq?.message || !String(cq.data ?? "").startsWith(CB_PREFIX)) continue;
      const msg = cq.message;
      if (String(msg.chat.id) !== this.chatId) continue;
      const parts = cq.data.slice(CB_PREFIX.length).split(":");
      if (parts.length !== 2) { await this.quiet("answerCallbackQuery", { callback_query_id: cq.id }); continue; }
      let choice = "";
      for (const row of msg.reply_markup?.inline_keyboard ?? []) {
        for (const b of row) if (b.callback_data === cq.data) choice = b.text;
      }
      s.answers.push({
        message_id: msg.message_id, nonce: parts[0], index: Number(parts[1]), choice,
        user: cq.from?.username || cq.from?.first_name || "", at: Math.floor(Date.now() / 1000),
      });
      await this.quiet("answerCallbackQuery", { callback_query_id: cq.id, text: `Got it: ${choice}` });
      await this.quiet("editMessageReplyMarkup", {
        chat_id: this.chatId, message_id: msg.message_id,
        reply_markup: { inline_keyboard: [[{ text: `✔ ${choice}`, callback_data: CB_PREFIX + "done" }]] },
      });
    }
    saveState(s);
  }

  /** Poll once (non-blocking); return and clear answers for ids (all if none). */
  async collect(...messageIds: number[]): Promise<Answer[]> {
    await this.poll(0);
    return takeAnswers(messageIds);
  }

  /** Send buttons and wait for a tap. Throws AskTimeout. */
  async ask(question: string, options: string[], o: SendOptions & { timeoutMs?: number } = {}): Promise<Answer> {
    const id = await this.prompt(question, options, o);
    const deadline = Date.now() + (o.timeoutMs ?? 600_000);
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) throw new AskTimeout("timed out waiting for an answer");
      await this.poll(Math.max(1, Math.min(30, Math.floor(left / 1000))));
      const got = takeAnswers([id]);
      if (got.length) return got[0];
    }
  }
}

// ---- shortcuts ------------------------------------------------------------

export const notify = (text: string, o?: SendOptions) => new Client().send(text, o);
export const sendFile = (path: string, caption?: string, o?: SendOptions) =>
  new Client().sendFile(path, caption, o);
export const prompt = (q: string, options: string[], o?: SendOptions) => new Client().prompt(q, options, o);
export const collect = (...ids: number[]) => new Client().collect(...ids);
/** Returns the chosen option text, or null on timeout. */
export async function ask(q: string, options: string[], o?: SendOptions & { timeoutMs?: number }) {
  try { return (await new Client().ask(q, options, o)).choice; }
  catch (e) { if (e instanceof AskTimeout) return null; throw e; }
}
