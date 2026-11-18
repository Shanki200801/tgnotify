import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import * as tg from "../../dist/index.js";

const stub = { calls: [], bodies: [], updates: [], nextId: 100 };
let server, base, dir;

before(async () => {
  server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const method = req.url.split("/").pop();
      const raw = Buffer.concat(chunks);
      const body = (req.headers["content-type"] || "").startsWith("application/json")
        ? JSON.parse(raw.toString()) : raw.toString();
      stub.calls.push(method);
      stub.bodies.push(body);
      let result = true;
      if (method === "sendMessage" || method === "sendDocument") result = { message_id: ++stub.nextId };
      else if (method === "getUpdates") { result = stub.updates; stub.updates = []; }
      res.end(JSON.stringify({ ok: true, result }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tgn-"));
  process.env.TGNOTIFY_STATE = join(dir, "state.json");
  Object.assign(stub, { calls: [], bodies: [], updates: [], nextId: 100 });
});

const client = () => new tg.Client({ token: "SECRET", chat_id: "42", api_base: base });
const cb = (uid, chat, msg, data, label) => ({
  update_id: uid,
  callback_query: {
    id: "cb", data, from: { username: "me" },
    message: { message_id: msg, chat: { id: chat },
      reply_markup: { inline_keyboard: [[{ text: label, callback_data: data }]] } },
  },
});

test("format escapes", () => {
  assert.equal(tg.formatMessage("a<b> & c", { title: "T<1>", level: "error" }),
    "🚨 <b>T&lt;1&gt;</b>\na&lt;b&gt; &amp; c");
});

test("split respects entities and newlines", () => {
  assert.equal(tg.splitText("aaaa&amp;bb", 6)[0], "aaaa");
  assert.equal(tg.splitText("x".repeat(10) + "\n" + "y".repeat(10), 15)[0], "x".repeat(10) + "\n");
});

test("long send puts buttons on last chunk", async () => {
  const ids = await client().send("z".repeat(9000), { buttons: { Open: "https://x" } });
  assert.equal(ids.length, 3);
  assert.equal(stub.bodies[0].reply_markup, undefined);
  assert.ok(stub.bodies[2].reply_markup);
});

test("sendFile uploads multipart", async () => {
  const f = join(dir, "r.txt");
  writeFileSync(f, "hello");
  await client().sendFile(f, "cap");
  assert.equal(stub.calls.at(-1), "sendDocument");
  assert.match(stub.bodies.at(-1), /hello/);
});

test("errors redact token", async () => {
  const c = new tg.Client({ token: "SECRET", chat_id: "1", api_base: "http://127.0.0.1:1" });
  await assert.rejects(c.send("hi"), (e) => !String(e.message).includes("SECRET"));
});

test("prompt + collect, ignoring foreign chats", async () => {
  const c = client();
  const mid = await c.prompt("Apply?", ["Yes", "No"]);
  const data = stub.bodies[0].reply_markup.inline_keyboard[0][0].callback_data;
  assert.ok(data.startsWith("tg:") && data.length <= 64);
  stub.updates = [cb(7, 999, mid, data, "Yes"), cb(8, 42, mid, data, "Yes")];
  const got = await c.collect();
  assert.deepEqual(got.map((a) => [a.message_id, a.choice]), [[mid, "Yes"]]);
  assert.equal(JSON.parse(readFileSync(process.env.TGNOTIFY_STATE, "utf8")).offset, 9);
});

test("ask keeps other answers for later", async () => {
  const c = client();
  stub.nextId = 200;
  stub.updates = [cb(1, 42, 555, "tg:aaaa:0", "Other"), cb(2, 42, 201, "tg:bbbb:1", "No")];
  assert.equal((await c.ask("Q?", ["Yes", "No"], { timeoutMs: 3000 })).choice, "No");
  assert.deepEqual((await c.collect(555)).map((a) => a.choice), ["Other"]);
});

test("config: env overrides file, 0600", () => {
  process.env.TGNOTIFY_CONFIG = join(dir, "c.json");
  const p = tg.saveConfig("f", "1");
  assert.equal(statSync(p).mode & 0o777, 0o600);
  process.env.TGNOTIFY_CHAT_ID = "99";
  const cfg = tg.loadConfig();
  delete process.env.TGNOTIFY_CHAT_ID;
  delete process.env.TGNOTIFY_CONFIG;
  assert.equal(cfg.token, "f");
  assert.equal(cfg.chat_id, "99");
});

test("latest tap per message wins", async () => {
  stub.updates = [cb(1, 42, 300, "tg:abcd:0", "Approve"), cb(2, 42, 300, "tg:abcd:1", "Skip")];
  assert.deepEqual((await client().collect(300)).map((a) => a.choice), ["Skip"]);
});

test("trims whitespace in secrets", async () => {
  const c = new tg.Client({ token: "SECRET\n", chat_id: " 42\n", api_base: base });
  await c.send("hi");
  assert.equal(stub.bodies.at(-1).chat_id, "42");
});
