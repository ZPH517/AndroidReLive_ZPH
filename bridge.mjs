/*
 * SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * 无线连接桥接服务端（bridge）
 * ───────────────────────────────────────────────────────────────────
 * 作用：把「浏览器」和「手机上的无线调试」之间那道浏览器跨不过的墙补上。
 *   浏览器(WebSocket) → 本程序(仅绑 127.0.0.1:8126) → 手机(无线调试)
 *
 * 为什么需要它：
 *   浏览器的 WebUSB 只能走 USB；而且网页出于安全根本不能直接开 TCP 去连手机的 ADB 端口。
 *   无线调试的「配对 / 连接 / 局域网发现」实际是交给本机 adb 服务端做的，
 *   所以本程序会按需启动/复用 adb server（默认 127.0.0.1:5037），把它的能力用 HTTP/WS 包出来。
 *
 * 安全：本程序只绑 127.0.0.1，局域网里的其他机器连不进来；ADB 端口也不暴露到公网。
 *
 * 启动：npm run bridge  （或 node bridge.mjs）
 * 环境变量：
 *   BRIDGE_PORT  本程序监听端口（默认 8126）
 *   ADB_BIN      adb 可执行文件路径（找不到时按常见位置探测，最后退回 PATH 里的 adb）
 *   ADB_PORT     adb server 端口（默认 5037）
 */
import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import { spawn, execSync } from "node:child_process";
import { AdbServerClient } from "@yume-chan/adb";

const BRIDGE_PORT = Number(process.env.BRIDGE_PORT || 8126);
const ADB_PORT = Number(process.env.ADB_PORT || 5037);
const ADB_HOST = "127.0.0.1";
const ADB_BIN = resolveAdb();

function resolveAdb() {
  if (process.env.ADB_BIN && fs.existsSync(process.env.ADB_BIN)) return process.env.ADB_BIN;
  const candidates = [
    "D:/software/Android_adbTools/adb.exe",
    "/d/software/Android_adbTools/adb.exe",
    "/mnt/d/software/Android_adbTools/adb.exe",
    process.env.APPDATA + "/../Local/Android/Sdk/platform-tools/adb.exe",
    "C:/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe",
    "C:/Android/android-sdk/platform-tools/adb.exe",
    "~/AppData/Local/Android/Sdk/platform-tools/adb.exe",
  ].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch {}
  }
  try { execSync("adb version", { stdio: "ignore" }); return "adb"; } catch {}
  return "adb"; // 最后兜底，真正用的时候会报错并提示
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tcpReachable(host, port) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    const done = (v) => { s.destroy(); resolve(v); };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    setTimeout(() => done(false), 800);
  });
}

let adbReady = false;
async function ensureAdbServer() {
  if (adbReady && (await tcpReachable(ADB_HOST, ADB_PORT))) return;
  try { await runAdb(["start-server"]); } catch {}
  for (let i = 0; i < 50; i++) {
    if (await tcpReachable(ADB_HOST, ADB_PORT)) { adbReady = true; return; }
    await sleep(200);
  }
  throw new Error(
    `无法启动本地 ADB 服务端（端口 ${ADB_PORT} 不可达）。请确认 ADB_BIN 指向正确的 adb，${"" }当前使用：${ADB_BIN}`
  );
}

function runAdb(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(ADB_BIN, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", reject);
    p.on("close", (code) => {
      if (code === 0) resolve(out);
      else reject(new Error((err || out || `adb 退出码 ${code}`).toString().trim()));
    });
  });
}

/**
 * 一个把 net.Socket 接到本机 adb server(5037) 的连接器，给本程序内部的 AdbServerClient 用。
 * 每次 connect() 都是一条全新的 TCP 连接，对应一次 ADB 服务端指令。
 */
function makeConnector() {
  return {
    connect() {
      const socket = net.connect(ADB_PORT, ADB_HOST);
      const readable = new ReadableStream({
        start(controller) {
          socket.on("data", (d) => { try { controller.enqueue(new Uint8Array(d)); } catch {} });
          socket.on("end", () => { try { controller.close(); } catch {} });
          socket.on("error", (e) => { try { controller.error(e); } catch {} });
        },
        cancel() { socket.destroy(); },
      });
      const writable = new WritableStream({
        write(chunk) {
          return new Promise((res, rej) => {
            const ok = socket.write(chunk, (e) => (e ? rej(e) : res()));
            if (!ok) socket.once("drain", () => res());
          });
        },
        close() { return new Promise((r) => socket.end(r)); },
        abort() { socket.destroy(); },
      });
      const closed = new Promise((resolve) => socket.on("close", () => resolve(undefined)));
      return {
        readable,
        writable,
        closed,
        close() { socket.destroy(); },
        dispose() { socket.destroy(); },
      };
    },
    addReverseTunnel() { throw new Error("桥接不提供反向隧道监听"); },
    removeReverseTunnel() {},
    clearReverseTunnels() {},
  };
}

async function getAdbVersion() {
  try { return await new AdbServerClient(makeConnector()).getVersion(); } catch { return null; }
}

/* ───────────────────────── 最小 WebSocket 服务端 ───────────────────────── */
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
function acceptKey(key) {
  return crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
}

function parseFrame(buf) {
  if (buf.length < 2) return null;
  const b0 = buf[0], b1 = buf[1];
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;
  let offset = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); offset = 4; }
  else if (len === 127) { if (buf.length < 10) return null; len = Number(buf.readBigUInt64BE(2)); offset = 10; }
  let mask;
  if (masked) { if (buf.length < offset + 4) return null; mask = buf.subarray(offset, offset + 4); offset += 4; }
  if (buf.length < offset + len) return null;
  let payload = buf.subarray(offset, offset + len);
  if (masked) {
    const out = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
    payload = out;
  }
  return { opcode, payload, rest: buf.subarray(offset + len) };
}

function sendFrame(socket, payload, opcode) {
  const len = payload.length;
  let header;
  if (len < 126) { header = Buffer.from([0x80 | opcode, len]); }
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x80 | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  socket.write(Buffer.concat([header, payload]));
}

/**
 * 接管一次已协商的 WebSocket 连接（调用方负责先发 101 握手响应）。
 * onData: 收到客户端二进制消息时回调（payload 是 Buffer）
 * onClose: 连接关闭时回调
 * 返回 { send(Buffer), close() }
 */
function makeWs(socket, onData, onClose) {
  let buf = Buffer.alloc(0);
  let closed = false;
  const send = (data) => { if (!closed) sendFrame(socket, Buffer.from(data), 0x2); };
  const close = () => {
    if (closed) return;
    closed = true;
    try { sendFrame(socket, Buffer.alloc(0), 0x8); } catch {}
    try { socket.end(); } catch {}
    onClose && onClose();
  };
  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (!closed) {
      const f = parseFrame(buf);
      if (!f) break;
      buf = f.rest;
      if (f.opcode === 0x8) { close(); return; }
      else if (f.opcode === 0x9) { if (!closed) sendFrame(socket, f.payload, 0xa); }
      else if (f.opcode === 0x1 || f.opcode === 0x2) { onData && onData(f.payload); }
    }
  });
  socket.on("close", () => { if (!closed) { closed = true; onClose && onClose(); } });
  socket.on("error", () => { if (!closed) { closed = true; onClose && onClose(); } });
  return { send, close };
}

/* ───────────────────────── HTTP + WS 服务 ───────────────────────── */
function setCORS(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}
function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("请求体不是合法 JSON")); } });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;
  setCORS(res);
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  try {
    if (req.method === "GET" && path === "/health") {
      json(res, 200, { ok: true, adb: ADB_BIN, adbPort: ADB_PORT, bridgePort: BRIDGE_PORT });
      return;
    }
    if (req.method === "POST" && path === "/start-server") {
      await ensureAdbServer();
      json(res, 200, { ok: true, version: await getAdbVersion() });
      return;
    }
    if (req.method === "POST" && path === "/mdns") {
      await ensureAdbServer();
      const services = await new AdbServerClient(makeConnector()).mDns.getServices();
      json(res, 200, { ok: true, services });
      return;
    }
    if (req.method === "POST" && path === "/wireless/pair") {
      const body = await readBody(req);
      if (!body.address || !body.code) throw new Error("缺少配对地址或配对码");
      await ensureAdbServer();
      await new AdbServerClient(makeConnector()).wireless.pair(String(body.address), String(body.code));
      json(res, 200, { ok: true });
      return;
    }
    if (req.method === "POST" && path === "/wireless/connect") {
      const body = await readBody(req);
      if (!body.address) throw new Error("缺少连接地址");
      await ensureAdbServer();
      try {
        await new AdbServerClient(makeConnector()).wireless.connect(String(body.address));
      } catch (e) {
        if (e && e.name === "AlreadyConnectedError") { json(res, 200, { ok: true, alreadyConnected: true }); return; }
        throw e;
      }
      json(res, 200, { ok: true });
      return;
    }
    json(res, 404, { error: "未找到路径：" + path });
  } catch (e) {
    json(res, 500, { error: e?.message || String(e) });
  }
});

server.on("upgrade", async (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");
  const key = req.headers["sec-websocket-key"];
  if (!key) { socket.destroy(); return; }

  let targetFactory;
  if (url.pathname === "/server") {
    targetFactory = async () => { await ensureAdbServer(); return net.connect(ADB_PORT, ADB_HOST); };
  } else if (url.pathname === "/adb") {
    const host = url.searchParams.get("host");
    const port = Number(url.searchParams.get("port"));
    if (!host || !port) { socket.write("HTTP/1.1 400 Bad Request\r\n\r\n"); socket.destroy(); return; }
    targetFactory = async () => net.connect(port, host);
  } else {
    socket.destroy();
    return;
  }

  // 先发 101 握手，握手后再异步建目标连接；握手前的数据先缓存
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`
  );

  const pending = [];
  let target = null;
  let closed = false;
  const ws = makeWs(
    socket,
    (data) => { if (target && !target.destroyed) target.write(data); else pending.push(data); },
    () => { closed = true; try { target && target.destroy(); } catch {} }
  );

  try {
    target = await targetFactory();
    for (const d of pending) if (!target.destroyed) target.write(d);
    pending.length = 0;
    target.on("data", (d) => { if (!closed) ws.send(d); });
    target.on("close", () => ws.close());
    target.on("error", () => ws.close());
  } catch (e) {
    try { ws.send(Buffer.from(JSON.stringify({ error: e?.message || String(e) }))); } catch {}
    setTimeout(() => ws.close(), 100);
  }
});

server.on("error", (e) => {
  console.error(e.code === "EADDRINUSE" ? `桥接端口 ${BRIDGE_PORT} 已被占用，请设置 BRIDGE_PORT 为其他端口后重试。` : e.message);
  process.exitCode = 1;
});

server.listen(BRIDGE_PORT, "127.0.0.1", () => {
  console.log(`安卓重生 无线桥接已启动：ws://127.0.0.1:${BRIDGE_PORT}`);
  console.log(`依赖的本机 adb：${ADB_BIN}（服务端端口 ${ADB_PORT}）`);
  console.log(`浏览器侧把桥接地址填 http://127.0.0.1:${BRIDGE_PORT} 即可。`);
});

process.on("unhandledRejection", (e) => console.error("未处理的异常：", e));
