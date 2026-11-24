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
import os from "node:os";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execSync } from "node:child_process";
import { AdbServerClient } from "@yume-chan/adb";

const BRIDGE_PORT = Number(process.env.BRIDGE_PORT || 8126);
const ADB_PORT = Number(process.env.ADB_PORT || 5037);
const ADB_HOST = "127.0.0.1";
const PROJECT_ROOT = path.dirname(fileURLToPath(import.meta.url));
// adb 启动 daemon 时会写 <TEMP>/adb.log。某些环境（受限账户 / 沙箱）下系统 TEMP 不可写，
// 会把日志重定向到项目内的 .tmp/，避免 "cannot open adb.log: Permission denied" 导致 server 起不来。
const ADB_TMP = path.join(PROJECT_ROOT, ".tmp");
try { fs.mkdirSync(ADB_TMP, { recursive: true }); } catch {}
const ADB_BIN = resolveAdb();

function resolveAdb() {
  // 显式指定的 ADB_BIN 优先级最高
  if (process.env.ADB_BIN && fs.existsSync(process.env.ADB_BIN)) return process.env.ADB_BIN;
  // 项目自带 adb（bin/ 目录）——随项目分发，别人 clone 下来即可直接用。
  // 用 import.meta.url 相对本文件定位，拷到任何盘符/机器都有效。
  const bundled = path.join(PROJECT_ROOT, "bin", process.platform === "win32" ? "adb.exe" : "adb");
  const candidates = [
    bundled,
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
    const env = { ...process.env, TMP: ADB_TMP, TEMP: ADB_TMP, TMPDIR: ADB_TMP };
    const p = spawn(ADB_BIN, args, { stdio: ["ignore", "pipe", "pipe"], env });
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

/* ───────────────────── 无线连接编排：把「配对」这件麻烦事藏起来 ─────────────────────
 *
 * 现实里设备分三类，靠同一套流程是连不上的，所以这里做成四条通道，前端一次扫描全给出来：
 *
 *   ① USB 引导（万能兜底）  插一次线 → adb tcpip 5555 → 自动读设备 IP → 连接 → 记住设备。
 *      覆盖 Android 2.x 至今所有版本，也覆盖没有任何配对界面的老手机。
 *   ② 局域网直连（老电视/盒子） 老设备大多没有 TLS 配对，adbd 直接监听 5555，
 *      扫网段端口就能发现，连上去只需在设备屏幕上点一次「允许」。
 *   ③ 无线调试配对（Android 11+） mDNS 自动找配对端口，用户只输 6 位码，配对后立即连接。
 *   ④ 设备档案（治「端口老变」） 记住连过的设备，下次一键重连：mDNS 换端口也能自愈。
 *
 * 所有路径最终都落到 `adb connect`，所以不会绕过 ADB 的授权模型——能做的只是把步骤减到最少。
 */

/** 跑 adb 但不像 runAdb 那样对非 0 退出码抛错（adb connect/tcpip 常有「退出码 0 但输出 failed」的坑）。 */
function adbRaw(args) {
  return new Promise((resolve) => {
    const env = { ...process.env, TMP: ADB_TMP, TEMP: ADB_TMP, TMPDIR: ADB_TMP };
    const p = spawn(ADB_BIN, args, { stdio: ["ignore", "pipe", "pipe"], env });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", (e) => resolve({ code: -1, out, err: err + e.message }));
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

/** 解析 `adb devices -l`，返回带型号与连接方式的结构。 */
function parseDevices(text) {
  const list = [];
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^List of devices/.test(line) || /^\*/.test(line)) continue;
    const m = line.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
    if (!m) continue;
    let [, serial, state, rest] = m;
    if (state === "no") state = "no permissions"; // 两词状态
    const props = {};
    for (const kv of String(rest || "").split(/\s+/)) {
      const i = kv.indexOf(":");
      if (i > 0) props[kv.slice(0, i)] = kv.slice(i + 1);
    }
    list.push({
      serial,
      state,
      model: props.model || props.product || "",
      product: props.product || "",
      device: props.device || "",
      transportId: props.transport_id || "",
      // serial 带冒号的是网络设备（ip:port），否则是 USB 设备
      isTcp: /:\d+$/.test(serial),
      address: /:\d+$/.test(serial) ? serial : "",
    });
  }
  return list;
}

async function listDevices() {
  await ensureAdbServer();
  const r = await adbRaw(["devices", "-l"]);
  return parseDevices(r.out || r.err);
}

async function mdnsServices() {
  try {
    await ensureAdbServer();
    return await new AdbServerClient(makeConnector()).mDns.getServices();
  } catch { return []; }
}

const normService = (s) => String(s || "").replace(/\.$/, "");

function isPrivateIPv4(ip) {
  const p = String(ip).split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isFinite(n))) return false;
  return p[0] === 10
    || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 192 && p[1] === 168)
    || (p[0] === 169 && p[1] === 254);
}

/** 本机所有可用于局域网通信的 IPv4（排除回环、虚拟网卡常见的 169.254 保留在列表末尾）。 */
function localIPv4s() {
  const out = [];
  const seen = new Set();
  for (const [iface, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== "IPv4" || a.internal) continue;
      if (!isPrivateIPv4(a.address)) continue;
      if (/^(docker|vEthernet|VMware|VirtualBox|Loopback)/i.test(iface)) continue;
      const prefix = a.address.split(".").slice(0, 3).join(".");
      if (seen.has(prefix)) continue;
      seen.add(prefix);
      out.push({ iface, address: a.address, prefix, cidr: prefix + ".0/24" });
    }
  }
  return out;
}

/** 端口探测，带可调超时（局域网扫描要短，判断服务端要长一点）。 */
function tcpProbe(host, port, timeout = 500) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      try { s.destroy(); } catch {}
      resolve(v);
    };
    s.once("connect", () => finish(true));
    s.once("error", () => finish(false));
    s.setTimeout(timeout, () => finish(false));
  });
}

/**
 * 扫局域网里的 ADB 端口。老电视/盒子/老手机通常没有 mDNS 广播，
 * 但 adbd 就监听在 5555，扫出来直接 connect 即可（首次需在设备屏幕上点「允许」）。
 */
async function scanLan({ ports = [5555], timeout = 400, concurrency = 128 } = {}) {
  const nets = localIPv4s();
  if (!nets.length) return [];
  const self = new Set(nets.map((n) => n.address));
  const hosts = [];
  for (const n of nets.slice(0, 3)) {
    for (let i = 1; i <= 254; i++) {
      const ip = `${n.prefix}.${i}`;
      if (!self.has(ip)) hosts.push(ip);
    }
  }
  const portList = (Array.isArray(ports) ? ports : [ports])
    .map(Number)
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
  if (!portList.length) portList.push(5555);

  const hits = [];
  let cursor = 0;
  const worker = async () => {
    while (true) {
      const i = cursor++;
      if (i >= hosts.length) return;
      const ip = hosts[i];
      for (const port of portList) {
        if (await tcpProbe(ip, port, timeout)) { hits.push({ ip, port, address: `${ip}:${port}` }); break; }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, hosts.length) }, worker));
  return hits;
}

/** 从设备 shell 输出里挑出局域网 IP；优先与电脑同网段的那个。 */
async function resolveDeviceIp(serial) {
  const r = await adbRaw(["-s", serial, "shell", "ip -4 addr 2>/dev/null || ifconfig 2>/dev/null"]);
  const text = r.out || "";
  const found = [...text.matchAll(/inet\s+(?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})/g)].map((m) => m[1]);
  const uniq = [...new Set(found)].filter((ip) => !ip.startsWith("127.") && isPrivateIPv4(ip));
  if (!uniq.length) return null;
  const mine = new Set(localIPv4s().map((n) => n.prefix));
  return uniq.find((ip) => mine.has(ip.split(".").slice(0, 3).join("."))) || uniq[0];
}

/* 设备档案：只存在本机 .tmp/ 里（已在 .gitignore），不随项目分发，避免把别人的设备带出去。 */
const KNOWN_FILE = path.join(ADB_TMP, "known-devices.json");
function loadKnown() {
  try {
    const list = JSON.parse(fs.readFileSync(KNOWN_FILE, "utf8"));
    return Array.isArray(list) ? list : [];
  } catch { return []; }
}
function saveKnown(entry) {
  if (!entry?.address) return;
  const list = loadKnown().filter((d) => d.address !== entry.address);
  list.unshift({ ...entry, lastSeen: Date.now() });
  try { fs.writeFileSync(KNOWN_FILE, JSON.stringify(list.slice(0, 24), null, 2)); } catch {}
}

/** `adb connect` 的成败要看输出，不能只看退出码。 */
async function adbConnect(address) {
  const r = await adbRaw(["connect", address]);
  const text = `${r.out}\n${r.err}`;
  if (/failed to connect|unable to connect|cannot connect|refused|timed out/i.test(text)) {
    return { ok: false, message: (r.out || r.err).trim() };
  }
  if (/connected to/i.test(text)) {
    const devices = await listDevices().catch(() => []);
    const dev = devices.find((d) => d.serial === address);
    if (dev && dev.state === "device") saveKnown({ address, model: dev.model, state: dev.state });
    return { ok: true, state: dev?.state || "device", model: dev?.model || "" };
  }
  return { ok: false, message: (r.out || r.err || "adb connect 没有返回结果").trim() };
}

/**
 * 智能连接：给一个 IP（端口可省），自动找对端口再连。
 * 手机/电视的 TLS 调试端口每次开机都可能变，这里先问 mDNS 要当前端口，再退回 5555。
 */
async function smartConnect(input) {
  const text = String(input || "").trim();
  const m = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/);
  if (!m) throw new Error("地址格式应为 IP 或 IP:端口，例如 192.168.1.100:5555");
  const ip = m[1];
  const explicitPort = m[2];
  await ensureAdbServer();

  const candidates = [];
  const fromMdns = new Set();
  const push = (a) => { if (a && !candidates.includes(a)) candidates.push(a); };
  if (explicitPort) push(`${ip}:${explicitPort}`);

  // Android 11+ 的无线调试端口由 mDNS 公布，优先用它
  const svcs = await mdnsServices();
  for (const s of svcs) {
    if (normService(s.service) !== "_adb-tls-connect._tcp") continue;
    if (String(s.address || "").startsWith(ip + ":")) {
      push(s.address);
      fromMdns.add(s.address);
    }
  }
  push(`${ip}:5555`);
  // 老设备可能把 adbd 开在别的常用端口上（个别盒子/电视固件）
  for (const p of [5556, 5037, 5554]) push(`${ip}:${p}`);

  const tried = [];
  let tlsButRejected = false;
  for (const address of candidates) {
    const r = await adbConnect(address);
    tried.push(address);
    if (r.ok && r.state === "device") return { address, ...r };
    if (r.ok && r.state === "unauthorized") {
      const err = new Error(`已连上 ${address}，但设备还没授权本电脑：请在设备屏幕上点「允许」（电视用遥控器选「始终允许」后按确定），然后重试`);
      err.needAuthorize = true;
      err.address = address;
      throw err;
    }
    // 端口是 mDNS 广播出来的、TCP 又确实通，却连不上 —— 这不是网络问题，是「本电脑没被信任」
    if (!r.ok && fromMdns.has(address)) {
      const port = Number(address.split(":")[1]);
      if (await tcpProbe(ip, port, 800)) tlsButRejected = true;
    }
  }
  if (tlsButRejected) {
    const err = new Error(`设备 ${ip} 正在广播无线调试（${[...fromMdns].join("、")}），但还没信任这台电脑。首次只需输一次 6 位配对码：在手机上打开「无线调试 → 使用配对码配对设备」，回到这里点「一键发现设备」，会出现「需配对码」条目。`);
    err.needPair = true;
    err.address = [...fromMdns][0] || "";
    throw err;
  }
  const err = new Error(`连不上 ${ip}：已尝试 ${tried.join("、")}。可能是设备未开 ADB / 不在同一网络 / 路由器开了 AP 隔离`);
  err.tried = tried;
  throw err;
}

/** USB 一键开启无线：插线一次，之后彻底免线。覆盖所有 Android 版本（含老手机）。 */
async function usbBootstrap({ port = 5555 } = {}) {
  const devices = await listDevices();
  const usb = devices.filter((d) => !d.isTcp);
  if (!usb.length) {
    throw new Error("没检测到 USB 设备：请插上数据线，并在手机的「开发者选项」里打开「USB 调试」");
  }
  const target = usb.find((d) => d.state === "device") || usb[0];
  if (target.state === "unauthorized") {
    const err = new Error("设备未授权：请解锁手机/电视，在弹出框里勾选「一律允许」并点「确定」，然后重试");
    err.needAuthorize = true;
    throw err;
  }
  if (target.state !== "device") throw new Error(`设备当前状态为 ${target.state}，请重新插拔数据线后重试`);

  const ip = await resolveDeviceIp(target.serial);
  if (!ip) throw new Error("拿不到设备的局域网 IP：请确认设备已连上 Wi-Fi（电视请连网线或 Wi-Fi）后重试");

  const r = await adbRaw(["-s", target.serial, "tcpip", String(port)]);
  const text = `${r.out}\n${r.err}`;
  if (!/restarting in TCP mode/i.test(text) && r.code !== 0) {
    throw new Error("开启无线调试失败：" + (text.trim() || "设备拒绝了 tcpip 指令"));
  }
  await sleep(1000);

  const address = `${ip}:${port}`;
  // adbd 重启后要给它一点时间重新监听
  for (let i = 0; i < 8; i++) {
    const c = await adbConnect(address);
    if (c.ok && c.state === "device") {
      saveKnown({ address, model: target.model || c.model, state: "device" });
      return { address, model: target.model || c.model || "", serial: target.serial, state: "device" };
    }
    if (c.ok && c.state === "unauthorized") {
      const err = new Error(`无线端口已开（${address}），但设备要求授权：请在设备屏幕上点「允许」后重试`);
      err.needAuthorize = true;
      err.address = address;
      throw err;
    }
    await sleep(700);
  }
  throw new Error(`无线端口已在 ${address} 打开，但连接超时：请确认手机与电脑在同一 Wi-Fi，且路由器未开启 AP 隔离`);
}

/** 配对后立刻连接：配对只管「信任」，连上还得找对 TLS 端口，这里把两步并成一步。 */
async function pairAndConnect({ address, code }) {
  if (!address || !code) throw new Error("缺少配对地址或配对码");
  if (!/^\d{6}$/.test(String(code))) throw new Error("配对码是手机屏幕上的 6 位数字");
  await ensureAdbServer();
  try {
    await new AdbServerClient(makeConnector()).wireless.pair(String(address), String(code));
  } catch (e) {
    const msg = String(e?.message || e);
    if (/wrong password|incorrect|failed to authenticate/i.test(msg)) {
      throw new Error("配对码不对或已过期：请在手机上重新打开「使用配对码配对设备」，用新出现的 6 位码再试");
    }
    if (/timed out|timeout|refused/i.test(msg)) {
      throw new Error("配对超时：配对界面只保持很短时间，请重新打开手机上的配对弹窗，立刻输入配对码");
    }
    throw new Error("配对失败：" + msg);
  }

  const ip = String(address).split(":")[0];
  // 配对成功后 TLS 连接端口会重新广播，等它出现（最多 8 秒）
  for (let i = 0; i < 16; i++) {
    const svcs = await mdnsServices();
    const target = svcs.find(
      (s) => normService(s.service) === "_adb-tls-connect._tcp" && String(s.address || "").startsWith(ip + ":")
    );
    if (target) {
      const r = await adbConnect(target.address);
      if (r.ok && r.state === "device") {
        saveKnown({ address: target.address, model: r.model, state: "device" });
        return { address: target.address, model: r.model || "", state: "device" };
      }
    }
    await sleep(500);
  }
  // mDNS 不可用（部分路由器屏蔽多播）时兜底：扫一下这个 IP 的常见端口
  const fallback = await smartConnect(ip).catch(() => null);
  if (fallback) return fallback;
  throw new Error("配对已成功，但没找到可连接的端口：请点「一键发现设备」重新扫描（配对结果已保存在手机上，不用再配对）");
}

/** 一键探测：把 USB / mDNS / 局域网 / 常用设备一次收齐，前端按组渲染。 */
async function probeAll({ lan = true, ports = [5555] } = {}) {
  await ensureAdbServer();
  const devices = await listDevices().catch(() => []);
  const mdns = await mdnsServices();
  const lanHits = lan ? await scanLan({ ports }) : [];

  const usb = devices.filter((d) => !d.isTcp).map((d) => ({
    serial: d.serial,
    state: d.state,
    model: d.model,
    label: d.model || d.serial,
  }));

  const connectMap = new Map();
  for (const s of mdns) {
    if (normService(s.service) !== "_adb-tls-connect._tcp") continue;
    connectMap.set(s.address, { address: s.address, name: s.name || "", via: "mdns" });
  }
  for (const h of lanHits) {
    if (!connectMap.has(h.address)) connectMap.set(h.address, { address: h.address, name: "", via: "lan" });
  }
  for (const d of devices) {
    if (!d.isTcp || d.state !== "device") continue;
    if (!connectMap.has(d.serial)) connectMap.set(d.serial, { address: d.serial, name: d.model || "", via: "connected" });
  }

  const pairing = mdns
    .filter((s) => normService(s.service) === "_adb-tls-pairing._tcp")
    .map((s) => ({ address: s.address, name: s.name || "" }));

  const known = loadKnown().map((k) => ({
    address: k.address,
    model: k.model || "",
    lastSeen: k.lastSeen || 0,
    online: [...connectMap.keys()].includes(k.address) || devices.some((d) => d.serial === k.address && d.state === "device"),
  }));

  return {
    localIPs: localIPv4s(),
    usb,
    connect: [...connectMap.values()],
    pairing,
    known,
    lanScanned: lan ? localIPv4s().map((n) => n.cidr) : [],
    scannedHosts: lan ? Math.min(254 * Math.min(localIPv4s().length, 3), 762) : 0,
  };
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

    /* ── 一键连接（四条通道的统一入口，前端只需调这几个） ── */
    if (req.method === "GET" && path === "/link/info") {
      json(res, 200, {
        ok: true,
        adb: ADB_BIN,
        adbVersion: await getAdbVersion(),
        localIPs: localIPv4s(),
        known: loadKnown(),
      });
      return;
    }
    if (req.method === "POST" && path === "/link/probe") {
      const body = await readBody(req);
      const ports = body.ports ? [].concat(body.ports) : [5555];
      json(res, 200, { ok: true, ...(await probeAll({ lan: body.lan !== false, ports })) });
      return;
    }
    if (req.method === "POST" && path === "/link/lan-scan") {
      const body = await readBody(req);
      const ports = body.ports ? [].concat(body.ports) : [5555];
      const hits = await scanLan({ ports, timeout: Number(body.timeout) || 400 });
      const devices = await listDevices().catch(() => []);
      json(res, 200, {
        ok: true,
        devices: hits.map((h) => {
          const d = devices.find((x) => x.serial === h.address);
          return { ...h, state: d?.state || "unknown", model: d?.model || "" };
        }),
        subnets: localIPv4s().map((n) => n.cidr),
      });
      return;
    }
    if (req.method === "POST" && path === "/link/usb-bootstrap") {
      const body = await readBody(req);
      json(res, 200, { ok: true, ...(await usbBootstrap({ port: Number(body.port) || 5555 })) });
      return;
    }
    if (req.method === "POST" && path === "/link/connect") {
      const body = await readBody(req);
      if (!body.address) throw new Error("缺少设备 IP 或 IP:端口");
      json(res, 200, { ok: true, ...(await smartConnect(String(body.address))) });
      return;
    }
    if (req.method === "POST" && path === "/link/pair") {
      const body = await readBody(req);
      json(res, 200, { ok: true, ...(await pairAndConnect({ address: body.address, code: body.code })) });
      return;
    }
    if (req.method === "GET" && path === "/link/known") {
      json(res, 200, { ok: true, known: loadKnown() });
      return;
    }
    if (req.method === "POST" && path === "/link/forget") {
      const body = await readBody(req);
      const addr = String(body.address || "");
      const list = loadKnown().filter((d) => d.address !== addr);
      try { fs.writeFileSync(KNOWN_FILE, JSON.stringify(list, null, 2)); } catch {}
      json(res, 200, { ok: true, known: list });
      return;
    }
    if (req.method === "POST" && path === "/link/reconnect") {
      const results = [];
      for (const d of loadKnown().slice(0, 5)) {
        try {
          const r = await smartConnect(d.address);
          results.push({ address: r.address, ok: true, model: r.model || d.model || "" });
        } catch (e) {
          results.push({
            address: d.address,
            ok: false,
            error: e?.message || String(e),
            needAuthorize: !!e?.needAuthorize,
            needPair: !!e?.needPair,
          });
        }
      }
      json(res, 200, { ok: true, results });
      return;
    }

    json(res, 404, { error: "未找到路径：" + path });
  } catch (e) {
    // needAuthorize / tried 是给前端做「下一步该干嘛」引导用的，不要塞进 message 里让用户自己猜
    json(res, 500, {
      error: e?.message || String(e),
      needAuthorize: !!e?.needAuthorize,
      needPair: !!e?.needPair,
      address: e?.address || "",
      tried: e?.tried || undefined,
    });
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
