/*
 * SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * 一键启动器（开发调试用）
 * ───────────────────────────────────────────────────────────────────
 * 双击 start.bat（Windows）/ start.sh（Mac · Linux）即会运行本脚本。
 * 它负责：
 *   1. 拉起网页服务 server.cjs（默认 127.0.0.1:8125）
 *   2. 拉起桥接服务 bridge.mjs（默认 127.0.0.1:8126）
 *   3. 等两个服务都就绪后，自动用默认浏览器打开管理页面
 *   4. 统一打印两个进程的日志（带 [网页] / [桥] 前缀，方便调试）
 *   5. 按 Ctrl+C 时把两个进程一起关掉
 *
 * 想换端口：PORT=9000 BRIDGE_PORT=9001 node launcher.mjs
 */
import { spawn } from "node:child_process";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_PORT = Number(process.env.PORT || 8125);
const BRIDGE_PORT = Number(process.env.BRIDGE_PORT || 8126);
const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;

const C = {
  web: "\x1b[36m", // cyan
  bridge: "\x1b[35m", // magenta
  ok: "\x1b[32m", // green
  warn: "\x1b[33m", // yellow
  reset: "\x1b[0m",
};
const tag = (color, label) => `${color}[${label}]${C.reset} `;

function startProcess(label, color, file, env) {
  const p = spawn(process.execPath, [file], {
    cwd: __dirname,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const prefix = tag(color, label);
  const pipe = (stream) => {
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      for (const line of chunk.split("\n")) {
        if (line.length) process.stdout.write(prefix + line + "\n");
      }
    });
  };
  pipe(p.stdout);
  pipe(p.stderr);
  p.on("exit", (code, signal) => {
    if (signal) process.stdout.write(prefix + `进程被 ${signal} 终止\n`);
    else if (code !== 0) process.stdout.write(prefix + `进程异常退出，退出码 ${code}\n`);
  });
  return p;
}

function portReady(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => { s.destroy(); resolve(false); });
  });
}

async function waitPort(port, label, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await portReady(port)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

function openBrowser(url) {
  const p = process.platform;
  let cmd, args;
  if (p === "win32") { cmd = "cmd"; args = ["/c", "start", "", url]; }
  else if (p === "darwin") { cmd = "open"; args = [url]; }
  else { cmd = "xdg-open"; args = [url]; }
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch {
    process.stdout.write(tag(C.warn, "启动器") + `无法自动打开浏览器，请手动访问 ${url}\n`);
  }
}

async function main() {
  process.stdout.write(tag(C.ok, "启动器") + "正在启动安卓重生 AndroidReLive…\n");

  const web = startProcess("网页", C.web, "server.cjs", { PORT: String(WEB_PORT) });
  const bridge = startProcess("桥", C.bridge, "bridge.mjs", { BRIDGE_PORT: String(BRIDGE_PORT) });

  process.stdout.write(tag(C.ok, "启动器") + `等待网页服务（端口 ${WEB_PORT}）…\n`);
  const webOk = await waitPort(WEB_PORT);
  if (!webOk) process.stdout.write(tag(C.warn, "启动器") + `网页端口 ${WEB_PORT} 未就绪，可能已被占用。\n`);

  process.stdout.write(tag(C.ok, "启动器") + `等待桥接服务（端口 ${BRIDGE_PORT}）…\n`);
  const bridgeOk = await waitPort(BRIDGE_PORT);
  if (!bridgeOk) process.stdout.write(tag(C.warn, "启动器") + `桥接端口 ${BRIDGE_PORT} 未就绪，可能已被占用。\n`);

  if (webOk) {
    process.stdout.write(tag(C.ok, "启动器") + `已就绪，正在打开 ${WEB_URL}\n`);
    openBrowser(WEB_URL);
  } else {
    process.stdout.write(tag(C.warn, "启动器") + `请手动访问 ${WEB_URL}\n`);
  }

  process.stdout.write(tag(C.ok, "启动器") + "按 Ctrl+C 退出（会同时关闭网页与桥）\n");

  let shutting = false;
  const shutdown = () => {
    if (shutting) return;
    shutting = true;
    process.stdout.write(tag(C.ok, "启动器") + "正在关闭…\n");
    try { web.kill("SIGTERM"); } catch {}
    try { bridge.kill("SIGTERM"); } catch {}
    setTimeout(() => process.exit(0), 500);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
