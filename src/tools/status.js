/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

设备状态面板：把主页「设备信息 / 电池管理」里那些只读命令搬进投屏页的窗口。
解析函数直接复用 js/core/core.js 里作者写好的 GJ.props / display / battery /
duration / deviceName，命令逐条串行执行、原文全写进详细日志 —— 不并发抢
WebUSB 连接，也不靠猜某台 ROM 的字段长什么样。
*/

import { GJ } from "../../js/core/core.js";

const COMMANDS = [
  ["props", "getprop"],
  ["size", "wm size"],
  ["density", "wm density"],
  ["battery", "dumpsys battery"],
  ["uptime", "cat /proc/uptime"],
  ["storage", "df -h /sdcard"],
  ["wifi", "settings get global wifi_on"],
  ["ip", "ip -o -4 addr show"],
  ["kernel", "uname -r"],
];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function pickStorage(text) {
  const lines = String(text).trim().split(/\r?\n/).filter((line) => line.trim());
  const row = lines.find((line) => /\d+%\s/.test(line)) || lines.at(-1) || "";
  const cols = row.trim().split(/\s+/);
  if (cols.length < 5) return { text: String(text).trim() || "未读到", used: "—", total: "—", percent: "" };
  return {
    text: row.trim(),
    total: cols[1],
    used: cols[2],
    avail: cols[3],
    percent: cols[4],
  };
}

function pickIp(text) {
  const found = [...String(text).matchAll(/inet\s+(\d+\.\d+\.\d+\.\d+)\//g)]
    .map((m) => m[1])
    .filter((ip) => ip !== "127.0.0.1");
  return found[0] || "—";
}

export function mountStatusPanel({ container, getDriver, log = () => {}, onTray = () => {} }) {
  container.innerHTML = `
    <div class="st-bar">
      <span class="st-title">设备状态</span>
      <button class="st-btn primary" data-act="refresh">刷新</button>
      <label class="st-auto"><input type="checkbox" id="stAuto"> 每分钟自动刷新电量</label>
      <span class="st-spacer"></span>
      <span class="st-state" id="stState">等待读取</span>
    </div>
    <div class="st-scroll">
      <div class="st-cards">
        <div class="st-card"><span class="st-k">设备</span><b class="st-v" id="stDevice">—</b><span class="st-sub" id="stSystem">—</span></div>
        <div class="st-card"><span class="st-k">电量</span><b class="st-v" id="stLevel">—</b><span class="st-sub" id="stPower">—</span></div>
        <div class="st-card"><span class="st-k">存储（/sdcard）</span><b class="st-v" id="stUsed">—</b><span class="st-sub" id="stStorage">—</span></div>
        <div class="st-card"><span class="st-k">网络 / 开机时长</span><b class="st-v" id="stIp">—</b><span class="st-sub" id="stUptime">—</span></div>
      </div>
      <div class="st-section">详细信息</div>
      <div class="st-grid" id="stGrid"></div>
      <div class="st-note">所有数值都来自设备上实时执行的只读命令；命令原文和返回内容写在右侧「详细日志」里（关掉窗口不影响投屏）。</div>
    </div>`;

  const $ = (id) => container.querySelector("#" + id);
  const stateEl = $("stState");
  const autoEl = $("stAuto");
  let timer = null;
  let loaded = false;
  let busy = false;
  let lastProps = {};

  function setState(text, kind = "") {
    stateEl.textContent = text;
    stateEl.className = "st-state" + (kind ? " " + kind : "");
  }

  async function run(command) {
    const driver = getDriver();
    if (!driver?.connected) throw new Error("设备未连接");
    const text = String(
      await driver.adb.subprocess.noneProtocol.spawnWaitText([command + " 2>&1"])
    ).trim();
    log(`[状态] $ ${command} → ${text.slice(0, 160) || "（无输出）"}`, "dim");
    return text;
  }

  function renderOverview(raw) {
    const p = GJ.props(raw.props || "");
    lastProps = p;
    const d = GJ.display(raw.size || "", raw.density || "");
    const b = GJ.battery(raw.battery || "");
    const uptime = GJ.duration(parseFloat(raw.uptime || "0"));
    const storage = pickStorage(raw.storage || "");
    const ip = pickIp(raw.ip || "");
    const wifiOn = /^1$/.test(String(raw.wifi || "").trim());
    const charging = b.ac || b.usb || b.wireless;

    $("stDevice").textContent = GJ.deviceName(p) || "—";
    $("stSystem").textContent = `Android ${p["ro.build.version.release"] || "?"} · API ${p["ro.build.version.sdk"] || "?"}`;
    $("stLevel").textContent = b.level === null ? "—" : `${b.level}%${charging ? " · 充电中" : ""}`;
    $("stPower").textContent = `${b.voltage === null ? "—" : b.voltage.toFixed(3) + " V"} · ${b.temperature === null ? "—" : b.temperature + "℃"}`;
    $("stUsed").textContent = storage.percent || "—";
    $("stStorage").textContent = `已用 ${storage.used} / 共 ${storage.total} · 可用 ${storage.avail || "—"}`;
    $("stIp").textContent = `${wifiOn ? "Wi-Fi 开" : "Wi-Fi 关"} · ${ip}`;
    $("stUptime").textContent = `已开机 ${uptime}`;

    const rows = [
      ["品牌", p["ro.product.brand"]], ["型号", p["ro.product.model"]],
      ["代号", p["ro.product.device"]], ["市场名", GJ.deviceName(p)],
      ["系统版本", p["ro.build.version.release"]], ["SDK", p["ro.build.version.sdk"]],
      ["CPU 架构", p["ro.product.cpu.abi"]], ["屏幕", d.width ? `${d.width}×${d.height} · ${d.dpi || "?"} dpi` : "—"],
      ["内核", (raw.kernel || "").trim()], ["编译版本", p["ro.build.fingerprint"]],
      ["电量原始值", b.level === null ? "—" : String(b.level)], ["充电状态", charging ? "充电中" : "未充电"],
      ["存储原文", storage.text], ["IP 原文", String(raw.ip || "").trim().split(/\r?\n/).slice(0, 2).join(" / ")],
    ];
    $("stGrid").innerHTML = rows
      .map(([k, v]) => `<div class="st-pair"><span>${esc(k)}</span><b title="${esc(v || "—")}">${esc(v || "—")}</b></div>`)
      .join("");

    const tray = b.level === null ? "" : `${b.level}%${charging ? " 充电中" : ""}`;
    onTray({ battery: tray, device: GJ.deviceName(p) });
    return b;
  }

  async function refresh() {
    if (busy) return;
    const driver = getDriver();
    if (!driver?.connected) {
      setState("设备未连接", "err");
      return;
    }
    busy = true;
    setState("正在读取…");
    const raw = {};
    try {
      // 串行：投屏正在跑时不能一次并发九条 shell 去抢这一条 WebUSB 连接
      for (const [key, command] of COMMANDS) {
        try {
          raw[key] = await run(command);
        } catch (error) {
          raw[key] = "";
          log(`[状态] ${key} 读取失败：${error?.message || error}`, "dim");
        }
      }
      renderOverview(raw);
      loaded = true;
      setState("已更新 " + new Date().toLocaleTimeString(), "ok");
    } catch (error) {
      setState("读取失败：" + (error?.message || error), "err");
      log("[状态] 读取失败：" + (error?.message || error), "err");
    } finally {
      busy = false;
    }
  }

  /** 自动刷新只跑两条轻命令，别把整台设备的信息每分钟全量拉一遍 */
  async function refreshLight() {
    if (busy || !loaded) return;
    // 窗口最小化 / 关掉后容器不可见，这时不占连接
    if (!container.isConnected || container.offsetParent === null) return;
    const driver = getDriver();
    if (!driver?.connected) return;
    try {
      const batteryText = await run("dumpsys battery");
      const uptimeText = await run("cat /proc/uptime");
      const b = GJ.battery(batteryText);
      const charging = b.ac || b.usb || b.wireless;
      $("stLevel").textContent = b.level === null ? "—" : `${b.level}%${charging ? " · 充电中" : ""}`;
      $("stPower").textContent = `${b.voltage === null ? "—" : b.voltage.toFixed(3) + " V"} · ${b.temperature === null ? "—" : b.temperature + "℃"}`;
      $("stUptime").textContent = `已开机 ${GJ.duration(parseFloat(uptimeText || "0"))}`;
      onTray({ battery: b.level === null ? "" : `${b.level}%${charging ? " 充电中" : ""}` });
      setState("已更新 " + new Date().toLocaleTimeString(), "ok");
    } catch (error) {
      log(`[状态] 轻量刷新失败：${error?.message || error}`, "dim");
    }
  }

  function syncTimer() {
    clearInterval(timer);
    timer = autoEl.checked ? setInterval(refreshLight, 60000) : null;
  }
  autoEl.addEventListener("change", () => {
    syncTimer();
    log(autoEl.checked ? "[状态] 已开启每分钟刷新电量" : "[状态] 已关闭自动刷新", "dim");
  });

  container.addEventListener("click", (event) => {
    if (event.target.closest('[data-act="refresh"]')) refresh();
  });

  function clear() {
    clearInterval(timer);
    timer = null;
    loaded = false;
    onTray({ battery: "" });
    setState("设备未连接");
  }

  return {
    open() {
      syncTimer();
      if (!loaded) refresh();
    },
    refresh,
    close() {
      clearInterval(timer);
      timer = null;
    },
    clear,
    onEscape: () => false,
    get props() {
      return lastProps;
    },
  };
}

export default mountStatusPanel;
