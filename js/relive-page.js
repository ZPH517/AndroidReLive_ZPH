/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-License-Identifier: GPL-3.0-only

重生控制台的页面逻辑（index.html 的 <script type="module">）。
只做「页面这层」的事：抓元素、接按钮、切界面、写日志。
真正的投屏、文件、应用、终端能力都在 relive.bundle.js 里，通过 window.ReLive 调用。

所以：
  · 想改按钮行为、布局、日志显示 → 改这里
  · 想改投屏/解码/设备命令     → 改 src/relive/（改完要 npm run build）
*/

import { GJTransport } from "./core/transport.js";
import "./vendor/relive.bundle.js?v=1.0.0";

const $ = (id) => document.getElementById(id);
const screenCanvas = $("screen");
const logBox = $("log");

let driver = null;
let mirrorSessionId = null;
let mirrorStarting = false;
let metricsTimer = null;

/* ---------- 日志 ---------- *
 * 分级：
 *   ""     正常信息（连接、启动成功、启动失败原因）
 *   "dim"  细节（逐条触摸、诊断值、服务端 DEBUG）—— 只在「详细日志」打开时显示
 *   "err"  错误 —— 永远显示
 * 这样平时右侧只有几行，出问题时点一下「详细日志」才铺开。
 */
let verbose = localStorage.getItem("relive.verbose") === "1";
function log(text, kind = "") {
  if (kind === "dim" && !verbose) return;
  const line = document.createElement("div");
  if (kind) line.className = kind;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  logBox.appendChild(line);
  while (logBox.childElementCount > 400) logBox.firstElementChild.remove();
  logBox.scrollTop = logBox.scrollHeight;
}
function setStatus(text, kind = "") {
  $("status").textContent = text;
  $("status").className = "status " + kind;
}
function syncButtons() {
  const on = !!driver;
  $("connect").disabled = on;
  $("disconnect").disabled = !on;
  ["mirror", "back", "home", "recents", "release", "wake"].forEach((id) => ($(id).disabled = !on));
  $("startBtn").disabled = !on; // 没连设备时别开着空面板
  // 托盘喇叭一直在（仿 Windows），只是没连设备时浮层里显示"未连接"
  $("trayVol").disabled = false;
}

/* ---------- 设备限制提示 ----------
 * 小米 / 红米 / POCO 把「允许电脑模拟点击」单独设了一个开关。没开时投屏、
 * 终端、文件都正常，唯独鼠标键盘和点亮屏幕全被拒。服务端会打印 INJECT_EVENTS，
 * 底层认出来后回调到这里，弹一条常驻指引，不用去日志里翻原因。
 */
function resetDeviceIssue() {
  const box = $("devIssue");
  box.hidden = true;
  box.classList.remove("ok");
  $("diBadge").textContent = "!";
  $("diTitle").textContent = "这台设备拒绝了电脑模拟点击：鼠标、键盘、唤醒都用不了";
  $("diSub").textContent = "小米 / 红米 / POCO：设置 → 更多设置 → 开发者选项 → 打开「USB 调试（安全设置）」→ 重启手机 → 重新连接";
  $("diMore").hidden = true;
  $("diMoreBtn").textContent = "详细步骤";
}
function showDeviceIssue(info) {
  resetDeviceIssue();
  $("devIssue").hidden = false;
  log(`[输入权限] 已显示设备设置指引（触发来源：${info?.source || "未知"}）`, "dim");
}
$("diMoreBtn").addEventListener("click", () => {
  const more = $("diMore");
  more.hidden = !more.hidden;
  $("diMoreBtn").textContent = more.hidden ? "详细步骤" : "收起步骤";
});
$("diClose").addEventListener("click", () => { $("devIssue").hidden = true; });
$("diCheck").addEventListener("click", async () => {
  if (!driver) { log("请先连接设备再验证", "err"); return; }
  const btn = $("diCheck");
  btn.disabled = true;
  btn.textContent = "验证中…";
  try {
    // 这条命令既是自检也是唤醒：能注入就把屏幕一起点亮了
    const result = await window.ReLive.checkInputPermission(driver.adb, log);
    if (result.ok) {
      $("devIssue").classList.add("ok");
      $("diBadge").textContent = "好";
      $("diTitle").textContent = "模拟点击权限已生效，点亮屏幕的命令执行成功";
      $("diSub").textContent = "把「主屏镜像」关掉再点一次重开，鼠标键盘就能用了。";
      log("[输入权限] 自检通过：设备已接受模拟点击，重新开关一次镜像即可控制", "ok");
    } else {
      log("[输入权限] 自检仍未通过：请按上面的步骤在手机上打开开关并重启", "err");
      if (result.denied && result.text) log("[输入权限] 设备原文：" + result.text, "err");
      else if (result.text) log("[输入权限] 命令输出：" + result.text, "dim");
    }
  } catch (error) {
    log("验证失败：" + (error?.message || error), "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "验证是否已开启";
  }
});

/* 连上后顺手读一下屏幕参数写进日志，排查缩放/密度问题用得上。
   两条都是毫秒级轻命令，别在这里跑 dumpsys（首次实测会卡 22 秒）。 */
async function readScreenInfo() {
  try {
    const size = String(await driver.adb.subprocess.noneProtocol.spawnWaitText(["wm", "size"])).trim().replace(/\s*\n\s*/g, " / ");
    const density = String(await driver.adb.subprocess.noneProtocol.spawnWaitText(["wm", "density"])).trim().replace(/\s*\n\s*/g, " / ");
    log(`设备屏幕 ${size} · ${density}`, "dim");
  } catch (error) {
    log("读取屏幕参数失败（不影响使用）：" + (error?.message || error), "dim");
  }
}

/* ---------- 连接 ---------- */
// 连接成功后的共用步骤：记录版本、拉起镜像、保持亮屏、显示触摸点。
// USB / 无线 两条路都走到这里，保证后续体验完全一致。
async function afterConnect(label) {
  log(`已连接 ${label}`, "ok");
  log(`投屏模块版本 ${window.ReLive?.BUILD || "未知"}`, "dim");
  $("build").textContent = "版本 " + (window.ReLive?.BUILD || "未知");
  $("trayBuild").textContent = "版本 " + (window.ReLive?.BUILD || "未知");
  desktop.setTray({ device: label, battery: "" });
  setStatus(label, "ok");
  syncButtons();
  // 连上就把无线面板收起来，别一直占着上半屏挡画面
  $("wirelessPanel").hidden = true;
  await readScreenInfo();
  // 连接成功就自动进主屏镜像，不用再手动点按钮。
  await startMirrorSession();
  try {
    await window.ReLive.keepAwake(driver.adb, true, log);
    await window.ReLive.sendWakeup(driver.adb, log, showDeviceIssue);
  } catch (error) {
    log("设置屏幕常亮失败（不影响投屏）：" + (error?.message || error), "dim");
  }
  const touchHint = await window.ReLive.setShowTouches(driver, true);
  log(
    touchHint
      ? "已在平板上打开『显示触摸位置』：点画面时平板上会出现白点，用来核对坐标"
      : "打开『显示触摸位置』失败（不影响使用）",
    "dim"
  );
}

$("connect").addEventListener("click", async () => {
  $("connect").disabled = true;
  try {
    if (!window.ReLive) throw new Error("投屏模块未加载（relive.bundle.js）");
    if (!window.ReLive.isSupported()) throw new Error("当前浏览器不支持 WebCodecs，请换 Chrome / Edge 94+");
    setStatus("等待连接…");
    resetDeviceIssue();
    await GJTransport.load();

    if (connMode === "wireless") {
      const bridge = bridgeBase();
      const manual = $("manualAddr").value.trim();
      if (manual) {
        log(`经无线桥接直连 ${manual}…`);
        driver = await GJTransport.connectTcp({ bridge, target: manual });
      } else {
        throw new Error("请在下方扫描列表里点「连接」，或填「手动 IP:端口」后再连接");
      }
    } else {
      driver = await GJTransport.connectUsb({});
    }

    await afterConnect(driver.label || driver.serial);
  } catch (error) {
    if (error?.name === "AbortError") {
      log("已取消选择设备", "dim");
      setStatus("未连接");
    } else {
      log(error?.message || String(error), "err");
      setStatus("失败", "error");
    }
    $("connect").disabled = false;
  }
});

/* ---------- 无线连接（本地桥接 bridge.mjs） ----------
 * 浏览器不能直接连无线 ADB，必须借一个跑在电脑上的桥接程序把字节转过去。
 * 这里只负责面板交互：切换模式、测桥、扫设备、配对、连接；真正的传输在 transport 层。 */
let connMode = "usb";

function bridgeBase() {
  let v = ($("bridgeAddr").value || "").trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(v)) v = "http://" + v;
  return v;
}
function setWirelessUI() {
  const wireless = connMode === "wireless";
  $("wirelessPanel").hidden = !wireless;
  $("connMode").querySelectorAll(".seg").forEach((b) => b.classList.toggle("active", b.dataset.mode === connMode));
}
$("connMode").querySelectorAll(".seg").forEach((btn) => {
  btn.addEventListener("click", () => {
    connMode = btn.dataset.mode;
    setWirelessUI();
    if (connMode === "wireless") log("已切到无线模式：填好桥接地址后点「扫描设备」或手动填 IP 连接", "dim");
  });
});

$("bridgeTest").addEventListener("click", async () => {
  const status = $("bridgeStatus");
  status.textContent = "测试中…";
  status.className = "wp-status";
  try {
    const r = await fetch(bridgeBase() + "/health");
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    status.textContent = "桥已连 (adb:" + (j.adbPort || 5037) + ")";
    status.className = "wp-status ok";
  } catch {
    status.textContent = "桥未启动";
    status.className = "wp-status err";
    log("连不上桥接程序：请先 `npm run bridge` 启动它（见 README 无线连接说明）", "err");
  }
});

/* ---------- 一键连接：四条通道 ----------
 * 站在用户角度只有三种设备：
 *   · 新手机（Android 11+）：有配对码，但端口老变 → mDNS 自动找，输 6 位码即可
 *   · 老手机 / 电视 / 盒子：没有配对界面，adbd 就在 5555 → 扫局域网，设备上点一次「允许」
 *   · 不想折腾：插一次 USB → tcpip 一键开无线，之后永久免线（覆盖所有版本）
 * 这三条都在桥接里编排好，网页只负责把结果分组列出来。 */
let quickBusy = false;

function fmtAgo(ts) {
  if (!ts) return "";
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return "刚刚";
  if (s < 3600) return Math.round(s / 60) + " 分钟前";
  if (s < 86400) return Math.round(s / 3600) + " 小时前";
  return Math.round(s / 86400) + " 天前";
}

async function runProbe({ lan = false } = {}) {
  if (quickBusy) return;
  quickBusy = true;
  const btns = ["scanBtn", "lanBtn", "usbBtn", "reconnectBtn"];
  btns.forEach((id) => ($(id).disabled = true));
  $("scanStatus").textContent = lan ? "正在扫描局域网端口（约 3-6 秒）…" : "正在查找设备…";
  try {
    let data;
    try {
      data = await GJTransport.probeWireless({ bridge: bridgeBase(), lan });
    } catch (e) {
      // 兼容旧版桥接：没有 /link/probe 时退回原来的 mDNS 扫描
      if (!/未找到路径|HTTP 404/.test(e?.message || "")) throw e;
      const services = await GJTransport.scanWireless({ bridge: bridgeBase() });
      const type = (s) => String(s?.service || "").replace(/\.$/, "");
      data = {
        usb: [],
        connect: services.filter((s) => type(s) === "_adb-tls-connect._tcp").map((s) => ({ ...s, via: "mdns" })),
        pairing: services.filter((s) => type(s) === "_adb-tls-pairing._tcp"),
        known: [],
      };
    }
    // 一键发现先走快的（mDNS/USB），什么都没找到再自动补一次局域网端口扫描，
    // 这样老电视也能被「一键」发现，用户不用知道 mDNS 是什么。
    const found = (data.usb?.length || 0) + (data.connect?.length || 0) + (data.pairing?.length || 0);
    if (!lan && !found) {
      $("scanStatus").textContent = "没找到广播，正在补扫局域网…";
      data = await GJTransport.probeWireless({ bridge: bridgeBase(), lan: true }).catch(() => data);
    }
    renderDeviceList(data);
    const parts = [];
    if (data.usb?.length) parts.push(`USB ${data.usb.length}`);
    if (data.connect?.length) parts.push(`可连 ${data.connect.length}`);
    if (data.pairing?.length) parts.push(`待配对 ${data.pairing.length}`);
    $("scanStatus").textContent = parts.length ? `发现 ${parts.join(" · ")}` : "没有发现设备";
    if (!parts.length) {
      log("没发现设备。三条路任选：①手机开「无线调试」后重试；②电视/老设备点「扫局域网」；③插 USB 点「USB 一键开启无线」", "dim");
    } else {
      log(`发现 ${parts.join(" · ")}`, "dim");
    }
  } catch (e) {
    $("scanStatus").textContent = "扫描失败";
    log("扫描失败：" + (e?.message || e), "err");
  } finally {
    quickBusy = false;
    btns.forEach((id) => ($(id).disabled = false));
  }
}

/** 一行设备：标题 + 副标题 + 标签 + 若干按钮。列表里四种来源共用同一套渲染，视觉才统一。 */
function deviceRow({ title, sub, tag, tagClass, actions = [] }) {
  const li = document.createElement("li");
  const box = document.createElement("span");
  box.className = "dl-name";
  const b = document.createElement("b");
  b.textContent = title;
  box.appendChild(b);
  if (sub) {
    const s = document.createElement("small");
    s.className = "dl-sub";
    s.textContent = sub;
    box.appendChild(s);
  }
  li.appendChild(box);
  if (tag) {
    const t = document.createElement("span");
    t.className = "dl-tag " + (tagClass || "");
    t.textContent = tag;
    li.appendChild(t);
  }
  for (const a of actions) {
    const btn = document.createElement("button");
    if (a.ghost) btn.className = "ghost";
    btn.type = "button";
    btn.textContent = a.text;
    if (a.title) btn.title = a.title;
    btn.addEventListener("click", (e) => { e.stopPropagation(); a.onClick(); });
    li.appendChild(btn);
  }
  return li;
}

function renderDeviceList(data) {
  const list = $("deviceList");
  list.innerHTML = "";
  const rows = [];

  // ① 插着 USB：最稳的一条路，直接一键把无线开起来
  for (const d of data.usb || []) {
    const label = d.model || d.serial;
    if (d.state === "unauthorized") {
      rows.push(deviceRow({
        title: label, sub: "USB · 等你在设备上点「允许」", tag: "待授权", tagClass: "pairing",
        actions: [{ text: "我已允许", ghost: true, onClick: () => runProbe({ lan: false }) }],
      }));
    } else if (d.state === "device") {
      rows.push(deviceRow({
        title: label, sub: "USB · 可一键开启无线，之后不用插线", tag: "USB", tagClass: "usb",
        actions: [{ text: "开启无线", onClick: () => usbBootstrapFlow() }],
      }));
    } else {
      rows.push(deviceRow({ title: label, sub: "USB · " + d.state, tag: d.state, tagClass: "pairing" }));
    }
  }

  // ② 只差 6 位配对码的设备（配对窗口很短，放在最显眼的位置）
  for (const p of data.pairing || []) {
    rows.push(deviceRow({
      title: p.name || p.address, sub: p.address, tag: "需配对码", tagClass: "pairing",
      actions: [{
        text: "去配对",
        onClick: () => {
          $("pairAddr").value = p.address;
          $("pairCode").value = "";
          $("pairCode").focus();
          log(`配对地址已填好（${p.address}）。输入手机屏幕上的 6 位配对码，输满自动配对并连接。`, "dim");
        },
      }],
    }));
  }

  // ③ 可直接连接：mDNS / 局域网扫描 / 当前已连
  for (const c of data.connect || []) {
    const via = c.via === "lan" ? "局域网 5555" : c.via === "connected" ? "已连接" : "无线调试";
    rows.push(deviceRow({
      title: c.name || c.address, sub: `${c.address} · ${via}`, tag: "可直连", tagClass: "connect",
      actions: [{ text: "连接", onClick: () => reconnectOne(c.address) }],
    }));
  }

  // ④ 连过的设备：端口变了也能靠 mDNS 自愈，一键重连
  const online = new Set((data.connect || []).map((c) => c.address));
  for (const k of data.known || []) {
    if (online.has(k.address)) continue;
    rows.push(deviceRow({
      title: k.model || k.address,
      sub: `${k.address} · ${k.online ? "在线" : "上次 " + fmtAgo(k.lastSeen)}`,
      tag: "常用", tagClass: "known",
      actions: [
        { text: "重连", onClick: () => reconnectOne(k.address) },
        {
          text: "×", ghost: true, title: "从常用里移除",
          onClick: async () => {
            try { await GJTransport.forgetKnown({ bridge: bridgeBase(), address: k.address }); } catch {}
            runProbe({ lan: false });
          },
        },
      ],
    }));
  }

  if (!rows.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "暂无设备，按上面的三种方式试一下";
    list.appendChild(li);
    return;
  }
  rows.forEach((r) => list.appendChild(r));
}

/** USB 一次性引导：插线 → tcpip → 自动取 IP → 连接 → 记住。 */
async function usbBootstrapFlow() {
  $("usbBtn").disabled = true;
  $("scanStatus").textContent = "正在通过 USB 开启无线…";
  try {
    log("已向设备发送 tcpip 指令，等它重新监听无线端口（约 2 秒）…", "dim");
    const r = await GJTransport.usbEnableWireless({ bridge: bridgeBase() });
    log(`无线已开启：${r.address}${r.model ? "（" + r.model + "）" : ""}，现在可以拔掉数据线了`, "ok");
    await connectWirelessTarget(r.address, r.model || r.address);
  } catch (e) {
    log("USB 开启无线失败：" + (e?.message || e), "err");
    if (e?.needAuthorize) log("到设备屏幕上勾选「一律允许」并点「确定」，然后重试", "dim");
    $("scanStatus").textContent = "失败";
  } finally {
    $("usbBtn").disabled = false;
  }
}

/** 重连单个常用设备：先让桥接找回当前端口，再真正建立投屏连接。 */
async function reconnectOne(address) {
  try {
    const r = await GJTransport.connectSmart({ bridge: bridgeBase(), address });
    log(`已连上 ${r.address}${r.model ? "（" + r.model + "）" : ""}`, "ok");
    await connectWirelessTarget(r.address, r.model || r.address);
  } catch (e) {
    log(e?.message || String(e), "err");
    if (e?.needAuthorize) log("设备还没信任这台电脑：到设备屏幕上点「允许」后再点重连", "dim");
    if (e?.needPair) {
      $("pairDetails").open = true;
      log("这是「还没配对」，不是网络问题：点「等待配对码」，再在手机上打开配对弹窗，地址会自动填好，输 6 位数字即可。", "dim");
    }
    runProbe({ lan: false });
  }
}

$("scanBtn").addEventListener("click", () => runProbe({ lan: false }));
$("lanBtn").addEventListener("click", () => runProbe({ lan: true }));
$("usbBtn").addEventListener("click", () => usbBootstrapFlow());

$("reconnectBtn").addEventListener("click", async () => {
  const btn = $("reconnectBtn");
  btn.disabled = true;
  $("scanStatus").textContent = "正在重连常用设备…";
  try {
    const r = await GJTransport.reconnectKnown({ bridge: bridgeBase() });
    const ok = (r.results || []).filter((x) => x.ok);
    if (ok.length) {
      log(`重连成功：${ok.map((x) => x.address).join("、")}`, "ok");
      await connectWirelessTarget(ok[0].address, ok[0].model || ok[0].address);
    } else {
      const first = (r.results || [])[0];
      if (first?.needPair) {
        $("pairDetails").open = true;
        log("常用设备还在，但本电脑没被信任（换电脑/重置过授权）：点「等待配对码」重新配一次即可", "err");
      } else if (first?.needAuthorize) {
        log("常用设备连上了但没授权：到设备屏幕上点「允许」后再点重连", "err");
      } else {
        log("常用设备都没连上：设备可能没开机、不在同一网络，或临时关掉了调试", "err");
      }
      runProbe({ lan: true });
    }
  } catch (e) {
    log("重连失败：" + (e?.message || e), "err");
  } finally {
    btn.disabled = false;
  }
});

async function connectWirelessTarget(target, label) {
  $("connect").disabled = true;
  try {
    if (!window.ReLive) throw new Error("投屏模块未加载");
    await GJTransport.load();
    setStatus("经无线桥接连接…");
    resetDeviceIssue();
    driver = await GJTransport.connectServer({ bridge: bridgeBase(), target });
    await afterConnect(label || driver.label || target);
  } catch (error) {
    const msg = error?.message || String(error);
    log(msg, "err");
    // 三种失败对应的下一步完全不同，必须说清楚，否则用户只能看到 failed to connect 干瞪眼。
    if (error?.needPair) {
      $("pairDetails").open = true;
      log("这台电脑还没被设备信任（不是网络问题）：点「等待配对码」，再在手机上打开配对弹窗，地址会自动填好", "dim");
    } else if (error?.needAuthorize) {
      log("设备已连上但还没信任这台电脑：到设备屏幕上勾选「一律允许」点「确定」（电视用遥控器选「始终允许」）", "dim");
    } else if (/unauthor/i.test(msg)) {
      log("设备显示未授权：解锁设备，在「允许调试吗」弹窗里勾选「一律允许」后点确定，再点「重连」", "dim");
    } else if (/failed to connect|connect.*refus|authentication|timed out/i.test(msg)) {
      log("连不上这个地址：Android 11+ 的调试端口每次开机都会变，别手动抄端口——回到上面点「一键发现设备」或「重连上次设备」自动找回。", "dim");
      log("如果是新设备，先在手机「无线调试 → 使用配对码配对设备」里输一次 6 位码（只需一次，之后永久有效）。", "dim");
    }
    setStatus("失败", "error");
    $("connect").disabled = false;
  }
}

$("manualConnect").addEventListener("click", async () => {
  const manual = $("manualAddr").value.trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$/.test(manual)) {
    log("手动地址格式应为 IP:端口，例如 192.168.1.100:5555", "err");
    return;
  }
  $("connect").disabled = true;
  try {
    if (!window.ReLive) throw new Error("投屏模块未加载");
    await GJTransport.load();
    setStatus("经无线桥接直连…");
    resetDeviceIssue();
    driver = await GJTransport.connectTcp({ bridge: bridgeBase(), target: manual });
    await afterConnect(driver.label || manual);
  } catch (error) {
    log(error?.message || String(error), "err");
    setStatus("失败", "error");
    $("connect").disabled = false;
  }
});

/* 配对 + 连接一步到位：配对只管「信任」，端口还得自己找回，所以两个动作合成一个按钮。
 * 配对码输满 6 位自动提交——配对界面在手机上只停留几十秒，少一次点击就少一次超时。 */
let pairBusy = false;
async function doPair() {
  if (pairBusy) return;
  const address = $("pairAddr").value.trim();
  const code = $("pairCode").value.trim();
  if (!address) { log("先填配对地址（手机「使用配对码配对设备」界面里那个带端口的地址）", "err"); $("pairAddr").focus(); return; }
  if (!/^\d{6}$/.test(code)) { log("配对码是手机屏幕上的 6 位数字", "err"); $("pairCode").focus(); return; }
  pairBusy = true;
  $("pairBtn").disabled = true;
  $("scanStatus").textContent = "正在配对…";
  try {
    const r = await GJTransport.pairAndConnect({ bridge: bridgeBase(), address, code });
    stopPairWait(true);
    log(`配对成功，已连上 ${r.address}${r.model ? "（" + r.model + "）" : ""}。以后这台设备直接点「重连上次设备」即可。`, "ok");
    $("pairCode").value = "";
    $("scanStatus").textContent = "配对成功";
    await connectWirelessTarget(r.address, r.model || r.address);
  } catch (error) {
    log("配对失败：" + (error?.message || error), "err");
    if (error?.needAuthorize) log("到设备屏幕上点「允许」后重试", "dim");
    $("scanStatus").textContent = "配对失败";
  } finally {
    pairBusy = false;
    $("pairBtn").disabled = false;
  }
}
$("pairBtn").addEventListener("click", doPair);
$("pairCode").addEventListener("input", () => {
  if ($("pairCode").value.trim().length === 6 && !pairBusy) doPair();
});

/* 等配对码：配对弹窗在手机上只停留几十秒，手抄「IP:端口」经常来不及，这是配对失败最常见的原因。
 * 这里每 1.5 秒问一次 mDNS，手机一广播配对端口就把地址填好，用户只需抬头输 6 位数字。 */
let pairWaitTimer = null;
function stopPairWait(quiet) {
  if (pairWaitTimer) { clearInterval(pairWaitTimer); pairWaitTimer = null; }
  $("pairWaitBtn").textContent = "等待配对码（不用手抄地址）";
  if (!quiet) log("已停止等待配对广播", "dim");
}
$("pairWaitBtn").addEventListener("click", () => {
  if (pairWaitTimer) { stopPairWait(); return; }
  $("pairDetails").open = true;
  $("pairWaitBtn").textContent = "停止等待";
  log("正在等手机广播配对端口：打开手机「无线调试 → 使用配对码配对设备」并保持该界面，地址会自动填好", "dim");
  const startedAt = Date.now();
  pairWaitTimer = setInterval(async () => {
    if (Date.now() - startedAt > 90000) {
      stopPairWait();
      log("等了 90 秒没抓到配对广播：确认手机和电脑在同一 Wi-Fi、配对弹窗一直开着；也可以手动填地址", "dim");
      return;
    }
    try {
      const data = await GJTransport.probeWireless({ bridge: bridgeBase(), lan: false });
      const p = (data.pairing || [])[0];
      if (!p) return;
      stopPairWait(true);
      $("pairAddr").value = p.address;
      $("pairCode").value = "";
      $("pairCode").focus();
      log(`抓到配对地址：${p.address}。输入手机上的 6 位配对码，输满自动配对并连接。`, "ok");
    } catch { /* 单次失败忽略，下一轮再试 */ }
  }, 1500);
});

setWirelessUI();

$("disconnect").addEventListener("click", async () => {
  clearInterval(metricsTimer);
  $("disconnect").disabled = true;
  resetDeviceIssue();
  try { desktop.closeAll(); } catch {}
  try { terminalPanel?.shutdown(); } catch {}
  try { statusPanel?.clear(); } catch {}
  try { desktop.setTray({ device: "未连接", battery: "" }); } catch {}
  try { await window.ReLive?.stop(); } catch {}
  // 关掉设备端所有 scrcpy 进程，否则下次连接会被残留进程占着编码器
  try { await window.ReLive?.cleanup(driver); } catch {}
  // 恢复平板自己的熄屏策略，别让它一直亮着耗电
  try { await window.ReLive?.keepAwake(driver?.adb, false); } catch {}
  try { await driver?.close(); } catch {}
  driver = null;
  mirrorSessionId = null;
  screenCanvas.classList.remove("on");
  closeVolFlyout(); // 音量浮层跟着断开一起收起
  closeQualityFlyout();
  $("empty").style.display = "";
  setStatus("已断开");
  log("已断开连接");
  syncButtons();
});

/* ---------- 任务栏喇叭 → 音量浮层（仿 Windows） ----------
 * 点右下角喇叭，在托盘上方弹出：
 *   媒体 = 平板自己的媒体音量（就是你在电脑上听到的那个声音，改它立刻能听出来）
 *   电脑端 = 浏览器里的播放增益，只影响你听多响，不碰平板
 *   其他平板音量 = 通话 / 铃声 / 通知 / 闹钟，折叠起来免得占地方
 * 读写走设备端 cmd media_session volume（Android 11+ 都有）。
 * 联想这类机器把 /system/bin/media 删了，老写法 `media volume` 直接报
 * "inaccessible or not found"，所以 device.js 里做了两级兜底。 */
const volFlyout = $("volFlyout");

function fmtPct(v) {
  return Math.round(Math.max(0, Math.min(1, Number(v) || 0)) * 100) + "%";
}

/* 第二行：电脑端播放增益（本地 AudioContext） */
function syncPcVolume(state) {
  const s = state || window.ReLive?.getAudioState?.() || { available: false, muted: false, volume: 1 };
  const muted = !!s.muted;
  // 静音时滑块仍停在原来的音量位置，取消静音能回到那个大小（和 Windows 一致）
  const vol = Number(s.volume ?? 1);
  const mute = $("vfMute");
  mute.textContent = muted ? "🔇" : vol < 0.01 ? "🔈" : vol < 0.5 ? "🔉" : "🔊";
  mute.classList.toggle("off", muted);
  $("vfPcVol").value = String(vol);
  $("vfPcVal").textContent = muted ? "静音" : fmtPct(vol);
  // 只有"压根没有设备声音"时才锁住；静音状态照样能拖（拖一下就取消静音）
  const usable = !!s.available;
  $("vfPcVol").disabled = !usable;
  $("vfPcVol").title = usable ? "电脑端播放音量" : "当前没有设备声音（需 Android 12+ 且镜像已启动）";
}

$("vfPcVol").addEventListener("input", () => {
  const v = Number($("vfPcVol").value);
  // 拖着滑块时顺手取消静音，和 Windows 的直觉一致
  if (window.ReLive?.getAudioState?.().muted) window.ReLive?.setAudioMuted?.(false);
  window.ReLive?.setAudioVolume?.(v);
  syncPcVolume();
});
$("vfMute").addEventListener("click", () => {
  if (!window.ReLive) return;
  // 别用 toggle：audio 那边的 toggle 为了兼容"首次点击唤醒"做了特殊处理，
  // 第一次点并不会静音。这里直接按当前状态取反，点一下就是一下。
  const now = window.ReLive.getAudioState?.() || {};
  window.ReLive.resumeAudio?.(); // 在用户手势里唤醒 AudioContext
  window.ReLive.setAudioMuted?.(!now.muted);
  syncPcVolume();
});

/* 造一行"名字 + 滑块 + 数值"，媒体那行和其他四路共用 */
function makeVolRow({ name, title }) {
  const row = document.createElement("div");
  row.className = "vf-row";
  const label = document.createElement("span");
  label.className = "vf-name";
  label.textContent = name;
  if (title) label.title = title;
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "0";
  slider.max = "15";
  slider.disabled = true; // 读到真实 max 之前先锁住
  const num = document.createElement("span");
  num.className = "vf-num";
  num.textContent = "…";
  row.append(label, slider, num);
  return { row, slider, num };
}

let volumeBusy = false;
/* 把一路设备音量灌进已有的一行 */
async function fillVolRow(slot, stream, name) {
  const { slider, num } = slot;
  try {
    const info = await window.ReLive.getDeviceVolume(driver.adb, stream);
    const max = info.max && info.max > 0 ? info.max : stream === 3 ? 15 : 7;
    // 通话音量这类流最小是 1 不是 0，照抄设备给的区间，别自己写死
    const min = Number.isFinite(info.min) ? info.min : 0;
    slider.min = String(min);
    slider.max = String(max);
    if (info.current !== null && info.current !== undefined) {
      slider.value = String(Math.min(info.current, max));
      num.textContent = info.current + "/" + max;
    } else {
      // 极个别机型输出格式对不上，把原文亮出来方便对症改解析
      num.textContent = "?";
      num.title = String(info.raw || "").slice(0, 200);
    }
    slider.disabled = false;
    slider.onchange = async () => {
      if (volumeBusy) return;
      volumeBusy = true;
      num.textContent = "…";
      try {
        const after = await window.ReLive.setDeviceVolume(driver.adb, stream, Number(slider.value));
        const m = after?.max && after.max > 0 ? after.max : max;
        const cur = after?.current;
        num.textContent = cur !== null && cur !== undefined ? cur + "/" + m : "已下发";
        log("平板「" + name + "」设为 " + slider.value + "（回读 " + (cur ?? "?") + "/" + m + "）", "dim");
      } catch (e) {
        num.textContent = "失败";
        log("设置平板「" + name + "」失败：" + (e?.message || e), "err");
      } finally {
        volumeBusy = false;
      }
    };
  } catch (e) {
    num.textContent = "失败";
    num.title = String(e?.message || e);
    slider.disabled = true;
  }
}

/* 主控行（媒体音量）建一次就复用，反复开浮层不重复插 DOM */
const mediaSlot = makeVolRow({ name: "媒体", title: "平板自己的媒体音量，改它你立刻能听出大小变化" });
const staticMediaRow = document.querySelector("#volFlyout .vf-row");
if (staticMediaRow) staticMediaRow.replaceWith(mediaSlot.row);

let moreSlots = null; // 其他四路：通话 / 铃声 / 通知 / 闹钟
const MORE_STREAMS = [
  { stream: 0, name: "通话", hint: "打电话时的听筒音量" },
  { stream: 2, name: "铃声", hint: "来电铃声" },
  { stream: 5, name: "通知", hint: "App 通知提示音" },
  { stream: 4, name: "闹钟", hint: "闹钟音量" },
];

function buildMoreRows() {
  if (moreSlots && moreSlots.length) return moreSlots;
  const box = $("vfDevRows");
  moreSlots = MORE_STREAMS.map((s) => {
    const slot = makeVolRow({ name: s.name, title: s.hint });
    box.appendChild(slot.row);
    return slot;
  });
  return moreSlots;
}

async function renderVolumes() {
  syncPcVolume();
  if (!driver) {
    mediaSlot.slider.disabled = true;
    mediaSlot.num.textContent = "未连接";
    mediaSlot.slider.title = "连上设备后才能调平板音量";
    buildMoreRows().forEach((slot) => {
      slot.slider.disabled = true;
      slot.num.textContent = "—";
    });
    return;
  }
  mediaSlot.slider.title = "";
  await fillVolRow(mediaSlot, 3, "媒体");
  // 其他四路只在展开时才读，省一堆 shell 往返
  buildMoreRows();
  if ($("vfMore").open) {
    await Promise.all(
      MORE_STREAMS.map((s, i) => fillVolRow(moreSlots[i], s.stream, s.name))
    );
  }
}

function openVolFlyout() {
  closeQualityFlyout(); // 两个浮层互斥
  volFlyout.hidden = false;
  $("trayVol").classList.add("on");
  window.ReLive?.resumeAudio?.(); // 这次点击本身就是手势，顺手唤醒音频
  renderVolumes();
}
function closeVolFlyout() {
  if (!volFlyout) return;
  volFlyout.hidden = true;
  $("trayVol").classList.remove("on");
}
function toggleVolFlyout() {
  if (volFlyout.hidden) openVolFlyout();
  else closeVolFlyout();
}

// 展开"其他平板音量"时才去读那四路
$("vfMore").addEventListener("toggle", () => {
  if (!$("vfMore").open || !driver) return;
  buildMoreRows();
  MORE_STREAMS.forEach((s, i) => fillVolRow(moreSlots[i], s.stream, s.name));
});

// 点浮层外面就收起（Windows 也是这样）
document.addEventListener("pointerdown", (event) => {
  if (!qualityFlyout.hidden) {
    if (qualityFlyout.contains(event.target) || $("trayQuality").contains(event.target)) return;
    closeQualityFlyout();
  }
  if (volFlyout.hidden) return;
  if (volFlyout.contains(event.target) || $("trayVol").contains(event.target)) return;
  closeVolFlyout();
});
// 声音状态变了刷新第二行；托盘图标由 desktop 模块自己更新
window.ReLive?.setAudioStateCb?.((s) => {
  if (!volFlyout.hidden) syncPcVolume(s);
});

/* ---------- 投屏画质三档 ----------
 * 码率是「启动投屏时才传给设备」的参数，运行中改不了，所以切档 =
 * 停掉当前画面 → 用新参数重启。这里把整套流程收在一处。
 * 档位数值：流畅档刻意压到 960/2M，老路由器 + 多设备时最抗卡顿。
 */
const QUALITY_LEVELS = {
  smooth:   { label: "流畅", maxSize: 960,  maxFps: 20, bitRate: 2000000 },
  balanced: { label: "均衡", maxSize: 1280, maxFps: 30, bitRate: 8000000 },
  hd:       { label: "高清", maxSize: 1920, maxFps: 30, bitRate: 12000000 },
};
const QUALITY_KEYS = ["smooth", "balanced", "hd"];
let qualityKey = "balanced";
try {
  const saved = localStorage.getItem("relive.quality");
  if (QUALITY_LEVELS[saved]) qualityKey = saved;
} catch {}
const qualityFlyout = $("qualityFlyout");

function currentQuality() {
  return QUALITY_LEVELS[qualityKey];
}
function syncQualityUi() {
  const label = currentQuality().label;
  $("trayQuality").textContent = "📺 " + label;
  $("trayQuality").title = `投屏画质：${label}（点开切换，网络卡就选「流畅」）`;
  $("qfCurrent").textContent = label;
  document.querySelectorAll(".qf-item").forEach((el) => {
    el.classList.toggle("on", el.dataset.quality === qualityKey);
  });
}
function openQualityFlyout() {
  closeVolFlyout(); // 两个浮层互斥，别叠在一起
  qualityFlyout.hidden = false;
  $("trayQuality").classList.add("on");
}
function closeQualityFlyout() {
  if (!qualityFlyout) return;
  qualityFlyout.hidden = true;
  $("trayQuality").classList.remove("on");
}

$("trayQuality").addEventListener("click", () => {
  if (qualityFlyout.hidden) openQualityFlyout();
  else closeQualityFlyout();
});
document.querySelectorAll(".qf-item").forEach((el) => {
  el.addEventListener("click", async () => {
    const key = el.dataset.quality;
    closeQualityFlyout();
    if (key === qualityKey) return;
    qualityKey = key;
    try { localStorage.setItem("relive.quality", key); } catch {}
    syncQualityUi();
    const q = currentQuality();
    log(`投屏画质已切到「${q.label}」：${q.maxSize} · ${q.maxFps}fps · ${Math.round(q.bitRate / 1000)}K`, "ok");
    // 画面正在跑才需要重启；没连设备/没投屏时只记设置，下次启动自动生效
    if (mirrorSessionId) {
      log("正在用新画质重启画面…", "dim");
      await stopMirrorSession();
      await startMirrorSession();
    }
  });
});
syncQualityUi();



/* ---------- 画面自适应铺满 ----------
 * canvas 的固有尺寸(width/height)就是视频分辨率，CSS 之前只给了 max 上限、
 * 没给确定的显示尺寸，所以画面永远按原始像素缩在中间一小块。
 * 这里按「完整显示 + 尽可能大」算显示尺寸：取窗口可用宽高与视频宽高比里
 * 最省的那个方向（letterbox 留黑边），把画面撑到最大。
 * 点击坐标换算走的是 getBoundingClientRect()，会自动跟着实际显示尺寸走，
 * 所以输入层(input.js)完全不用改，点哪还是准的。
 */
function fitScreen() {
  if (!screenCanvas.classList.contains("on")) return;
  const vw = screenCanvas.width, vh = screenCanvas.height;
  const stage = $("stage");
  const availW = Math.max(0, stage.clientWidth - 8);
  const availH = Math.max(0, stage.clientHeight - 8);
  if (!vw || !vh || !availW || !availH) return;
  const scale = Math.min(availW / vw, availH / vh);
  screenCanvas.style.width = Math.max(1, Math.floor(vw * scale)) + "px";
  screenCanvas.style.height = Math.max(1, Math.floor(vh * scale)) + "px";
}
// 窗口缩放 / F11 / 专注模式切日志栏，只要 stage 尺寸变了就重算
try { new ResizeObserver(fitScreen).observe($("stage")); } catch {}

/* ---------- 主屏镜像 ----------
 * 抽成两个函数，连接成功后自动 start，顶栏按钮再负责"开关切换"。
 * 切换（关闭→重开）的稳定性靠 src/scrcpy/index.js 里"等旧 server 真正退出"那条逻辑兜底，
 * 这里只在成功后更新 UI、失败后兜底（重新让提示露出来）。 */
async function startMirrorSession() {
  if (mirrorSessionId) return;
  // 防止「关掉再点」时连点触发多个并发启动（它们会互相清掉对方的转发）
  if (mirrorStarting) return;
  mirrorStarting = true;
  screenCanvas.classList.add("on");
  // 先露出"正在启动"，盖在黑屏上；成功才收起，失败再换成错误提示。
  $("empty").style.display = "";
  $("empty").innerHTML = "正在启动主屏镜像…<br><small>若长时间无画面，点顶栏「主屏镜像」关闭再重开</small>";
  try {
    const info = await window.ReLive.startSession({
      id: "mirror",
      driver,
      canvas: screenCanvas,
      mode: "mirror",
      // 画质三档：网络差选「流畅」降码率抗卡，网好选「高清」更清晰
      maxSize: currentQuality().maxSize,
      maxFps: currentQuality().maxFps,
      bitRate: currentQuality().bitRate,
      // kind 必须透传：以前这里只接一个参数，服务端 DEBUG 和逐条触摸全部降级失败，
      // 「详细日志」开关对镜像这条链等于没生效，默认日志里刷一大片。
      log: (text, kind = "") => log(`[镜像] ${text}`, kind),
      onIssue: showDeviceIssue,
    });
    mirrorSessionId = info.id;
    $("empty").style.display = "none";
    log(`镜像已启动 ${info.width}×${info.height}`, "ok");
    // canvas 的真实分辨率要等第一帧解码完才写入，这里连着补几次，确保按最终尺寸铺满
    fitScreen();
    setTimeout(fitScreen, 120);
    setTimeout(fitScreen, 500);
    clearInterval(metricsTimer);
    metricsTimer = setInterval(() => {
      const s = window.ReLive.stats();
      $("metrics").textContent = `${s.fps.toFixed(1)} fps · ${s.width}×${s.height}`;
      fitScreen(); // 分辨率在运行中若变化（旋转屏幕等），持续跟着调整
    }, 1000);
    mirrorStarting = false;
  } catch (error) {
    // 兜底：把画面藏起来、露出提示，按钮回到"可重新开启"状态，避免卡在"画布隐藏但鼠标没反应"
    mirrorSessionId = null;
    screenCanvas.classList.remove("on");
    $("empty").style.display = "";
    $("empty").innerHTML =
      '主屏镜像启动失败，点顶栏「主屏镜像」再试一次<br><small>' +
      String(error?.message || error).replace(/</g, "&lt;") +
      '</small><br><small>详见右侧运行日志（可点「详细日志」展开诊断）</small>';
    log("镜像失败：" + (error?.message || error), "err");
    mirrorStarting = false;
  }
}

async function stopMirrorSession() {
  if (!mirrorSessionId) return;
  const id = mirrorSessionId;
  mirrorSessionId = null;
  try {
    await window.ReLive.stop(id);
  } catch {
    /* 关不掉也无所谓，下面强制复位 UI */
  }
  screenCanvas.classList.remove("on");
  clearInterval(metricsTimer);
  log("镜像已关闭", "dim");
}

$("mirror").addEventListener("click", () => {
  if (mirrorSessionId) stopMirrorSession();
  else startMirrorSession();
});

/* ---------- 顶栏按键 ---------- */
["back", "home", "recents", "release"].forEach((name) => {
  $(name).addEventListener("click", () => window.ReLive.systemKey(null, name));
});

/* 唤醒：平板熄屏后不用重新连接，点一下就能叫醒（再点主屏镜像就正常了） */
$("wake").addEventListener("click", async () => {
  if (!driver) return;
  try {
    const after = await window.ReLive.wakeScreen(driver.adb, log, showDeviceIssue);
    log(
      after.awake === false
        ? `唤醒命令已发，但屏幕仍是 ${after.wakefulness}（可能设了锁屏密码或系统限制）`
        : `屏幕已点亮（当前状态 ${after.wakefulness || "未知"}）`,
      after.awake === false ? "err" : "ok"
    );
  } catch (error) {
    log("唤醒失败：" + (error?.message || error), "err");
  }
});

/* 详细日志开关：状态存本地，刷新后保持 */
function syncVerboseButton() {
  const btn = $("verbose");
  btn.classList.toggle("on", verbose);
  btn.textContent = verbose ? "详细日志 · 开" : "详细日志";
}
$("verbose").addEventListener("click", () => {
  verbose = !verbose;
  localStorage.setItem("relive.verbose", verbose ? "1" : "0");
  syncVerboseButton();
  if (verbose) log("已开启详细日志：逐条触摸、诊断值、服务端 DEBUG 都会显示", "dim");
});
syncVerboseButton();

/* 专注模式：收起右侧日志栏，投屏区铺满窗口；状态记在本地，刷新后保持 */
function applyFocus(on, quiet = false) {
  document.body.classList.toggle("focus", on);
  $("focus").classList.toggle("on", on);
  $("focus").textContent = on ? "显示日志栏" : "专注模式";
  try { localStorage.setItem("relive.focus", on ? "1" : "0"); } catch {}
  fitScreen(); // 日志栏收起后 stage 变宽，画面立刻跟着放大
  if (!quiet) log(on ? "已收起右侧日志栏，投屏区铺满窗口" : "已恢复右侧日志栏", "dim");
}
let savedFocus = false;
try { savedFocus = localStorage.getItem("relive.focus") === "1"; } catch {}
applyFocus(savedFocus, true);
$("focus").addEventListener("click", () => applyFocus(!document.body.classList.contains("focus")));

/* ---------- 桌面窗口 ----------
 * WebUSB 在同一个页面里只能有一个持有者，所以所有工具都长在这个页面、
 * 共用同一条 driver，各自装进一扇可拖可缩的窗口。窗口可以叠着开，
 * 最小化只收进任务栏、不销毁面板：终端会话、文件目录、应用列表都留着。
 * 面板容器平时收在 #winHosts，开窗口时才搬进去，三个面板模块内部不用改。
 */
let filePanel = null;
let appPanel = null;
let terminalPanel = null;
let statusPanel = null;
let shotPanel = null;

const desktop = window.ReLive.createDesktop({
  layer: $("desktop"),
  taskbar: $("taskbar"),
  log,
  // 点任务栏喇叭 → 由这里弹音量浮层（浮层要读写设备音量，得留在页面侧）
  onTrayAudioClick: () => toggleVolFlyout(),
  tools: [
    {
      id: "file", title: "文件管理", mark: "文", color: "#3d7ea6", host: $("fpPanel"),
      width: 1040, height: 700, minWidth: 620, minHeight: 400,
      onMount: (host) => (filePanel = window.ReLive.mountFilePanel({
        container: host, getDriver: () => driver, log,
        onClose: () => desktop.close("file"),
      })),
      onOpen: () => filePanel.open(localStorage.getItem("relive.filePath") || "/sdcard"),
      onClose: () => { if (filePanel?.path) localStorage.setItem("relive.filePath", filePanel.path); },
      onEscape: () => false,
    },
    {
      id: "app", title: "应用管理", mark: "应", color: "#6b52a3", host: $("apPanel"),
      width: 1120, height: 720, minWidth: 700, minHeight: 420,
      onMount: (host) => (appPanel = window.ReLive.mountAppPanel({
        container: host, getDriver: () => driver, log,
        onClose: () => desktop.close("app"),
      })),
      onOpen: () => appPanel.open(),
      onClose: () => appPanel?.close(), // 收起详情，缓存由面板自己管
      onEscape: (panel) => !!panel?.onEscape?.(),
    },
    {
      id: "term", title: "ADB 终端", mark: ">", color: "#2f6c4a", host: $("tmPanel"),
      width: 1000, height: 640, minWidth: 560, minHeight: 340,
      onMount: (host) => (terminalPanel = window.ReLive.mountTerminalPanel({
        container: host, getDriver: () => driver, log,
        onClose: () => desktop.close("term"),
      })),
      onOpen: () => { requestAnimationFrame(() => terminalPanel?.fit()); terminalPanel.open(); },
      onResize: () => terminalPanel?.fit(),
      onClose: () => {}, // 关窗口也保留 shell 会话，断开设备时才 shutdown
      onEscape: () => true, // 终端里 Esc 是有效按键（vi / less），绝不抢
    },
    {
      id: "status", title: "设备状态", mark: "态", color: "#8a6a2f", host: $("stPanel"),
      width: 780, height: 560, minWidth: 480, minHeight: 340,
      onMount: (host) => (statusPanel = window.ReLive.mountStatusPanel({
        container: host, getDriver: () => driver, log,
        onTray: ({ battery, device } = {}) => desktop.setTray(device ? { battery, device } : { battery }),
      })),
      onOpen: () => statusPanel?.open(),
      onClose: () => statusPanel?.close(),
      onEscape: () => false,
    },
    {
      id: "shot", title: "截图", mark: "图", color: "#a35a3d", host: $("ssPanel"),
      width: 760, height: 540, minWidth: 440, minHeight: 320,
      onMount: (host) => (shotPanel = window.ReLive.mountScreenshotPanel({
        container: host, getDriver: () => driver, log,
      })),
      onOpen: () => shotPanel?.open(),
      onClose: () => shotPanel?.close(),
      onEscape: () => !!shotPanel?.onEscape?.(),
    },
  ],
});

/* 文件 / 应用管理 / 终端 / 设备状态 / 截图都只从左下角「开始」菜单进，
   顶栏不再放快捷按钮——顶栏留给连接、投屏、导航这些高频操作。 */

/* Esc 逐级退出：音量浮层 → 开始菜单 → 当前窗口的面板自己处理（文件预览在捕获阶段
   已经把 Esc 吃掉，不会走到这里）→ 关最上层窗口。终端返回 true 不关。 */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (!$("qualityFlyout").hidden) {
    closeQualityFlyout();
    event.stopPropagation();
    event.preventDefault();
    return;
  }
  if (!$("volFlyout").hidden) {
    closeVolFlyout();
    event.stopPropagation();
    event.preventDefault();
    return;
  }
  if (desktop.onEscape()) {
    event.stopPropagation();
    event.preventDefault();
  }
});

window.addEventListener("beforeunload", () => {
  try { terminalPanel?.shutdown(); } catch {}
  try { shotPanel?.clear(); } catch {}
  try { window.ReLive?.stop(); } catch {}
});

syncButtons(); // 初始态：没连设备时「开始」菜单不可用
log("页面已加载，等待连接设备");
