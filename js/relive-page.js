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
  ["mirror", "back", "home", "recents", "release", "wake", "files", "appManage", "terminal"].forEach((id) => ($(id).disabled = !on));
  $("startBtn").disabled = !on; // 没连设备时别开着空面板
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

$("scanBtn").addEventListener("click", async () => {
  const btn = $("scanBtn");
  btn.disabled = true;
  $("scanStatus").textContent = "扫描中…";
  try {
    const services = await GJTransport.scanWireless({ bridge: bridgeBase() });
    renderDeviceList(services);
    $("scanStatus").textContent = services.length ? `发现 ${services.length} 条` : "未发现（确认手机已开无线调试）";
    if (!services.length) log("未扫描到设备：请确认手机「开发者选项 → 无线调试」已开启，且与电脑同一 Wi-Fi", "dim");
  } catch (e) {
    $("scanStatus").textContent = "扫描失败";
    log("扫描失败：" + (e?.message || e), "err");
  } finally {
    btn.disabled = false;
  }
});

function renderDeviceList(services) {
  const list = $("deviceList");
  list.innerHTML = "";
  const connect = services.filter((s) => s.service === "_adb-tls-connect._tcp.");
  const pairing = services.filter((s) => s.service === "_adb-tls-pairing._tcp.");
  const all = [
    ...connect.map((s) => ({ ...s, kind: "connect" })),
    ...pairing.map((s) => ({ ...s, kind: "pairing" })),
  ];
  if (!all.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "暂无设备";
    list.appendChild(li);
    return;
  }
  for (const s of all) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "dl-name";
    name.textContent = `${s.name || "设备"} · ${s.address}`;
    const tag = document.createElement("span");
    tag.className = "dl-tag " + s.kind;
    tag.textContent = s.kind === "connect" ? "可直连" : "需配对";
    const act = document.createElement("button");
    act.className = "ghost";
    act.textContent = s.kind === "connect" ? "连接" : "去配对";
    act.addEventListener("click", (e) => {
      e.stopPropagation();
      if (s.kind === "connect") connectWirelessTarget(s.address, s.name);
      else {
        $("pairAddr").value = s.address;
        log(`已把配对地址 ${s.address} 填到下方「添加新设备」，请输入手机上的 6 位配对码点「配对」`, "dim");
      }
    });
    li.append(name, tag, act);
    list.appendChild(li);
  }
}

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
    log(error?.message || String(error), "err");
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

$("pairBtn").addEventListener("click", async () => {
  const address = $("pairAddr").value.trim();
  const code = $("pairCode").value.trim();
  try {
    await GJTransport.pairWireless({ bridge: bridgeBase(), address, code });
    log(`配对成功 ${address}，稍后点「扫描设备」应会出现「可直连」条目`, "ok");
    $("pairCode").value = "";
  } catch (error) {
    log("配对失败：" + (error?.message || error), "err");
  }
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
  $("empty").style.display = "";
  setStatus("已断开");
  log("已断开连接");
  syncButtons();
});

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
      maxSize: 1280,
      maxFps: 30,
      bitRate: 8000000,
      // kind 必须透传：以前这里只接一个参数，服务端 DEBUG 和逐条触摸全部降级失败，
      // 「详细日志」开关对镜像这条链等于没生效，默认日志里刷一大片。
      log: (text, kind = "") => log(`[镜像] ${text}`, kind),
      onIssue: showDeviceIssue,
    });
    mirrorSessionId = info.id;
    $("empty").style.display = "none";
    log(`镜像已启动 ${info.width}×${info.height}`, "ok");
    clearInterval(metricsTimer);
    metricsTimer = setInterval(() => {
      const s = window.ReLive.stats();
      $("metrics").textContent = `${s.fps.toFixed(1)} fps · ${s.width}×${s.height}`;
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

/* 顶栏三个按钮 = 快捷开关：再点一次最小化（会话留着），任务栏能点回来 */
$("files").addEventListener("click", () => { if (driver) desktop.toggle("file"); });
$("appManage").addEventListener("click", () => { if (driver) desktop.toggle("app"); });
$("terminal").addEventListener("click", () => { if (driver) desktop.toggle("term"); });

/* Esc 逐级退出：开始菜单 → 当前窗口的面板自己处理（文件预览在捕获阶段
   已经把 Esc 吃掉，不会走到这里）→ 关最上层窗口。终端返回 true 不关。 */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
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
