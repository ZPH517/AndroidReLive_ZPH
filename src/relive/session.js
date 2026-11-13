/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

投屏会话层（session）
======================================
负责「从设备拿到视频流并画到画布上」这一整条链：

  · 推送 / 校验 scrcpy-server（每次启动前核对字节数，防被系统清理）
  · 组织启动参数（max_size / max_fps / bit_rate / scid / 编码器）
  · 启动失败的三段重试：重放取证 → 精准清理该 scid 的进程 → 换默认 socket
  · 视频流 → WebCodecs 解码 → CanvasRenderer 绘制
  · 输入通道（input.js）、系统按键、截图、显示触摸位置
  · 会话生命周期（start / stop / stats / cleanup）

设备侧的具体操作（shell、杀进程、唤醒、logcat 取证）在 device.js，
这里只负责编排。想单独调设备命令，去 device.js，不用碰这个文件。

依赖：@yume-chan/adb-scrcpy（MIT）、@yume-chan/scrcpy（MIT）、
      scrcpy-server 3.3.3（Apache-2.0）
*/

import {
  INJECT_DENIED,
  checkInputPermission,
  clearScrcpyReverse,
  countScrcpyProcs,
  createOutputCapture,
  dumpCrashLog,
  getPowerState,
  getAndroidSdk,
  keepAwake,
  killServerByScid,
  pkillServer,
  replayServerCommand,
  reportInjectIssue,
  resetInjectIssue,
  sendWakeup,
  shCmd,
  waitForServerGone,
  wakeScreen,
} from "./device.js";

import { AdbScrcpyClient, AdbScrcpyOptions3_3_3 } from "@yume-chan/adb-scrcpy";
import { ReadableStream as TangoReadableStream } from "@yume-chan/stream-extra";
import { WebCodecsVideoDecoder } from "@yume-chan/scrcpy-decoder-webcodecs";
import { bindInput, AndroidKey } from "./input.js";
import { AudioPlayer } from "./audio.js";

const SERVER_PATH = "/data/local/tmp/scrcpy-server-v3.3.3.jar";
const SERVER_URL = "js/vendor/scrcpy-server-v3.3.3.jar";

/* ---------- 画布渲染器 ---------- */
class CanvasRenderer {
  constructor(canvas) {
    this._canvas = canvas;
    this.ctx = canvas.getContext("2d", { alpha: false, desynchronized: true });
    this.width = 0;
    this.height = 0;
  }
  get canvas() {
    return this._canvas;
  }
  setSize(width, height) {
    this.width = width;
    this.height = height;
    if (this._canvas.width !== width) this._canvas.width = width;
    if (this._canvas.height !== height) this._canvas.height = height;
  }
  async draw(frame) {
    try {
      // 画布尺寸直接以真实解码帧为准：不依赖 SPS 解析结果，
      // 也就不会出现"尺寸还没解析出来就画不了"的空窗。
      if (!this.width || !this.height) {
        const w = frame.displayWidth || frame.codedWidth || 0;
        const h = frame.displayHeight || frame.codedHeight || 0;
        if (w && h) this.setSize(w, h);
      }
      if (!this.width || !this.height) return;
      this.ctx.drawImage(frame, 0, 0, this.width, this.height);
    } catch (error) {
      if (!this._drawError) {
        this._drawError = error;
        console.warn("[scrcpy] drawImage 失败", error);
      }
    } finally {
      try { frame.close(); } catch {}
    }
  }
}

/* ---------- 全局状态 ---------- */
const sessions = new Map();
const pushedDrivers = new WeakSet();
const cleanedDrivers = new WeakSet();
let sessionSeq = 0;

/* 当前活跃音频播放器（镜像会话的），供 UI 控制 */
let activeAudio = null;
let audioStateCb = null;
function emitAudioState(s) {
  if (audioStateCb) audioStateCb(s);
}
export function setAudioStateCb(cb) {
  audioStateCb = cb;
}
export function setAudioMuted(m) {
  if (activeAudio) activeAudio.setMuted(m);
}
export function setAudioVolume(v) {
  if (activeAudio) activeAudio.setVolume(v);
}
export function resumeAudio() {
  if (activeAudio) return activeAudio.resume();
  return Promise.resolve(false);
}

export function toggleAudioMuted() {
  if (!activeAudio) return true;
  // 首次点击：在用户手势内唤醒 AudioContext（绕过浏览器自动播放限制），并确保非静音
  if (!activeAudio._everResumed) {
    activeAudio._everResumed = true;
    activeAudio.resume();
    activeAudio.setMuted(false);
    return false;
  }
  const m = !activeAudio.muted;
  activeAudio.setMuted(m);
  if (!m) activeAudio.resume();
  return m;
}
export function getAudioState() {
  return activeAudio
    ? { available: true, muted: activeAudio.muted, volume: activeAudio.volume }
    : { available: false, muted: false, volume: 1 };
}

function isSupported() {
  return typeof VideoDecoder !== "undefined";
}

/* scid 必须唯一，否则多个 server 会抢同一个 abstract socket */
function nextScid() {
  sessionSeq += 1;
  const value = (Date.now() % 0x0fffffff) ^ (sessionSeq * 0x9e3779b1);
  return (value & 0x7fffffff).toString(16).padStart(8, "0");
}

let serverBytesCache = null;

async function loadServerBytes() {
  if (serverBytesCache) return serverBytesCache;
  const response = await fetch(SERVER_URL);
  if (!response.ok) throw new Error(`无法加载 scrcpy-server（HTTP ${response.status}）`);
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength < 1000) throw new Error("scrcpy-server 文件异常，可能下载失败");
  serverBytesCache = new Uint8Array(buffer);
  return serverBytesCache;
}

/** 设备上那份 jar 现在多大：-1 = 不存在，null = 读不到 */
async function remoteServerSize(adb) {
  try {
    const out = String(
      await shCmd(adb, `[ -f ${SERVER_PATH} ] && wc -c < ${SERVER_PATH} || echo MISSING`)
    ).trim();
    if (!out) return null;
    if (out.includes("MISSING")) return -1;
    const n = parseInt(out, 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/**
 * 确保设备上的 scrcpy-server 在位且完整，然后才允许启动。
 *
 * 惨痛教训（18:08 日志）：18:08:33 推好 jar、镜像正常启动；18:08:50 关掉镜像；
 * 18:08:53 再开就 `Aborted`。logcat 的原文是：
 *   W System  : ClassLoader referenced unknown path: /data/local/tmp/scrcpy-server-v3.3.3.jar
 *   E appproc : ERROR: could not find class 'com.genymobile.scrcpy.Server'
 * 也就是说 —— **设备上那个 jar 已经不见了**，app_process 连类都找不到，直接 SIGABRT。
 * 以前只看「这台设备推过一次没有」（pushedDrivers），推过就永远不再推，
 * 文件一旦消失就再也起不来，而且报错只有一行 "Aborted"，完全看不出是缺文件。
 *
 * 现在的做法：每次启动前按**字节数**核对，不存在 / 大小不符 / 读不到都重推，
 * 推完再核对一遍。88 KB 的推送不到半秒，比猜来猜去便宜得多。
 */
async function pushServer(adb, log) {
  const bytes = await loadServerBytes();
  const want = bytes.length;
  const kb = (want / 1024).toFixed(0);
  const have = await remoteServerSize(adb);

  if (have === want) {
    pushedDrivers.add(adb);
    log(`scrcpy-server 已就绪（设备上已有 ${kb} KB）`, "dim");
    return;
  }
  if (have === -1) {
    // 本页还没推过 → 就是首次连接；推过又没了 → 文件被清掉了（重开必崩的老坑）
    log(
      pushedDrivers.has(adb)
        ? `设备上的 scrcpy-server 不见了（被系统清理掉了？），重新推送（${kb} KB）…`
        : `首次连接，推送 scrcpy-server（${kb} KB）…`
    );
  } else if (have === null) {
    log(`读不到设备上的 scrcpy-server 大小，直接重推（${kb} KB）…`, "dim");
  } else {
    log(`设备上的 scrcpy-server 大小不符（设备 ${have} / 本地 ${want} 字节），重新推送…`);
  }

  const push = async () => {
    const stream = new TangoReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });
    await AdbScrcpyClient.pushServer(adb, stream, SERVER_PATH);
  };

  await push();
  let after = await remoteServerSize(adb);
  if (after !== want) {
    // 推一次不对就再推一次：sync 通道偶发截断时，这一步能救回来
    log(`推送后校验不符（设备 ${after} / 本地 ${want} 字节），再推一次…`, "dim");
    await push();
    after = await remoteServerSize(adb);
  }
  if (after === want) {
    pushedDrivers.add(adb);
    log("scrcpy-server 已就绪", "dim");
  } else {
    log(`scrcpy-server 推送后仍不对（设备 ${after} / 本地 ${want} 字节），启动大概率失败`, "err");
  }
}


/** 解析 App 的入口 Activity */
async function resolveLauncherActivity(adb, pkg) {
  const text = await adb.subprocess.noneProtocol.spawnWaitText([
    "cmd",
    "package",
    "resolve-activity",
    "--brief",
    "-c",
    "android.intent.category.LAUNCHER",
    pkg,
  ]);
  const lines = String(text)
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i].includes("/")) return lines[i];
  }
  return null;
}

/**
 * 把 App 拉到虚拟显示上。
 *
 * scrcpy 的 startApp 控制消息只是发一条普通启动命令，App 会落在主屏（display 0），
 * 虚拟显示里还是空的 —— 这就是"窗口开了但一直黑屏"。必须用 am start --display N
 * 显式指定显示，N 从服务端日志 "New display: ... (id=N)" 里取。
 */
async function launchAppOnDisplay(adb, pkg, displayId, log) {
  const component = await resolveLauncherActivity(adb, pkg);
  if (!component) {
    log(`找不到 ${pkg} 的启动入口`, "err");
    return false;
  }
  const text = await adb.subprocess.noneProtocol.spawnWaitText([
    "am",
    "start",
    "--display",
    String(displayId),
    "-n",
    component,
  ]);
  const normalized = String(text).replace(/\s+/g, " ").trim();
  if (/Error|Exception|does not exist/i.test(normalized)) {
    log(`am start 回报异常：${normalized}`, "err");
    return false;
  }
  log(`已在 display ${displayId} 上启动 ${component}`, "ok");
  return true;
}

/* 每个驱动只自动清一次，避免把正在运行的窗口一起杀掉 */
async function cleanupStale(adb, log) {
  if (cleanedDrivers.has(adb)) return;
  cleanedDrivers.add(adb);
  await pkillServer(adb, log);
}

/* 重放诊断每页只做一次，否则每开一个窗口都要多等十几秒 */
let replayDone = false;

async function forceCleanup(adb, log) {
  cleanedDrivers.delete(adb);
  await pkillServer(adb, log);
}

/* ---------- 会话 ---------- */

function buildInit({ mode, width, height, dpi, maxSize, maxFps, bitRate, scid, audio = false, log = () => {} }) {
  const isWindow = mode === "window";
  // 只传 P0 阶段实测跑通过的那几个字段。多传一个看似无害的选项，
  // 都可能让 server 在参数校验阶段直接 Aborted，而它只回一行 "Aborted"。
  const base = {
    video: true,
    audio: !!audio,
    control: true,
    maxFps,
    videoBitRate: bitRate,
    tunnelForward: true, // 浏览器没有本地 TCP 端口做反向隧道
  };
  if (!isWindow) base.maxSize = maxSize;
  if (scid) base.scid = scid;
  // DPI 要按缩放比例同步给，否则应用按原密度渲染到小画布上会挤成一条
  if (isWindow) {
    // server 对 new_display 的格式要求极严：只要出现非 "宽x高[/dpi]" 的字符，
    // 参数校验失败就只回一行 Aborted，没有任何提示。所以这里强制净化。
    const w = Math.round(Number(width)) || 0;
    const h = Math.round(Number(height)) || 0;
    const d = Math.round(Number(dpi)) || 0;
    const size = `${w}x${h}`;
    base.newDisplay = d > 0 ? `${size}/${d}` : size;
    // 展锐的硬件 H.264 编码器只有一个实例：镜像在跑时，窗口再用硬件
    // 编码器必然 Aborted（真机日志已验证）。窗口改用安卓自带的软编码器，
    // 与镜像共存。软编吃 CPU，所以窗口限 20fps / 4Mbps。
    base.videoEncoder = "c2.android.avc.encoder";
    base.maxFps = Math.min(maxFps, 20);
    base.videoBitRate = Math.min(bitRate, 4000000);
    // 把净化前后的值都打出来，dpi 到底脏在哪一步一眼可见
    log(
      `[诊断] 尺寸入参 width=${JSON.stringify(width)}(${typeof width}) height=${JSON.stringify(height)}(${typeof height}) ` +
        `dpi=${JSON.stringify(dpi)}(${typeof dpi}) → new_display=${base.newDisplay}`,
      "dim"
    );
  }
  log(
    `[诊断] 启动参数 scid=${base.scid ?? "(默认 socket)"} maxSize=${base.maxSize ?? "-"} ` +
      `maxFps=${base.maxFps} bitRate=${base.videoBitRate} 编码器=${base.videoEncoder ?? "硬件默认"}`,
    "dim"
  );
  return base;
}

function buildOptions(args) {
  return new AdbScrcpyOptions3_3_3(buildInit(args), args.spawner ? { spawner: args.spawner } : undefined);
}

function codecName(codec) {
  const map = { 0x68323634: "h264", 0x68323635: "h265", 0x61763031: "av1" };
  const num = Number(codec);
  if (map[num]) return map[num];
  const hex = Number.isFinite(num) ? "0x" + num.toString(16) : "非数字";
  return `${String(codec)}（${hex}，未识别）`;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** 启动一次（不带重试） */
async function startOnce(opts) {
  const {
    id,
    driver,
    canvas,
    mode = "mirror",
    app = null,
    width = 1024,
    height = 1024,
    dpi = 0,
    maxSize = 1280,
    maxFps = 30,
    bitRate = 8000000,
    useScid = true,
    log = () => {},
    onIssue = null,
  } = opts;

  const adb = driver.adb;
  const sessionId = id || `s${++sessionSeq}`;
  const isWindow = mode === "window";

  await pushServer(adb, log);

  // 音频：仅 Android 12+（SDK>=31）scrcpy 才支持；老设备硬开 audio 会让服务端 Aborted
  let audioEnabled = false;
  let sdk = 0;
  try {
    sdk = await getAndroidSdk(adb);
    audioEnabled = sdk >= 31;
  } catch {}
  log(
    audioEnabled
      ? `检测到 Android SDK ${sdk}，已启用音频同步`
      : `Android SDK ${sdk} < 31，暂不启用音频（老设备开音频会 Aborted）`,
    "dim"
  );

  const scid = useScid ? nextScid() : undefined;
  const capture = createOutputCapture(adb);
  const options = buildOptions({
    mode,
    width,
    height,
    dpi,
    maxSize,
    maxFps,
    bitRate,
    scid,
    audio: audioEnabled,
    spawner: capture.spawner,
    log,
  });

  log(isWindow ? `创建虚拟显示 ${width}×${height}…` : "启动 scrcpy 服务…");

  let client;
  try {
    client = await AdbScrcpyClient.start(adb, SERVER_PATH, options);
  } catch (error) {
    // 先打真实命令行，再打完整输出 —— 以前只看到 "Aborted"，是因为输出还在管道里
    log("[诊断] 实际命令：" + (capture.args || []).join(" "), "dim");
    const fromClient = Array.isArray(error?.output)
      ? error.output.map((line) => String(line).trim()).filter(Boolean)
      : [];
    // 等复制流落完再读，否则读到的还是空的
    const captured = await capture.flush();
    const fromCapture = String(captured)
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const merged = [...new Set([...fromClient, ...fromCapture])];
    if (merged.length) {
      log(`服务端输出（共 ${merged.length} 行，client ${fromClient.length} / 复制流 ${fromCapture.length}）：`, "err");
      merged.slice(-40).forEach((line) => log("  " + line, "err"));
    } else {
      log("服务端一行输出都没有就退出了（连 Device 行都没打印）", "err");
    }
    const wrapped = new Error(`scrcpy 服务端启动失败：${error?.message || error}`);
    // 启动即退出，多半是编码器被残留进程占着，值得重试
    wrapped.retryable = true;
    wrapped.scid = scid;
    wrapped.args = capture.args;
    wrapped.isWindow = isWindow;
    throw wrapped;
  }

  // 服务端 stdout 必须持续消费，否则会阻塞整条连接
  // 顺带把虚拟显示的编号抓出来：服务端会打印 "New display: 640x1024/120 (id=2)"
  let displayId = null;
  client.output
    .pipeTo(
      new WritableStream({
        write(text) {
          const line = String(text).trim();
          if (!line) return;
          const matched = line.match(/\(id=(\d+)\)/);
          if (matched && isWindow) {
            displayId = Number(matched[1]);
            log(`[诊断] 虚拟显示编号 displayId=${displayId}`, "dim");
          }
          // 服务端 DEBUG 太吵（每帧/每次 API 调用都有一堆），归到详细级别
          log(line, line.includes("DEBUG:") ? "dim" : "");
          // 小米没开「USB 调试（安全设置）」时，第一次注入就会打出这两行 ERROR。
          // 认下来并弹指引，不然用户只看到"鼠标点不动"，得自己翻日志找原因。
          if (INJECT_DENIED.test(line)) reportInjectIssue(log, onIssue, "scrcpy 服务端", line);
        },
      })
    )
    .catch(() => {});

  let videoStream;
  try {
    videoStream = await client.videoStream;
  } catch (error) {
    try { await client.close(); } catch {}
    throw new Error(`视频流建立失败：${error?.message || error}`);
  }

  if (!videoStream) {
    try { await client.close(); } catch {}
    throw new Error("设备没有返回视频流");
  }

  /* ---- 关键顺序：必须先把流接到解码器，数据才会流动 ---- */
  // videoStream.width/height 是从第一包 SPS 配置里解出来的，
  // 而 SPS 只有在这条流被消费时才会流过来。之前把"等尺寸"放在
  // "开始消费"之前，等于在等一个永远不会到的值 —— 这就是
  // "视频尺寸无效（640×1024）"这种自相矛盾报错的由来。
  const renderer = new CanvasRenderer(canvas);
  const rawCodec = videoStream.metadata?.codec;
  log(`[诊断] 视频流已就绪，codec=${String(rawCodec)}（${typeof rawCodec}），开始消费数据…`, "dim");

  const decoder = new WebCodecsVideoDecoder({ codec: rawCodec, renderer });
  videoStream.stream.pipeTo(decoder.writable).catch((error) => {
    log("解码中断：" + (error?.message || error), "err");
  });

  // 等尺寸：优先用粘性事件 sizeChanged（错过也能补），再退回渲染器的真实帧尺寸
  let vw = Number(videoStream.width) || 0;
  let vh = Number(videoStream.height) || 0;
  log(`[诊断] 消费开始时 videoStream 尺寸=${JSON.stringify(videoStream.width)}×${JSON.stringify(videoStream.height)}`, "dim");

  if (!vw || !vh) {
    const sizeResult = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), 5000);
      const done = (size) => {
        clearTimeout(timer);
        resolve(size);
      };
      try {
        videoStream.sizeChanged((size) => {
          log(`[诊断] sizeChanged 事件：${size?.width}×${size?.height}`, "dim");
          done(size);
        });
      } catch (error) {
        log("[诊断] 订阅 sizeChanged 失败：" + (error?.message || error), "err");
      }
      if (videoStream.width && videoStream.height) {
        done({ width: videoStream.width, height: videoStream.height });
      }
    });
    if (sizeResult) {
      vw = Number(sizeResult.width) || 0;
      vh = Number(sizeResult.height) || 0;
    }
  }

  // 渲染器已经拿到真实解码帧时，以它为准（SPS 解析失败也不影响出画面）
  if (renderer.width && renderer.height) {
    vw = renderer.width;
    vh = renderer.height;
  }

  if (!vw || !vh) {
    log(
      `[诊断] 5 秒内没有拿到有效尺寸 → videoStream=${JSON.stringify(videoStream.width)}×${JSON.stringify(videoStream.height)}，` +
        `renderer=${renderer.width}×${renderer.height}，已渲染 ${decoder?.framesRendered ?? 0} 帧，codec=${String(rawCodec)}`,
      "err"
    );
    // 抛错前先关掉，否则它的 server 进程会一直占着编码器，
    // 紧接着的重试必然 Aborted。
    try { await client.close(); } catch {}
    const error = new Error("视频流 5 秒内没有输出有效画面（详见上方诊断行）");
    error.retryable = true;
    throw error;
  }

  renderer.setSize(vw, vh);
  if (canvas) {
    log(`[诊断] 画布 element ${canvas.width}×${canvas.height}，videoStream metadata=${JSON.stringify(rawCodec)}`, "dim");
  }
  log(`视频流已建立：${vw}×${vh}，编码 ${codecName(rawCodec)}`);

  // 一秒后回看一眼真实渲染情况，专治"有画面但用户说黑屏"
  setTimeout(() => {
    log(
      `[诊断] 1 秒后：画布 ${renderer.width}×${renderer.height}，已渲染 ${decoder?.framesRendered ?? 0} 帧，` +
        `跳过 ${decoder?.framesSkipped ?? 0} 帧`,
      "dim"
    );
  }, 1000);

  const session = {
    id: sessionId,
    scid,
    mode,
    app,
    driver,
    client,
    canvas,
    decoder,
    renderer,
    videoStream,
    input: null,
    _startedAt: performance.now(),
    async startApp(pkg) {
      if (!client.controller) throw new Error("控制通道未就绪");
      await client.controller.startApp(pkg);
      this.app = pkg;
    },
    key(code) {
      this.input?.key(code);
    },
    async stop() {
      try { this.input?.dispose(); } catch {}
      this.input = null;
      if (this.audio) {
        if (activeAudio === this.audio) activeAudio = null;
        try { this.audio.stop(); } catch {}
        this.audio = null;
      }
      try { this.decoder?.dispose?.(); } catch {}
      this.decoder = null;
      this.renderer = null;
      this.videoStream = null;
      try { await client.close(); } catch {}
      // 顺手把设备端这条 server 进程也杀了：client.close() 只关连接，
      // 进程可能还在退出中、仍占着编码器；下次重开前等它真正没了再启动。
      try { await killServerByScid(adb, this.scid, log); } catch {}
      // 库自己的 dispose 对反向转发是「发射后不管、不 await、失败就吞掉」，
      // 残留的旧转发会抢住 tcp 端口让下次重开 Aborted。这里显式再撤一次
      // （非阻塞，失败无所谓——下次 startSession 启动前还会整体扫一遍清掉）。
      try {
        adb.reverse
          .remove(`localabstract:scrcpy_${String(this.scid).padStart(8, "0")}`)
          .catch(() => {});
      } catch {}
      sessions.delete(this.id);
    },
    stats() {
      const elapsed = this._startedAt ? (performance.now() - this._startedAt) / 1000 : 0;
      return {
        fps: elapsed > 0 ? +(this.decoder?.framesRendered ?? 0) / elapsed : 0,
        rendered: this.decoder?.framesRendered ?? 0,
        skipped: this.decoder?.framesSkipped ?? 0,
        width: this.renderer?.width ?? 0,
        height: this.renderer?.height ?? 0,
      };
    },
  };

  sessions.set(sessionId, session);

  /* ---- 音频：Android 12+ 时把 scrcpy 音频流接去播放 ---- */
  if (audioEnabled) {
    try {
      const audio = await client.audioStream;
      if (audio && audio.type === "success") {
        const player = new AudioPlayer({ onState: (s) => emitAudioState(s), log: (m, lv) => log("[音频] " + m, lv || "dim") });
        player.start(audio.codec, audio.stream).catch((e) => log("音频启动失败：" + (e?.message || e), "err"));
        session.audio = player;
        activeAudio = player;
        emitAudioState({ available: true, muted: player.muted, volume: player.volume });
        log("音频流已开启", "ok");
      } else if (audio) {
        log("设备未提供音频流（" + audio.type + "）", "dim");
      }
    } catch (e) {
      log("音频不可用：" + (e?.message || e), "err");
    }
  }

  session.input = bindInput({
    canvas,
    log,
    // 用渲染器的真实帧尺寸做坐标基准，SPS 解析失败也不影响点击
    getSize: () => ({ width: renderer.width || vw, height: renderer.height || vh }),
    getController: () => client.controller,
  });

  // 窗口模式：把目标 App 拉进这块虚拟显示
  if (isWindow && app) {
    await new Promise((resolve) => setTimeout(resolve, 400));
    let launched = false;
    if (displayId != null) {
      try {
        launched = await launchAppOnDisplay(adb, app, displayId, log);
      } catch (error) {
        log(`在虚拟显示里启动 ${app} 失败：${error?.message || error}`, "err");
      }
    } else {
      log("[诊断] 没抓到 displayId，退回控制通道启动（可能落在主屏）", "err");
    }
    if (!launched) {
      try {
        await client.controller.startApp(app);
        log(`已用控制通道启动 ${app}（若画面仍黑，说明它落在主屏上了）`, "dim");
      } catch (error) {
        log(`启动 ${app} 失败：${error?.message || error}（画面里是空桌面，可手动点图标）`, "err");
      }
    }
  }

  return {
    id: sessionId,
    width: vw,
    height: vh,
    codec: codecName(rawCodec),
    session,
  };
}

/**
 * 启动一个投屏会话（含一次自动重试）。
 */
async function startSession(opts) {
  const { driver, log = () => {}, onIssue = null } = opts;
  if (!driver?.adb) throw new Error("设备未连接");
  if (!isSupported()) throw new Error("当前浏览器不支持 WebCodecs，请使用 Chrome / Edge 94 以上版本");

  const adb = driver.adb;
  // 每次新会话只弹一次指引；断开重连会重置，万一用户在手机上刚开完开关，
  // 重新连上就该重新判一次。（标记在 device.js 里，只能通过函数重置）
  resetInjectIssue();

  // 熄屏是这台机器起不来的头号原因（同一行命令，亮屏能起、熄屏立刻 Aborted）。
  // 直接发一次点亮命令就够了，别在这里读 dumpsys power（首次 20 多秒）。
  await sendWakeup(adb, log, onIssue);

  // 没有任何会话在跑时，先把设备端可能残留的 server 清掉。
  // 否则上一次失败留下的进程还占着硬件编码器，新的必然 Aborted。
  // 有会话在跑时绝不清场，否则会把正在用的窗口一起杀掉。
  log(`[诊断] 当前活动会话 ${sessions.size} 个`, "dim");
  if (sessions.size === 0) {
    // 先看看启动前到底有没有旧 server 赖着（重开镜像时通常有 1 个）
    const stale = await countScrcpyProcs(adb, null);
    if (stale > 0) log(`[诊断] 启动前发现 ${stale} 个旧 scrcpy 进程，先清掉再启动`, "dim");
    await forceCleanup(adb, log);
    // 等旧进程真正退出再启动：展锐只有一路编码器，没退干净就开新的会直接 Aborted。
    await waitForServerGone(adb, log, 6000);
    // 确实清掉过旧 server 时，编码器要被内核/媒体服务释放需要一点时间，
    // 立刻抢占仍可能 Aborted，这里补一小段等待。
    if (stale > 0) {
      log("[诊断] 等硬件编码器释放…", "dim");
      await sleep(600);
    }
  }

  // 只有「没有别的会话在跑」时才清反向转发，避免把正在用的窗口/镜像转发一起干掉。
  // 这是「关掉再开必 Aborted」的核心修复：库的 dispose 不保证撤转发，残留的旧
  // scid 转发会抢住同一个 tcp 端口，让新 server 连到一条已死的 socket。
  const alone = sessions.size === 0;
  const attempt = async (extra) => {
    if (alone) await clearScrcpyReverse(adb, log);
    return startOnce(extra);
  };

  // 第 1 次：正常启动
  try {
    return await attempt({ ...opts, useScid: true });
  } catch (first) {
    if (!first?.retryable) throw first;
    log("启动异常：" + (first?.message || first), "err");
    // 先重放：客户端那条管道会丢输出，重放能拿回完整 stderr + 退出码。
    // 主屏和窗口都做 —— 上次熄屏后主屏起不来，恰恰因为只有窗口才重放，
    // 结果日志里只剩一行 Aborted，什么结论都拿不到。
    if (!replayDone) {
      replayDone = true;
      await replayServerCommand(adb, first.args, log);
    }
    // 稍等一下：刚失败的那个子进程 socket 还在关，立刻跑诊断命令容易全拿到空输出
    await sleep(250);
    await dumpCrashLog(adb, log);
    // 只杀这次失败的那一个进程。以前是无差别 pkill，会把正在跑的镜像
    // 和别的窗口一起干掉 —— 开窗失败一次，主屏画面也跟着没了。
    await killServerByScid(adb, first.scid, log);
    // 重试前再叫醒一次：熄屏导致的失败，这一步就能救回来
    await sendWakeup(adb, log, onIssue);
    // 等这次失败进程彻底退出后重试：上一条没退干净是重开 Aborted 的头号原因
    await waitForServerGone(adb, log, 4000);
    // 编码器（尤其展锐这一路硬件编码器）释放需要一点时间
    await sleep(500);
    log("清理本次失败进程后重试…", "dim");
  }

  // 第 2 次：清掉本次失败进程后重试
  await sleep(700);
  try {
    return await attempt({ ...opts, useScid: true });
  } catch (second) {
    if (!second?.retryable) throw second;
    log("仍然失败：" + (second?.message || second), "dim");
    await killServerByScid(adb, second.scid, log);
    await waitForServerGone(adb, log, 3000);
    await sleep(500);
    log("改用默认 socket 名再试一次…", "dim");
  }

  // 第 3 次：不带 scid（排除 socket 隔离导致的兼容问题）
  await sleep(500);
  return attempt({ ...opts, useScid: false });
}

/** 兼容旧接口：单路镜像 */
async function start({ driver, canvas, maxSize = 1280, maxFps = 30, bitRate = 8000000, log = () => {}, onIssue = null }) {
  return startSession({ driver, canvas, mode: "mirror", maxSize, maxFps, bitRate, log, onIssue });
}

async function stop(id) {
  if (id) {
    const session = sessions.get(id);
    if (session) await session.stop();
    return;
  }
  const list = [...sessions.values()];
  sessions.clear();
  await Promise.all(list.map((s) => s.stop().catch(() => {})));
}

function getSession(id) {
  return sessions.get(id) || null;
}

function stats(id) {
  if (id) return sessions.get(id)?.stats() ?? null;
  const first = [...sessions.values()][0];
  return first ? first.stats() : { fps: 0, rendered: 0, skipped: 0, width: 0, height: 0 };
}

/** 列出可直接启动的第三方应用 */
async function listApps(driver) {
  if (!driver?.adb) throw new Error("设备未连接");
  const text = await driver.adb.subprocess.noneProtocol.spawnWaitText(["pm", "list", "packages", "-3"]);
  return String(text)
    .split("\n")
    .map((line) => line.trim().replace(/^package:/, ""))
    .filter((pkg) => pkg && pkg.includes("."))
    .sort()
    .map((pkg) => {
      const parts = pkg.split(".");
      return { pkg, short: parts[parts.length - 1], label: parts[parts.length - 1] };
    });
}

/** 屏幕快照 */
async function snapshot(id) {
  const session = id ? sessions.get(id) : [...sessions.values()][0];
  return session?.decoder?.snapshot?.() ?? null;
}

/** 系统级按键 */
async function systemKey(id, name) {
  const session = id ? sessions.get(id) : [...sessions.values()][0];
  if (!session) return;
  // 手动松手：设备端如果卡在"按下"，点这个清一次
  if (name === "release") {
    session.input?.cancelTouch?.("手动");
    return;
  }
  const map = {
    back: AndroidKey.BACK,
    home: AndroidKey.HOME,
    recents: AndroidKey.APP_SWITCH,
    power: AndroidKey.POWER,
    volup: AndroidKey.VOLUME_UP,
    voldown: AndroidKey.VOLUME_DOWN,
  };
  const code = map[name];
  if (code !== undefined) session.input?.key(code);
}

/** 手动清场：断开前调用，保证设备端不留进程 */
async function cleanup(driver) {
  if (!driver?.adb) return;
  await pkillServer(driver.adb, () => {});
  cleanedDrivers.delete(driver.adb);
}

/**
 * 打开/关闭平板的"显示触摸位置"。
 * 调试阶段特别有用：平板上会直接画出触摸落点，一眼看出坐标有没有偏，
 * 不用再靠"点了没反应"去反推。
 */
async function setShowTouches(driver, on) {
  if (!driver?.adb) return false;
  try {
    await driver.adb.subprocess.noneProtocol.spawnWaitText([
      "settings",
      "put",
      "system",
      "show_touches",
      on ? "1" : "0",
    ]);
    return true;
  } catch {
    return false;
  }
}

const BUILD = "1.1.0";

const ReLive = {
  BUILD,
  isSupported,
  start,
  startSession,
  stop,
  getSession,
  stats,
  listApps,
  snapshot,
  systemKey,
  cleanup,
  setShowTouches,
  getPowerState,
  sendWakeup,
  wakeScreen,
  keepAwake,
  checkInputPermission,
  sessions,
  SERVER_PATH,
  setAudioStateCb,
  setAudioMuted,
  setAudioVolume,
  resumeAudio,
  toggleAudioMuted,
  getAudioState,
};

export { ReLive };
export default ReLive;
