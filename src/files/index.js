/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

设备文件管理：浏览器 ↔ 平板 双向传文件。

用的是 ADB 自带的 sync 协议（不是 adb push 命令），所以：
 - 大文件有进度、可中断
 - 不需要在设备上安装任何东西
 - 文件名带空格、中文都不会出错

对外只暴露一个 mountFilePanel()，UI 自包含，页面里放一个空 div 就行。
*/

const TYPE_DIR = 4;
const TYPE_FILE = 8;
const TYPE_LINK = 10;

/* ---------- 路径工具 ---------- */

/** 规整成 POSIX 绝对路径，去掉多余的 / 和 .. */
export function normalizePath(input) {
  const parts = String(input || "/")
    .split("/")
    .filter((part) => part && part !== ".");
  const stack = [];
  for (const part of parts) {
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  return "/" + stack.join("/");
}

export function joinPath(base, name) {
  return normalizePath(base.replace(/\/+$/, "") + "/" + name);
}

export function parentPath(path) {
  const clean = normalizePath(path);
  if (clean === "/") return "/";
  const at = clean.lastIndexOf("/");
  return at <= 0 ? "/" : clean.slice(0, at);
}

/**
 * 包成 shell 单引号参数。
 * 平时传路径给 rm / mv 用，文件名里什么字符都可能有（空格、引号、$、中文），
 * 直接拼字符串迟早出事，所以统一走这里。
 */
export function shQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

export function formatSize(bytes) {
  const size = Number(bytes) || 0;
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = size / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export function formatTime(mtime) {
  const seconds = Number(mtime);
  if (!seconds) return "";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  const now = new Date();
  const sameYear = date.getFullYear() === now.getFullYear();
  const md = `${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  const hm = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  return sameYear ? `${md} ${hm}` : `${date.getFullYear()}-${md}`;
}

/** 按文件夹优先 + 名称排序，中文按拼音（localeCompare 交给浏览器） */
export function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    const aDir = a.type === TYPE_DIR;
    const bDir = b.type === TYPE_DIR;
    if (aDir !== bDir) return aDir ? -1 : 1;
    return String(a.name).localeCompare(String(b.name), "zh-Hans-CN", { numeric: true });
  });
}

/* ---------- 文件类型 ---------- */

const IMAGE_RE = /\.(png|jpe?g|gif|webp|bmp|avif|svg)$/i;
const VIDEO_RE = /\.(mp4|m4v|webm|mkv|mov|3gp|ts|avi)$/i;
const AUDIO_RE = /\.(mp3|m4a|aac|wav|flac|ogg|opus|amr|wma)$/i;
const PDF_RE = /\.pdf$/i;
const TEXT_RE = /\.(txt|log|md|markdown|json|xml|csv|tsv|ini|conf|cfg|properties|js|mjs|ts|css|html|htm|java|kt|c|h|cpp|hpp|py|sh|bat|yml|yaml|srt|ass|lrc)$/i;

const MIME = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  avif: "image/avif",
  svg: "image/svg+xml",
  mp4: "video/mp4",
  m4v: "video/mp4",
  webm: "video/webm",
  mkv: "video/x-matroska",
  mov: "video/quicktime",
  "3gp": "video/3gpp",
  ts: "video/mp2t",
  avi: "video/x-msvideo",
  mp3: "audio/mpeg",
  m4a: "audio/mp4",
  aac: "audio/aac",
  wav: "audio/wav",
  flac: "audio/flac",
  ogg: "audio/ogg",
  opus: "audio/ogg",
  amr: "audio/amr",
  wma: "audio/x-ms-wma",
  pdf: "application/pdf",
};

export function mimeOf(name) {
  const ext = String(name).split(".").pop().toLowerCase();
  return MIME[ext] || "application/octet-stream";
}

/** 决定用哪种方式打开：image / video / audio / text / pdf / other（other 只能下载） */
export function kindOf(name) {
  const text = String(name);
  if (IMAGE_RE.test(text)) return "image";
  if (VIDEO_RE.test(text)) return "video";
  if (AUDIO_RE.test(text)) return "audio";
  if (PDF_RE.test(text)) return "pdf";
  if (TEXT_RE.test(text)) return "text";
  return "other";
}

/**
 * 用小色块 + 文字标类型，不用 emoji：
 * 部分 Windows/Chromium 组合缺彩色 emoji 字形，会渲染成白方块（实测过）。
 * 这里只输出固定字符串，不含文件名，用 innerHTML 是安全的。
 */
function iconFor(entry) {
  const badge = (label, cls) => `<span class="fp-ico ${cls}">${label}</span>`;
  if (entry.type === TYPE_DIR) return badge("夹", "i-dir");
  if (entry.type === TYPE_LINK) return badge("链", "i-link");
  const kind = kindOf(entry.name);
  if (kind === "image") return badge("图", "i-image");
  if (kind === "video") return badge("视", "i-video");
  if (kind === "audio") return badge("音", "i-audio");
  if (kind === "pdf") return badge("PDF", "i-pdf");
  if (kind === "text") return badge("文", "i-text");
  const name = String(entry.name).toLowerCase();
  if (/\.(epub|mobi|azw3)$/.test(name)) return badge("书", "i-book");
  if (/\.(apk|xapk|apks)$/.test(name)) return badge("包", "i-apk");
  if (/\.(zip|rar|7z|tar|gz)$/.test(name)) return badge("压", "i-zip");
  return badge("件", "i-other");
}

/* ---------- 数据操作 ---------- */

async function listDir(driver, path) {
  return driver.withSync(async (sync) => {
    const entries = await sync.readdir(path);
    return entries
      // "." 和 ".." 这两条 android sync 有时会带出来，列表里不需要
      .filter((entry) => entry.name !== "." && entry.name !== "..")
      .map((entry) => ({
        name: entry.name,
        type: entry.type,
        size: Number(entry.size),
        mtime: Number(entry.mtime),
      }));
  });
}

async function shell(driver, command) {
  const result = await driver.exec(command);
  if (result.exitCode !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    throw new Error(detail || `命令失败（退出码 ${result.exitCode}）`);
  }
  return result.stdout;
}

/* ---------- UI ---------- */

const SHORTCUTS = [
  { label: "内部存储", path: "/sdcard" },
  { label: "下载", path: "/sdcard/Download" },
  { label: "文档", path: "/sdcard/Documents" },
  { label: "图片", path: "/sdcard/DCIM" },
  { label: "根目录", path: "/" },
];

export function mountFilePanel({ container, getDriver, log = () => {}, onClose = () => {} }) {
  const state = {
    path: "/sdcard",
    entries: [],
    selected: null,
    busy: false,
    filter: "",
  };

  container.innerHTML = `
    <div class="fp-bar">
      <button class="fp-btn" data-act="up" title="上一级">↑</button>
      <button class="fp-btn" data-act="home" title="回到内部存储">⌂</button>
      <div class="fp-path" id="fpPath" title="点击可手输路径">/sdcard</div>
      <input class="fp-filter" id="fpFilter" placeholder="筛选当前目录…">
      <button class="fp-btn" data-act="mkdir">新建文件夹</button>
      <button class="fp-btn primary" data-act="upload">上传</button>
      <button class="fp-btn" data-act="refresh">刷新</button>
      <button class="fp-btn" data-act="close" title="关闭">✕</button>
    </div>
    <div class="fp-chips">
      ${SHORTCUTS.map((item) => `<button class="fp-chip" data-path="${item.path}">${item.label}</button>`).join("")}
    </div>
    <div class="fp-head-row">
      <span class="fp-col-name">名称</span>
      <span class="fp-col-size">大小</span>
      <span class="fp-col-time">修改时间</span>
      <span class="fp-col-ops"></span>
    </div>
    <div class="fp-list" id="fpList"></div>
    <div class="fp-status" id="fpStatus">连接设备后即可浏览</div>
    <input type="file" id="fpFileInput" multiple hidden>
  `;

  const $ = (id) => container.querySelector("#" + id);
  const listEl = $("fpList");
  const statusEl = $("fpStatus");
  const pathEl = $("fpPath");
  const filterEl = $("fpFilter");
  const fileInput = $("fpFileInput");

  const setStatus = (text, kind = "") => {
    statusEl.textContent = text;
    statusEl.className = "fp-status" + (kind ? " " + kind : "");
  };

  /* ---------- 在线预览 ---------- *
   * 图片直接画，视频/音频用浏览器自带播放器，文本按纯文本、PDF 用内嵌框。
   * 数据仍然走同一条 ADB sync 通道整份读进内存（浏览器没法解设备端的流），
   * 所以超大文件先问一句，别让人对着进度条干等。
   */
  const BIG_FILE = 300 * 1024 * 1024;
  const TEXT_LIMIT = 8 * 1024 * 1024;

  const pv = document.createElement("div");
  pv.className = "pv";
  pv.innerHTML = `
    <div class="pv-bar">
      <span class="pv-name" id="pvName"></span>
      <span class="pv-meta" id="pvMeta"></span>
      <span class="pv-nav" id="pvNav">
        <button class="fp-btn" data-pv="prev" title="上一个（←）">‹</button>
        <span class="pv-idx" id="pvIdx"></span>
        <button class="fp-btn" data-pv="next" title="下一个（→）">›</button>
      </span>
      <button class="fp-btn" data-pv="full" id="pvFull" title="全屏查看（F 或双击画面）">⛶ 全屏</button>
      <button class="fp-btn" data-pv="download" title="存到电脑">下载</button>
      <button class="fp-btn" data-pv="close" title="关闭（Esc）">✕</button>
    </div>
    <div class="pv-body" id="pvBody"></div>
    <div class="pv-status" id="pvStatus"></div>
  `;
  container.appendChild(pv);

  const pvName = pv.querySelector("#pvName");
  const pvMeta = pv.querySelector("#pvMeta");
  const pvIdx = pv.querySelector("#pvIdx");
  const pvNav = pv.querySelector("#pvNav");
  const pvBody = pv.querySelector("#pvBody");
  const pvStatus = pv.querySelector("#pvStatus");
  const pvFull = pv.querySelector("#pvFull");

  // token：每次换文件都自增，读得慢的旧请求回来时直接作废，避免串台
  const viewer = { open: false, items: [], index: 0, url: null, token: 0, max: false };

  const setPvStatus = (text, kind = "") => {
    pvStatus.textContent = text || "";
    pvStatus.className = "pv-status" + (kind ? " " + kind : "");
  };

  /**
   * 全屏：先把预览层撑满整个浏览器窗口，再尽量进浏览器真全屏。
   * 真全屏被拒（iframe / 权限）也不影响，至少最大化已经生效。
   */
  let pvHome = null;
  let pvSlot = null;
  async function setFullscreen(on) {
    viewer.max = on;
    pv.classList.toggle("max", on);
    pvFull.textContent = on ? "还原" : "全屏";
    pvFull.title = on ? "还原到文件面板（F / Esc）" : "全屏查看（F 或双击画面）";
    if (on) {
      // 桌面化之后预览层被关在窗口里，窗口有 z-index 会形成层叠上下文，
      // fixed 的 .pv.max 再高也盖不过任务栏。全屏时临时挂到页面根部，
      // 还原时按占位符放回原处，事件监听和面板状态都不受影响。
      if (!pvHome) {
        pvHome = pv.parentNode;
        pvSlot = document.createComment("pv-slot");
        pvHome.insertBefore(pvSlot, pv);
        document.body.appendChild(pv);
      }
      try {
        await pv.requestFullscreen?.();
      } catch {
        /* 浏览器不给全屏就保持最大化，功能照样能用 */
      }
    } else {
      if (pvHome && pvSlot) {
        pvHome.insertBefore(pv, pvSlot);
        pvSlot.remove();
        pvHome = null;
        pvSlot = null;
      }
      if (document.fullscreenElement === pv) {
        try {
          await document.exitFullscreen();
        } catch {}
      }
    }
  }
  const toggleFullscreen = () => setFullscreen(!viewer.max);

  // 浏览器按 Esc 退出真全屏时，把"最大化"状态也同步还原，别留半吊子
  document.addEventListener("fullscreenchange", () => {
    if (document.fullscreenElement !== pv && viewer.max && viewer.open) setFullscreen(false);
  });

  function releaseMedia() {
    if (viewer.url) {
      URL.revokeObjectURL(viewer.url);
      viewer.url = null;
    }
    // 正在播的音视频必须显式停掉，否则关了窗口还在后台响
    pvBody.querySelectorAll("video,audio").forEach((el) => {
      try {
        el.pause();
        el.removeAttribute("src");
        el.load?.();
      } catch {}
    });
    pvBody.textContent = "";
  }

  function closeViewer() {
    viewer.open = false;
    viewer.token += 1;
    if (viewer.max) setFullscreen(false);
    releaseMedia();
    pv.classList.remove("on");
  }

  function updateNav() {
    const total = viewer.items.length;
    pvNav.style.display = total > 1 ? "" : "none";
    pvIdx.textContent = total > 1 ? `${viewer.index + 1} / ${total}` : "";
  }

  /** 文本解码：先按 UTF-8，出现大量替换字符说明是老 GBK 文件，再换 GBK 试一次 */
  async function renderText(blob) {
    const slice = blob.size > TEXT_LIMIT ? blob.slice(0, TEXT_LIMIT) : blob;
    const buffer = await slice.arrayBuffer();
    const utf8 = new TextDecoder("utf-8").decode(buffer);
    const bad = (text) => (text.match(/\uFFFD/g) || []).length;
    let text = utf8;
    let encoding = "UTF-8";
    if (bad(utf8) > 3) {
      try {
        const gbk = new TextDecoder("gbk").decode(buffer);
        if (bad(gbk) < bad(utf8)) {
          text = gbk;
          encoding = "GBK";
        }
      } catch {
        /* 浏览器不支持 gbk 就保持 UTF-8 */
      }
    }
    const pre = document.createElement("pre");
    pre.textContent = text;
    pvBody.appendChild(pre);
    setPvStatus(
      blob.size > TEXT_LIMIT
        ? `${encoding} · 只显示前 ${formatSize(TEXT_LIMIT)}（文件共 ${formatSize(blob.size)}）`
        : `${encoding} · ${formatSize(blob.size)}`
    );
  }

  async function showItem(entry) {
    const driver = getDriver();
    if (!driver || !entry) return;
    const kind = kindOf(entry.name);
    const token = ++viewer.token;

    pvName.textContent = entry.name;
    pvMeta.textContent = `${formatSize(entry.size)} · ${formatTime(entry.mtime) || "—"}`;
    releaseMedia();
    setPvStatus("读取中… 0%");

    let blob;
    try {
      blob = await driver.read(joinPath(state.path, entry.name), {
        onProgress: (done, total) => {
          if (token !== viewer.token) return;
          const percent = total ? Math.round((done / total) * 100) : 0;
          setPvStatus(`读取中… ${percent}%（${formatSize(done)}${total ? " / " + formatSize(total) : ""}）`);
        },
      });
    } catch (error) {
      if (token === viewer.token) setPvStatus("读取失败：" + (error?.message || error), "err");
      return;
    }
    if (token !== viewer.token) return;

    if (kind === "text") {
      await renderText(blob);
      log(`[文件] 预览 ${entry.name}`, "dim");
      return;
    }

    // read() 给回来的 MIME 只认 png/apk，这里按扩展名重新贴一次
    const url = URL.createObjectURL(new Blob([blob], { type: mimeOf(entry.name) }));
    viewer.url = url;

    if (kind === "pdf") {
      const frame = document.createElement("iframe");
      frame.className = "pv-frame";
      frame.src = url;
      pvBody.appendChild(frame);
      setPvStatus(`PDF · ${formatSize(blob.size)}（浏览器内置阅读器，翻页在框内操作）`);
      log(`[文件] 预览 ${entry.name}`, "dim");
      return;
    }

    const media = document.createElement(kind === "image" ? "img" : kind === "video" ? "video" : "audio");
    if (kind === "image") {
      media.alt = entry.name;
      media.addEventListener("load", () => setPvStatus(`${media.naturalWidth}×${media.naturalHeight} · ${formatSize(blob.size)}`));
      media.addEventListener("error", () => setPvStatus("图片解码失败（可能不是真正的图片文件）", "err"));
      media.src = url;
    } else {
      media.controls = true;
      media.autoplay = true;
      media.playsInline = true;
      media.addEventListener("loadedmetadata", () => {
        const total = Number.isFinite(media.duration) ? media.duration : 0;
        const mm = String(Math.floor(total / 60)).padStart(2, "0");
        const ss = String(Math.floor(total % 60)).padStart(2, "0");
        setPvStatus(`${total ? `时长 ${mm}:${ss}` : "时长未知"} · ${formatSize(blob.size)}`);
      });
      media.addEventListener("error", () => {
        // mkv / avi 这类浏览器多半解不了，直接给条明路，不要只留一个黑框
        setPvStatus("浏览器解不了这个格式，点右上「下载」用本地播放器看", "err");
      });
      media.src = url;
      media.play?.().catch(() => {
        /* 自动播放被拦是正常的，点播放键即可 */
      });
    }
    pvBody.appendChild(media);
    log(`[文件] 预览 ${entry.name}`, "dim");
  }

  /** 打开预览：把当前目录里同类文件做成一组，左右键可以直接翻 */
  function openViewer(entry) {
    const kind = kindOf(entry.name);
    if (kind === "other") {
      downloadEntry(entry);
      return;
    }
    if (entry.size > BIG_FILE) {
      const go = window.confirm(
        `「${entry.name}」有 ${formatSize(entry.size)}，\n要在浏览器里打开必须先整份读到内存，会等较久。\n\n确定打开吗？（选取消可以点 ↓ 直接下载到电脑）`
      );
      if (!go) return;
    }
    viewer.items = state.entries.filter((item) => item.type !== TYPE_DIR && kindOf(item.name) === kind);
    viewer.index = Math.max(0, viewer.items.findIndex((item) => item.name === entry.name));
    viewer.open = true;
    pv.classList.add("on");
    updateNav();
    showItem(viewer.items[viewer.index] || entry);
  }

  async function stepViewer(delta) {
    const total = viewer.items.length;
    if (total < 2) return;
    viewer.index = (viewer.index + delta + total) % total;
    updateNav();
    await showItem(viewer.items[viewer.index]);
  }

  function render() {
    const keyword = state.filter.trim().toLowerCase();
    const visible = keyword
      ? state.entries.filter((entry) => entry.name.toLowerCase().includes(keyword))
      : state.entries;

    listEl.textContent = "";
    if (!visible.length) {
      const empty = document.createElement("div");
      empty.className = "fp-empty";
      empty.textContent = keyword ? "没有匹配的项目" : "这个目录是空的";
      listEl.appendChild(empty);
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const entry of visible) {
      const row = document.createElement("div");
      row.className = "fp-row" + (state.selected === entry.name ? " on" : "");
      row.dataset.name = entry.name;
      row.dataset.type = String(entry.type);
      row.innerHTML = `
        <span class="fp-col-name">${iconFor(entry)}<span class="fp-txt"></span></span>
        <span class="fp-col-size">${entry.type === TYPE_DIR ? "—" : formatSize(entry.size)}</span>
        <span class="fp-col-time">${formatTime(entry.mtime)}</span>
        <span class="fp-col-ops">
          ${entry.type !== TYPE_DIR && kindOf(entry.name) !== "other" ? '<button class="fp-op" data-op="preview" title="在线打开">👁</button>' : ""}
          ${entry.type !== TYPE_DIR ? '<button class="fp-op" data-op="download" title="下载到电脑">↓</button>' : ""}
          <button class="fp-op" data-op="rename" title="重命名">✎</button>
          <button class="fp-op danger" data-op="delete" title="删除">🗑</button>
        </span>
      `;
      // 文件名一律走 textContent，避免 "&" "<" 这类字符被当成 HTML
      row.querySelector(".fp-txt").textContent = entry.name;
      fragment.appendChild(row);
    }
    listEl.appendChild(fragment);
  }

  function updatePath() {
    pathEl.textContent = state.path;
    filterEl.value = "";
    state.filter = "";
  }

  async function load(path, { quiet = false } = {}) {
    const driver = getDriver();
    if (!driver) {
      setStatus("设备未连接", "err");
      return;
    }
    const target = normalizePath(path);
    if (viewer.open) closeViewer();
    if (!quiet) setStatus("正在读取 " + target + " …");
    try {
      const entries = await listDir(driver, target);
      // 目录读成功才切换当前路径，读失败时停在原地，方便重试
      state.path = target;
      state.entries = sortEntries(entries);
      state.selected = null;
      updatePath();
      render();
      const dirs = state.entries.filter((entry) => entry.type === TYPE_DIR).length;
      setStatus(`${state.entries.length} 项（${dirs} 个文件夹）`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus("读取失败：" + message, "err");
      log(`[文件] 读取 ${target} 失败：${message}`, "err");
    }
  }

  /* 上传：多个文件依次写，每个文件单独算进度 */
  async function uploadFiles(files) {
    const driver = getDriver();
    if (!driver || !files?.length) return;
    if (state.busy) {
      setStatus("上一个操作还没结束", "err");
      return;
    }
    state.busy = true;
    let okCount = 0;
    try {
      for (let i = 0; i < files.length; i += 1) {
        const file = files[i];
        const target = joinPath(state.path, file.name);
        const label = files.length > 1 ? `(${i + 1}/${files.length}) ` : "";
        setStatus(`${label}上传 ${file.name} … 0%`);
        try {
          await driver.write(file, target, {
            onProgress: (done, total) => {
              const percent = total ? Math.round((done / total) * 100) : 0;
              setStatus(`${label}上传 ${file.name} … ${percent}%（${formatSize(done)} / ${formatSize(total)}）`);
            },
          });
          okCount += 1;
          log(`[文件] 已上传 ${file.name}（${formatSize(file.size)}）`, "ok");
        } catch (error) {
          const message = error?.message || String(error);
          setStatus(`上传 ${file.name} 失败：${message}`, "err");
          log(`[文件] 上传 ${file.name} 失败：${message}`, "err");
        }
      }
    } finally {
      state.busy = false;
    }
    await load(state.path, { quiet: true });
    setStatus(`上传完成：成功 ${okCount} / 共 ${files.length} 个`);
  }

  async function downloadEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const target = joinPath(state.path, entry.name);
    setStatus(`下载 ${entry.name} … 0%`);
    try {
      const blob = await driver.read(target, {
        onProgress: (done, total) => {
          const percent = total ? Math.round((done / total) * 100) : 0;
          setStatus(`下载 ${entry.name} … ${percent}%（${formatSize(done)}${total ? " / " + formatSize(total) : ""}）`);
        },
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = entry.name;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      // 立刻 revoke 会让部分浏览器的下载中断，给它一点时间
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      setStatus(`已下载 ${entry.name}（${formatSize(blob.size)}）`);
      log(`[文件] 已下载 ${entry.name}（${formatSize(blob.size)}）`, "ok");
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`下载 ${entry.name} 失败：${message}`, "err");
      log(`[文件] 下载 ${entry.name} 失败：${message}`, "err");
    }
  }

  async function removeEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const target = joinPath(state.path, entry.name);
    const what = entry.type === TYPE_DIR ? "文件夹" : "文件";
    // 删文件夹会连里面一起删，必须说清楚
    const hint =
      entry.type === TYPE_DIR
        ? `确定删除文件夹「${entry.name}」吗？\n里面的内容会一起删掉，不能恢复。`
        : `确定删除文件「${entry.name}」吗？`;
    if (!window.confirm(hint)) return;
    setStatus(`正在删除 ${entry.name} …`);
    try {
      await shell(driver, `rm -rf -- ${shQuote(target)}`);
      log(`[文件] 已删除${what} ${entry.name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`已删除 ${entry.name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`删除失败：${message}`, "err");
      log(`[文件] 删除 ${entry.name} 失败：${message}`, "err");
    }
  }

  async function renameEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const next = window.prompt(`重命名「${entry.name}」为：`, entry.name);
    if (next === null) return;
    const name = next.trim();
    if (!name || name === entry.name) return;
    if (name.includes("/")) {
      setStatus("名字里不能有 /", "err");
      return;
    }
    const from = joinPath(state.path, entry.name);
    const to = joinPath(state.path, name);
    setStatus(`正在重命名 ${entry.name} …`);
    try {
      await shell(driver, `mv -f -- ${shQuote(from)} ${shQuote(to)}`);
      log(`[文件] ${entry.name} → ${name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`已重命名为 ${name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`重命名失败：${message}`, "err");
      log(`[文件] 重命名 ${entry.name} 失败：${message}`, "err");
    }
  }

  async function makeDir() {
    const driver = getDriver();
    if (!driver) return;
    const name = (window.prompt("新建文件夹，名字：", "新建文件夹") || "").trim();
    if (!name) return;
    if (name.includes("/")) {
      setStatus("名字里不能有 /", "err");
      return;
    }
    const target = joinPath(state.path, name);
    try {
      await shell(driver, `mkdir -p -- ${shQuote(target)}`);
      log(`[文件] 已新建文件夹 ${name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`已新建 ${name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`新建失败：${message}`, "err");
      log(`[文件] 新建 ${name} 失败：${message}`, "err");
    }
  }

  /* ---------- 事件 ---------- */

  pv.addEventListener("click", (event) => {
    const act = event.target.closest("[data-pv]")?.dataset.pv;
    if (!act) return;
    if (act === "close") closeViewer();
    else if (act === "full") toggleFullscreen();
    else if (act === "prev") stepViewer(-1);
    else if (act === "next") stepViewer(1);
    else if (act === "download") {
      const entry = viewer.items[viewer.index];
      if (entry) downloadEntry(entry);
    }
  });

  pvBody.addEventListener("dblclick", (event) => {
    if (event.target.closest("video,audio,iframe")) return;
    toggleFullscreen();
  });

  // 捕获阶段拦：预览开着时 Esc / F / ← / → 归预览，不能让它再去关整个文件面板
  document.addEventListener(
    "keydown",
    (event) => {
      if (!viewer.open) return;
      const tag = event.target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (event.key === "Escape") {
        // 真全屏时 Esc 归浏览器处理，fullscreenchange 会同步状态
        if (document.fullscreenElement === pv) return;
        event.stopPropagation();
        event.preventDefault();
        if (viewer.max) setFullscreen(false);
        else closeViewer();
      } else if (event.key === "f" || event.key === "F") {
        event.stopPropagation();
        event.preventDefault();
        toggleFullscreen();
      } else if (event.key === "ArrowLeft") {
        event.stopPropagation();
        event.preventDefault();
        stepViewer(-1);
      } else if (event.key === "ArrowRight") {
        event.stopPropagation();
        event.preventDefault();
        stepViewer(1);
      }
    },
    true
  );

  container.querySelector(".fp-bar").addEventListener("click", (event) => {
    const button = event.target.closest("[data-act]");
    if (!button) return;
    const act = button.dataset.act;
    if (act === "up") load(parentPath(state.path));
    else if (act === "home") load("/sdcard");
    else if (act === "refresh") load(state.path);
    else if (act === "mkdir") makeDir();
    else if (act === "upload") fileInput.click();
    else if (act === "close") onClose();
  });

  container.querySelector(".fp-chips").addEventListener("click", (event) => {
    const chip = event.target.closest("[data-path]");
    if (chip) load(chip.dataset.path);
  });

  // 点路径可以直接手输，省得一层层往上走
  pathEl.addEventListener("click", () => {
    const input = window.prompt("跳转到路径：", state.path);
    if (input) load(input);
  });

  filterEl.addEventListener("input", () => {
    state.filter = filterEl.value;
    render();
  });
  filterEl.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      filterEl.value = "";
      state.filter = "";
      render();
      filterEl.blur();
    }
  });

  listEl.addEventListener("click", (event) => {
    const row = event.target.closest(".fp-row");
    if (!row) return;
    state.selected = row.dataset.name;
    listEl.querySelectorAll(".fp-row.on").forEach((el) => el.classList.remove("on"));
    row.classList.add("on");

    const op = event.target.closest("[data-op]")?.dataset.op;
    if (!op) return;
    const entry = state.entries.find((item) => item.name === row.dataset.name);
    if (!entry) return;
    if (op === "preview") openViewer(entry);
    else if (op === "download") downloadEntry(entry);
    else if (op === "rename") renameEntry(entry);
    else if (op === "delete") removeEntry(entry);
  });

  listEl.addEventListener("dblclick", (event) => {
    const row = event.target.closest(".fp-row");
    if (!row) return;
    const entry = state.entries.find((item) => item.name === row.dataset.name);
    if (!entry) return;
    if (entry.type === TYPE_DIR) load(joinPath(state.path, entry.name));
    else openViewer(entry);
  });

  fileInput.addEventListener("change", () => {
    const files = [...fileInput.files];
    fileInput.value = "";
    uploadFiles(files);
  });

  /* 拖拽上传：拖到列表上就传，位置不敏感（路径已经由面包屑决定） */
  let dragDepth = 0;
  listEl.addEventListener("dragenter", (event) => {
    event.preventDefault();
    dragDepth += 1;
    listEl.classList.add("drop");
  });
  listEl.addEventListener("dragover", (event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  });
  listEl.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) listEl.classList.remove("drop");
  });
  listEl.addEventListener("drop", (event) => {
    event.preventDefault();
    dragDepth = 0;
    listEl.classList.remove("drop");
    const files = [...(event.dataTransfer?.files || [])];
    if (files.length) uploadFiles(files);
  });

  return {
    open(path = "/sdcard") {
      load(path);
    },
    refresh() {
      load(state.path, { quiet: true });
    },
    get path() {
      return state.path;
    },
  };
}
