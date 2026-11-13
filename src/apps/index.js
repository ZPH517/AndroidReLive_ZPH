/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

应用管理面板 —— 长在投屏页里，和投屏 / 文件管理共用同一条 WebUSB 连接。

为什么不另起一个页面：WebUSB 在同一个浏览器里只能有一个持有者，切到主页的
「软件管理」就得断开重连，投屏也跟着没了。所以这里做成一个浮层面板。

命令层复用 js/core/core.js 里上游作者已实测过的 GJ.Service（省掉重复造轮子）：
  - 启用/禁用/运行/强停/卸载/清数据/恢复/软件信息 → packageAction()
  - 提取安装包（含拆分 APK 自动打 zip）        → extract()
  - 安装 APK（含 install-create 拆分会话）      → install()
pm 的参数顺序（--user 0、系统包要带 -k、恢复用 install-existing）在不同 ROM
上差别很大，自己拼一套很容易翻车，复用现成的比重新试错稳得多。

本模块新增的部分只有：一次性把几种 pm list 结果聚合成「包名 + 类型 + 状态」
的表格，以及搜索、勾选、批量编排、清单导出和详情解析。
*/

import { GJ } from "../../js/core/core.js";
import { formatSize } from "../files/index.js";
import { probeDevice, resolveAppMeta, getCachedMeta, saveMeta, clearMetaCache } from "./labels.js";

/* 一次 shell 拿齐所有分组，避免并行开好几条 ADB 流。
   顺序有讲究：U 是「含已卸载」的全集，P 是「当前可见」的全集，
   两者求差就是被 pm uninstall --user 0 卸掉、但还能恢复的那些包。
   -e 只用来交叉验证，不参与状态判断（有些 ROM 不支持这个过滤）。*/
const SECTIONS = [
  ["U", "pm list packages -u"],
  ["P", "pm list packages"],
  ["3", "pm list packages -3"],
  ["S", "pm list packages -s"],
  ["D", "pm list packages -d"],
  ["E", "pm list packages -e"],
];

const TYPE_LABEL = { system: "系统", third: "第三方", unknown: "未知" };
const STATE_LABEL = { enabled: "已启用", disabled: "已禁用", uninstalled: "已卸载", installed: "已安装" };

const ACTION_LABEL = {
  launch: "启动",
  stop: "强行停止",
  uninstall: "卸载",
  restore: "恢复",
  disable: "禁用",
  enable: "启用",
  clear: "清除数据",
};

const FILTERS = [
  ["all", "全部"],
  ["third", "第三方"],
  ["system", "系统"],
  ["disabled", "已禁用"],
  ["uninstalled", "已卸载"],
  ["selected", "已勾选"],
];

/* ---------- 解析 ---------- */

/** 把 echo 出来的分段标记切开，包名行进 names，其它行进 noise（供详细日志核对） */
function parseSections(text) {
  const sections = {};
  let current = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    const mark = line.match(/^__([A-Z0-9]+)__$/);
    if (mark) {
      current = mark[1];
      sections[current] = { names: new Set(), noise: [] };
      continue;
    }
    if (!current || !line) continue;
    if (line.startsWith("package:")) sections[current].names.add(line.slice(8).trim());
    else sections[current].noise.push(line);
  }
  return sections;
}

function shortName(pkg) {
  const parts = String(pkg).split(".");
  return parts[parts.length - 1] || pkg;
}

/** dumpsys package 里挑几项有用的，输出太大所以只留摘要 */
function parseDetail(text) {
  const raw = String(text);
  const pick = (re) => raw.match(re)?.[1]?.trim() || "—";
  const permissions = [];
  const block = raw.split(/grantedPermissions:\s*/)[1] || "";
  for (const line of block.split(/\r?\n/)) {
    const value = line.trim();
    if (/^[\w.]+\.permission\.[\w.]+$/.test(value)) permissions.push(value);
    else if (permissions.length) break;
  }
  return {
    versionName: pick(/\bversionName=([^\s]+)/),
    versionCode: pick(/\bversionCode=(\d+)/),
    targetSdk: pick(/\btargetSdk=(\d+)/),
    firstInstall: pick(/firstInstallTime=([^\r\n]+)/),
    lastUpdate: pick(/lastUpdateTime=([^\r\n]+)/),
    installer: pick(/installerPackageName=([^\s]+)/),
    permissions,
    lines: raw.split(/\r?\n/).length,
  };
}

function csvCell(value) {
  return '"' + String(value ?? "").replace(/"/g, '""') + '"';
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // 立刻 revoke 会让部分浏览器的下载中断，给它一点时间
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}

/* ---------- 面板 ---------- */

export function mountAppPanel({ container, getDriver, log = () => {}, onClose = () => {} }) {
  container.innerHTML = `
    <div class="ap-bar">
      <button class="ap-btn primary" data-act="refresh" title="重新读取设备上的应用">刷新列表</button>
      <button class="ap-btn" data-act="identify" title="从平板上的 APK 里读出应用名称和桌面图标；只处理当前筛选出来的、还没认过的">识别应用</button>
      <button class="ap-btn" data-act="install" title="选择一个或多个独立 APK 分别安装">安装 APK</button>
      <button class="ap-btn" data-act="install-split" title="选中同一套 base.apk + split_config.*.apk 一起安装">拆分安装</button>
      <button class="ap-btn" data-act="export" title="把当前列表导出成 CSV，Excel 可直接打开">导出清单</button>
      <span class="ap-spacer"></span>
      <span class="ap-count" id="apCount">—</span>
      <button class="ap-btn tiny ghost" data-act="clear-meta" title="清掉记住的名称和图标，下次重新识别">清缓存</button>
      <button class="ap-btn ghost" data-act="close" title="关闭（Esc）">✕</button>
    </div>
    <div class="ap-chips" id="apChips"></div>
    <div class="ap-tools">
      <input class="ap-filter" id="apFilter" placeholder="搜索包名，Esc 清空" spellcheck="false">
      <span class="ap-tools-label">批量：</span>
      <button class="ap-btn tiny" data-batch="uninstall">卸载</button>
      <button class="ap-btn tiny" data-batch="disable">禁用</button>
      <button class="ap-btn tiny" data-batch="enable">启用</button>
      <button class="ap-btn tiny" data-batch="restore">恢复</button>
      <span class="ap-tools-sep"></span>
      <button class="ap-btn tiny ghost" data-batch="select-all">全选可见</button>
      <button class="ap-btn tiny ghost" data-batch="clear-sel">清空勾选</button>
    </div>
    <div class="ap-head">
      <span></span><span>应用</span><span>类型</span><span>状态</span><span>操作</span>
    </div>
    <div class="ap-list" id="apList"></div>
    <div class="ap-detail" id="apDetail" hidden></div>
    <div class="ap-status" id="apStatus">连接设备后点「刷新列表」</div>
    <input type="file" id="apFile" accept=".apk,application/vnd.android.package-archive" multiple hidden>
  `;

  const listEl = container.querySelector("#apList");
  const chipsEl = container.querySelector("#apChips");
  const filterEl = container.querySelector("#apFilter");
  const countEl = container.querySelector("#apCount");
  const statusEl = container.querySelector("#apStatus");
  const detailEl = container.querySelector("#apDetail");
  const fileEl = container.querySelector("#apFile");
  const identifyBtn = container.querySelector('[data-act="identify"]');

  const state = {
    rows: [],
    filter: "all",
    keyword: "",
    selected: new Set(),
    busy: false,
    detailPkg: null,
    stats: null,
    loadToken: 0,
    identifying: false,
    stopIdentify: false,
    caps: null,
    capsDriver: null,
  };

  function setStatus(text, kind = "") {
    statusEl.textContent = text;
    statusEl.className = "ap-status" + (kind ? " " + kind : "");
  }

  function setBusy(on) {
    state.busy = on;
    container.classList.toggle("busy", on);
  }

  /** 每次现取现用：断线重连后 getDriver() 会返回新对象，缓存住就废了 */
  function getService() {
    const driver = getDriver();
    if (!driver?.connected) throw new Error("设备未连接");
    const service = new GJ.Service({
      output: (kind, text) => {
        const value = String(text).trim();
        if (!value) return;
        const prefix = kind === "command" ? "$ " : kind === "stderr" ? "! " : "  ";
        log(`[应用] ${prefix}${value}`, "dim");
      },
      progress: (name, done, total) => {
        const percent = total ? Math.round((done / total) * 100) : 0;
        setStatus(`${name} … ${percent}%（${formatSize(done)}${total ? " / " + formatSize(total) : ""}）`);
      },
      saveFile: (blob, name) => {
        downloadBlob(blob, name);
        log(`[应用] 已保存 ${name}（${formatSize(blob.size)}）`, "ok");
      },
      history: (item) => log(`[应用] 操作记录 ${item.action} ${item.package}`, "dim"),
      getSettings: () => GJ.defaults,
    });
    service.driver = driver;
    return service;
  }

  /* ---------- 列表 ---------- */

  /* force: 批量操作期间调用方自己正持有 busy，这时也允许刷新
     keepStatus: 刷新完不要把状态栏的「操作结论」冲掉 */
  async function load({ quiet = false, force = false, keepStatus = false } = {}) {
    const driver = getDriver();
    if (!driver?.connected) {
      setStatus("设备未连接", "err");
      return;
    }
    if (state.busy && !force) return;
    const token = ++state.loadToken;
    const wasBusy = state.busy;
    setBusy(true);
    if (!quiet) setStatus("正在读取应用列表…");
    try {
      const service = getService();
      // 分号串成一条：一次 ADB 流拿完，也避免并发流把某些 ROM 搞卡
      const script = SECTIONS.map(([tag, cmd]) => `echo __${tag}__; ${cmd} 2>&1`).join("; ");
      const text = await service.text(script, { log: false, allowFailure: true });
      if (token !== state.loadToken) return;
      const sections = parseSections(text);
      const get = (tag) => sections[tag]?.names || new Set();
      const u = get("U");
      const p = get("P");
      const third = get("3");
      const system = get("S");
      const disabled = get("D");
      const enabled = get("E");

      // 不确定就先打到日志里核对，别靠猜：各段包数、异常输出都留痕
      log(
        `[应用] 分组统计 U(含已卸载)=${u.size} P(当前)=${p.size} ` +
          `第三方=${third.size} 系统=${system.size} 禁用=${disabled.size} 启用过滤=${enabled.size}`,
        "dim"
      );
      for (const [tag, section] of Object.entries(sections)) {
        if (section.noise.length) {
          log(`[应用] ${tag} 段有 ${section.noise.length} 行非包名输出：${section.noise.slice(0, 4).join(" | ")}`, "err");
        }
      }
      if (!u.size) log("[应用] -u 段为空：这台设备可能不支持列出已卸载应用，『已卸载』分组会是空的", "err");
      if (!p.size) log("[应用] pm list packages 没有返回任何包名，请检查 ADB 权限", "err");

      // 全集以 U 为准；万一 -u 不可用，退回 P，保证列表不至于空白
      const all = new Set([...u, ...p, ...third, ...system, ...disabled, ...enabled]);
      const rows = [];
      for (const pkg of all) {
        if (!/^[\w]+(?:\.[\w]+)+$/.test(pkg)) continue;
        const type = system.has(pkg) ? "system" : third.has(pkg) ? "third" : "unknown";
        // U 有、P 没有 = 对当前用户卸载过，还能用 install-existing 找回来
        const status = u.has(pkg) && !p.has(pkg) ? "uninstalled" : disabled.has(pkg) ? "disabled" : "enabled";
        rows.push({ pkg, short: shortName(pkg), type, status });
      }
      rows.sort((a, b) => a.pkg.localeCompare(b.pkg, "en", { numeric: true }));
      state.rows = rows;
      state.stats = { u: u.size, p: p.size, third: third.size, system: system.size, disabled: disabled.size, enabled: enabled.size };
      // 列表变了，勾选项里已经不在的就丢掉
      const known = new Set(rows.map((row) => row.pkg));
      for (const pkg of state.selected) if (!known.has(pkg)) state.selected.delete(pkg);
      if (state.detailPkg && !known.has(state.detailPkg)) closeDetail();
      render();
      const removed = rows.filter((r) => r.status === "uninstalled").length;
      const off = rows.filter((r) => r.status === "disabled").length;
      const identified = rows.filter((r) => getCachedMeta(r.pkg)?.label).length;
      if (!keepStatus) {
        setStatus(`共 ${rows.length} 个应用 · 第三方 ${rows.filter((r) => r.type === "third").length} · 已禁用 ${off} · 可恢复 ${removed} · 已识别 ${identified}${identified ? "" : "（点「识别应用」显示名称和图标）"}`);
      }
      log(`[应用] 列表已更新：${rows.length} 个（已禁用 ${off}，可恢复 ${removed}）`, quiet ? "dim" : "ok");
    } catch (error) {
      const message = error?.message || String(error);
      if (!keepStatus) setStatus("读取失败：" + message, "err");
      log(`[应用] 读取应用列表失败：${message}`, "err");
    } finally {
      setBusy(wasBusy);
    }
  }

  /** 搜索同时匹配包名、短名和识别出来的中文名 */
  function matchesKeyword(row) {
    const kw = state.keyword;
    if (!kw) return true;
    if (row.pkg.toLowerCase().includes(kw) || row.short.toLowerCase().includes(kw)) return true;
    const label = getCachedMeta(row.pkg)?.label;
    return !!(label && String(label).toLowerCase().includes(kw));
  }

  function visibleRows() {
    return state.rows.filter((row) => {
      if (!matchesKeyword(row)) return false;
      const f = state.filter;
      if (f === "selected") return state.selected.has(row.pkg);
      if (f === "third" || f === "system") return row.type === f;
      if (f === "disabled" || f === "uninstalled") return row.status === f;
      return true;
    });
  }

  function countFor(filter) {
    if (filter === "all") return state.rows.length;
    if (filter === "selected") return state.selected.size;
    if (filter === "third" || filter === "system") return state.rows.filter((r) => r.type === filter).length;
    return state.rows.filter((r) => r.status === filter).length;
  }

  function renderChips() {
    chipsEl.textContent = "";
    for (const [key, label] of FILTERS) {
      const chip = document.createElement("button");
      chip.className = "ap-chip" + (state.filter === key ? " on" : "");
      chip.dataset.filter = key;
      chip.textContent = `${label} (${countFor(key)})`;
      chipsEl.appendChild(chip);
    }
  }

  function opButtons(row) {
    const op = (action, label, cls = "") =>
      `<button class="ap-op ${cls}" data-op="${action}" title="${label}">${label}</button>`;
    if (row.status === "uninstalled") {
      return op("restore", "恢复", "good") + op("detail", "详情");
    }
    const list = [];
    if (row.status === "disabled") list.push(op("enable", "启用", "good"));
    else list.push(op("launch", "启动"), op("stop", "强停"), op("disable", "禁用"));
    list.push(op("uninstall", "卸载", "danger"), op("clear", "清数据", "danger"), op("extract", "提取"), op("detail", "详情"));
    return list.join("");
  }

  /** 一行的「图标 + 显示名 + 包名」；认不出来就退回短名和首字色块 */
  function nameHtml(row) {
    const meta = getCachedMeta(row.pkg);
    const label = meta?.label || "";
    const text = label || row.short;
    const icon = meta?.icon
      ? `<img class="ap-ico" src="${esc(meta.icon)}" alt="" loading="lazy">`
      : `<span class="ap-ico-fb">${esc((text[0] || "?").toUpperCase())}</span>`;
    return `<span class="ap-name">${icon}<span class="ap-text">` +
      `<span class="ap-short${label ? " cn" : ""}" title="${esc(row.pkg)}">${esc(text)}</span>` +
      `<span class="ap-pkg">${esc(row.pkg)}</span></span></span>`;
  }

  /** 识别完一个就只改这一行，别整表重绘，否则勾选、滚动位置和焦点全没了 */
  function updateRow(pkg) {
    const selector = window.CSS?.escape ? `.ap-row[data-pkg="${CSS.escape(pkg)}"]` : null;
    const item = selector
      ? listEl.querySelector(selector)
      : [...listEl.querySelectorAll(".ap-row")].find((el) => el.dataset.pkg === pkg);
    if (!item) return;
    const row = state.rows.find((r) => r.pkg === pkg);
    if (!row) return;
    const holder = document.createElement("span");
    holder.innerHTML = nameHtml(row);
    item.querySelector(".ap-name")?.replaceWith(holder.firstElementChild);
  }

  function render() {
    renderChips();
    const rows = visibleRows();
    countEl.textContent = `${rows.length} / ${state.rows.length} 条 · 已勾选 ${state.selected.size}`;
    listEl.textContent = "";
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "ap-empty";
      empty.textContent = state.rows.length ? "没有匹配的应用" : "点「刷新列表」读取设备上的应用";
      listEl.appendChild(empty);
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const row of rows.slice(0, 800)) {
      const item = document.createElement("div");
      item.className = "ap-row" + (state.detailPkg === row.pkg ? " on" : "");
      item.dataset.pkg = row.pkg;
      const stateClass = row.status === "disabled" ? "warn" : row.status === "uninstalled" ? "off" : "ok";
      item.innerHTML = `
        <label class="ap-check"><input type="checkbox" data-check="${esc(row.pkg)}" ${state.selected.has(row.pkg) ? "checked" : ""}></label>
        ${nameHtml(row)}
        <span class="ap-type ${row.type}">${TYPE_LABEL[row.type]}</span>
        <span class="ap-state ${stateClass}">${STATE_LABEL[row.status]}</span>
        <span class="ap-ops">${opButtons(row)}</span>
      `;
      fragment.appendChild(item);
    }
    listEl.appendChild(fragment);
    if (rows.length > 800) {
      const more = document.createElement("div");
      more.className = "ap-empty";
      more.textContent = `只显示前 800 条，共 ${rows.length} 条；用搜索缩小范围`;
      listEl.appendChild(more);
    }
  }

  /* ---------- 详情 ---------- */

  function closeDetail() {
    state.detailPkg = null;
    detailEl.hidden = true;
    detailEl.textContent = "";
    listEl.querySelectorAll(".ap-row.on").forEach((el) => el.classList.remove("on"));
  }

  async function showDetail(pkg) {
    if (state.detailPkg === pkg) return closeDetail();
    closeDetail();
    state.detailPkg = pkg;
    const row = state.rows.find((item) => item.pkg === pkg);
    const label = getCachedMeta(pkg)?.label;
    const title = label ? `${label} · ${pkg}` : pkg;
    detailEl.hidden = false;
    detailEl.innerHTML = `<div class="ap-detail-head"><b>${esc(title)}</b><button class="ap-op" data-d="close">关闭</button></div><div class="ap-detail-body">读取中…</div>`;
    render();
    try {
      const service = getService();
      const [raw, pathText] = await Promise.all([
        service.text(`dumpsys package ${GJ.quote(pkg)}`, { log: false, allowFailure: true }),
        service.text(`pm path ${GJ.quote(pkg)}`, { log: false, allowFailure: true }),
      ]);
      if (state.detailPkg !== pkg) return;
      const info = parseDetail(raw);
      const paths = String(pathText)
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.startsWith("package:"))
        .map((line) => line.slice(8).trim());
      log(`[应用] 详情 ${pkg}：dumpsys ${info.lines} 行，APK ${paths.length} 个，已授权限 ${info.permissions.length} 条`, "dim");
      const kv = (label, value) => `<div class="ap-kv"><span>${label}</span><code>${esc(value)}</code></div>`;
      detailEl.innerHTML = `
        <div class="ap-detail-head"><b>${esc(title)}</b><span class="ap-detail-meta">${TYPE_LABEL[row?.type] || "未知"} · ${STATE_LABEL[row?.status] || "—"}</span><button class="ap-op" data-d="close">关闭</button></div>
        <div class="ap-detail-body">
          <div class="ap-kv-grid">
            ${kv("版本号", info.versionName)}
            ${kv("版本码", info.versionCode)}
            ${kv("targetSdk", info.targetSdk)}
            ${kv("安装来源", info.installer)}
            ${kv("首次安装", info.firstInstall)}
            ${kv("最后更新", info.lastUpdate)}
          </div>
          <div class="ap-detail-sec">安装包路径（${paths.length} 个）</div>
          <div class="ap-paths">${paths.length ? paths.map((p) => `<code>${esc(p)}</code>`).join("") : "<code>该应用当前没有安装路径（可能已被卸载）</code>"}</div>
          <div class="ap-detail-sec">已授予权限（${info.permissions.length} 条）</div>
          <div class="ap-perms">${info.permissions.length ? info.permissions.slice(0, 40).map((p) => `<code>${esc(p)}</code>`).join("") : "<code>没有读到权限列表</code>"}${info.permissions.length > 40 ? `<code>… 另有 ${info.permissions.length - 40} 条</code>` : ""}</div>
        </div>
      `;
    } catch (error) {
      if (state.detailPkg !== pkg) return;
      detailEl.querySelector(".ap-detail-body").textContent = "读取失败：" + (error?.message || error);
      log(`[应用] 读取 ${pkg} 详情失败：${error?.message || error}`, "err");
    }
  }

  /* ---------- 操作 ---------- */

  /** 单个操作。返回 true 表示成功，失败原因已经打到日志和状态栏 */
  async function runOne(action, pkg, { quiet = false } = {}) {
    const label = ACTION_LABEL[action] || action;
    try {
      const service = getService();
      const out = await service.packageAction(action, pkg);
      const text = String(out || "").trim();
      if (action === "launch" && /No activities found|monkey aborted|Error/i.test(text)) {
        log(`[应用] ${label} ${pkg}：没找到桌面启动入口（${text.slice(0, 120)}）`, "err");
        if (!quiet) setStatus(`${label} ${pkg} 失败：没有桌面启动入口`, "err");
        return false;
      }
      log(`[应用] ${label} ${pkg} 成功${text ? `：${text.slice(0, 120)}` : ""}`, quiet ? "dim" : "ok");
      return true;
    } catch (error) {
      const message = String(error?.message || error).trim();
      log(`[应用] ${label} ${pkg} 失败：${message.slice(0, 300)}`, "err");
      if (!quiet) setStatus(`${label} ${pkg} 失败：${message.slice(0, 200)}`, "err");
      return false;
    }
  }

  const WARN = {
    uninstall: "系统应用会按主页的成熟做法「保留数据卸载」，之后可以在「已卸载」里恢复。",
    disable: "禁用后应用会从桌面消失，但数据还在，随时可以再启用。",
    enable: "会把选中的应用重新启用。",
    restore: "只对已经卸载、还能找回来的系统应用有效；第三方应用卸载后没法用这个恢复。",
  };

  async function runBatch(action) {
    if (state.busy) return setStatus("上一个操作还没结束", "err");
    if (blockedByIdentify("做这个操作")) return;
    const targets = visibleRows().filter((row) => state.selected.has(row.pkg));
    const label = ACTION_LABEL[action];
    if (!targets.length) return setStatus(`先勾选要${label}的应用`, "err");
    // 状态不对的包直接跳过，别把「恢复」误发到还装着的包上
    const usable = targets.filter((row) => {
      if (action === "restore") return row.status === "uninstalled";
      if (action === "enable") return row.status === "disabled";
      if (action === "disable") return row.status === "enabled";
      return row.status !== "uninstalled";
    });
    const skipped = targets.length - usable.length;
    if (!usable.length) return setStatus(`勾选的应用都不需要「${label}」（状态不匹配）`, "err");
    const preview = usable.slice(0, 8).map((row) => `  · ${row.pkg}`).join("\n");
    const more = usable.length > 8 ? `\n  … 还有 ${usable.length - 8} 个` : "";
    const hint = `\n\n${WARN[action] || ""}${skipped ? `\n\n另有 ${skipped} 个状态不匹配，会自动跳过。` : ""}`;
    if (!window.confirm(`确定对 ${usable.length} 个应用执行「${label}」吗？\n${preview}${more}${hint}`)) return;

    setBusy(true);
    let ok = 0;
    let fail = 0;
    try {
      for (let i = 0; i < usable.length; i += 1) {
        const pkg = usable[i].pkg;
        setStatus(`(${i + 1}/${usable.length}) ${label} ${pkg} …`);
        if (await runOne(action, pkg, { quiet: true })) ok += 1;
        else fail += 1;
      }
      setStatus(`${label}完成：成功 ${ok} / 失败 ${fail} / 共 ${usable.length}${skipped ? `，跳过 ${skipped}` : ""}`, fail ? "err" : "");
      log(`[应用] 批量${label}结束：成功 ${ok}，失败 ${fail}`, fail ? "err" : "ok");
      state.selected.clear();
      await load({ quiet: true, force: true, keepStatus: true });
    } finally {
      setBusy(false);
    }
  }

  async function singleOp(action, pkg) {
    if (state.busy) return setStatus("上一个操作还没结束", "err");
    if (blockedByIdentify("做这个操作")) return;
    const label = ACTION_LABEL[action] || "操作";
    if (action === "clear") {
      if (!window.confirm(`确定清除「${pkg}」的全部数据吗？\n\n会删掉登录状态、设置和本地文件，不能恢复。\n只清缓存的话，安卓没有给 ADB 开放单应用清缓存的接口，这里清的是完整数据。`)) return;
    } else if (action === "uninstall") {
      if (!window.confirm(`确定卸载「${pkg}」吗？\n\n系统应用会保留数据卸载，之后可以在「已卸载」分组里点「恢复」找回来。`)) return;
    }
    setBusy(true);
    try {
      setStatus(`正在${label} ${pkg} …`);
      const ok = await runOne(action, pkg);
      if (ok) {
        setStatus(`${label} ${pkg} 完成`);
        await load({ quiet: true, force: true, keepStatus: true });
      }
    } finally {
      setBusy(false);
    }
  }

  async function extractOne(pkg) {
    if (state.busy) return setStatus("上一个操作还没结束", "err");
    if (blockedByIdentify("做这个操作")) return;
    setBusy(true);
    try {
      setStatus(`正在提取 ${pkg} 的安装包…`);
      const service = getService();
      // 复用主页的实现：单 APK 直接下载，拆分 APK 自动打成一个 zip
      const blob = await service.extract(pkg);
      setStatus(`已提取 ${pkg}（${formatSize(blob.size)}）`);
    } catch (error) {
      const message = String(error?.message || error).trim();
      setStatus(`提取 ${pkg} 失败：${message.slice(0, 200)}`, "err");
      log(`[应用] 提取 ${pkg} 失败：${message.slice(0, 300)}`, "err");
    } finally {
      setBusy(false);
    }
  }

  async function installFiles(files, split) {
    if (!files.length) return;
    if (state.busy) return setStatus("上一个操作还没结束", "err");
    if (blockedByIdentify("做这个操作")) return;
    for (const file of files) {
      if (!/\.apk$/i.test(file.name)) {
        setStatus(`${file.name} 不是 APK 文件`, "err");
        return;
      }
    }
    setBusy(true);
    try {
      setStatus(`正在安装 ${files.length} 个 APK（${split ? "拆分会话" : "逐个安装"}）…`);
      const service = getService();
      const results = await service.install(files, { split });
      const ok = results.filter((item) => item.success).length;
      const fail = results.length - ok;
      for (const item of results) {
        log(`[应用] 安装 ${item.name}：${item.success ? "成功" : `失败 ${String(item.output || "").slice(0, 200)}`}`, item.success ? "ok" : "err");
      }
      setStatus(`安装完成：成功 ${ok} / 失败 ${fail}`, fail ? "err" : "");
      await load({ quiet: true, force: true, keepStatus: true });
    } catch (error) {
      const message = String(error?.message || error).trim();
      setStatus("安装失败：" + message.slice(0, 200), "err");
      log(`[应用] 安装失败：${message.slice(0, 300)}`, "err");
    } finally {
      setBusy(false);
    }
  }

  function exportCsv() {
    const rows = state.selected.size
      ? state.rows.filter((row) => state.selected.has(row.pkg))
      : visibleRows();
    if (!rows.length) return setStatus("没有可导出的应用", "err");
    const header = ["包名", "应用名称", "短名", "类型", "状态", "导出时间"].map(csvCell).join(",");
    const now = new Date().toLocaleString("zh-CN");
    const lines = rows.map((row) =>
      [row.pkg, getCachedMeta(row.pkg)?.label || "", row.short, TYPE_LABEL[row.type], STATE_LABEL[row.status], now].map(csvCell).join(",")
    );
    // BOM：Excel 打开中文不乱码
    const csv = "\uFEFF" + [header, ...lines].join("\r\n") + "\r\n";
    const name = `应用清单_${GJ.timestamp()}.csv`;
    downloadBlob(new Blob([csv], { type: "text/csv;charset=utf-8" }), name);
    setStatus(`已导出 ${rows.length} 条到 ${name}${state.selected.size ? "（仅勾选）" : "（当前筛选）"}`);
    log(`[应用] 导出清单 ${name}（${rows.length} 条）`, "ok");
  }

  /* ---------- 应用名称 / 图标识别 ----------
   * 一台平板 180+ 个包，挨个读 APK 会一直占着 ADB 连接，所以：
   *   - 只处理当前筛选里还没认过的（已卸载的没有 APK，直接跳过）
   *   - 并发 2，随时可以再点一次按钮停下来
   *   - 结果按包名缓存，下次打开面板直接显示，不用重跑
   */
  function blockedByIdentify(what) {
    if (!state.identifying) return false;
    setStatus(`正在识别应用，先点「停止识别」再${what}`, "err");
    return true;
  }

  async function identify() {
    if (state.identifying) {
      state.stopIdentify = true;
      setStatus("正在停止，等手头这两个跑完…");
      return;
    }
    if (state.busy) return setStatus("先等当前操作结束", "err");
    const driver = getDriver();
    if (!driver?.connected) return setStatus("设备未连接", "err");
    const candidates = visibleRows().filter((row) => {
      if (row.status === "uninstalled") return false; // 已卸载的拿不到 APK
      const meta = getCachedMeta(row.pkg);
      return !(meta?.label || meta?.icon);
    });
    if (!candidates.length) {
      setStatus("当前筛选里的应用都认过了；想重新读一遍先点「清缓存」");
      return;
    }

    state.identifying = true;
    state.stopIdentify = false;
    identifyBtn.textContent = "停止识别";
    const queue = [...candidates];
    const total = queue.length;
    let done = 0;
    let ok = 0;
    let fail = 0;
    try {
      // 换过设备（断线重连）就重新探一次，同一台设备别每次都白跑
      if (!state.caps || state.capsDriver !== driver) {
        setStatus("正在探测平板上可用的命令…");
        state.caps = await probeDevice(getService(), log);
        state.capsDriver = driver;
      }
      if (!state.caps.unzip || !state.caps.base64) {
        log("[识别] 平板没有可用的 unzip/base64，改走整包读取，会慢不少；随时可以点「停止识别」", "err");
      }
      const service = getService();
      const worker = async () => {
        while (queue.length && !state.stopIdentify) {
          const row = queue.shift();
          try {
            const meta = await resolveAppMeta({ service, driver, pkg: row.pkg, caps: state.caps, log });
            saveMeta(row.pkg, meta);
            updateRow(row.pkg);
            ok += 1;
            if (!meta.label && !meta.icon) log(`[识别] ${row.pkg}：名称和图标都没取到`, "dim");
          } catch (error) {
            fail += 1;
            log(`[识别] ${row.pkg} 失败：${String(error?.message || error).slice(0, 180)}`, "dim");
          }
          done += 1;
          if (done % 5 === 0 || done === total || state.stopIdentify) {
            setStatus(`识别中 ${done}/${total} · 成功 ${ok} · 失败 ${fail}（再点一次可停止）`);
          }
        }
      };
      await Promise.all([worker(), worker()]);
      const stopped = state.stopIdentify;
      setStatus(
        `识别${stopped ? "已停止" : "完成"}：成功 ${ok} / 失败 ${fail} / 计划 ${total}` +
          (stopped ? `，还有 ${queue.length} 个没跑` : ""),
        fail ? "err" : ""
      );
      const source = state.caps.aapt ? "aapt" : state.caps.unzip && state.caps.base64 ? "unzip+base64" : "ADB 整包";
      log(`[识别] ${stopped ? "中途停止" : "完成"}：成功 ${ok}，失败 ${fail}，共 ${total}，取数方式 ${source}`, fail ? "err" : "ok");
    } catch (error) {
      setStatus("识别中断：" + (error?.message || error), "err");
      log(`[识别] 中断：${error?.message || error}`, "err");
    } finally {
      state.identifying = false;
      state.stopIdentify = false;
      identifyBtn.textContent = "识别应用";
    }
  }

  /* ---------- 事件 ---------- */

  container.querySelector(".ap-bar").addEventListener("click", (event) => {
    const act = event.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    if (act === "close") onClose();
    else if (act === "refresh") load();
    else if (act === "identify") identify();
    else if (act === "clear-meta") {
      if (blockedByIdentify("清缓存")) return;
      clearMetaCache();
      render();
      setStatus("已清掉记住的名称和图标，点「识别应用」可重新读取");
      log("[应用] 已清空应用名称/图标缓存", "dim");
    }
    else if (act === "export") exportCsv();
    else if (act === "install" || act === "install-split") {
      fileEl.dataset.split = act === "install-split" ? "1" : "";
      fileEl.click();
    }
  });

  fileEl.addEventListener("change", () => {
    const files = [...fileEl.files];
    const split = fileEl.dataset.split === "1";
    fileEl.value = "";
    installFiles(files, split);
  });

  chipsEl.addEventListener("click", (event) => {
    const key = event.target.closest("[data-filter]")?.dataset.filter;
    if (!key) return;
    state.filter = key;
    render();
  });

  container.querySelector(".ap-tools").addEventListener("click", (event) => {
    const batch = event.target.closest("[data-batch]")?.dataset.batch;
    if (!batch) return;
    if (batch === "select-all") {
      for (const row of visibleRows()) state.selected.add(row.pkg);
      render();
    } else if (batch === "clear-sel") {
      state.selected.clear();
      render();
    } else {
      runBatch(batch);
    }
  });

  filterEl.addEventListener("input", () => {
    state.keyword = filterEl.value.trim().toLowerCase();
    render();
  });
  filterEl.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (filterEl.value) {
      filterEl.value = "";
      state.keyword = "";
      render();
      filterEl.blur();
      event.stopPropagation();
    }
  });

  listEl.addEventListener("change", (event) => {
    const check = event.target.closest("[data-check]");
    if (!check) return;
    const pkg = check.dataset.check;
    if (check.checked) state.selected.add(pkg);
    else state.selected.delete(pkg);
    renderChips();
    countEl.textContent = `${visibleRows().length} / ${state.rows.length} 条 · 已勾选 ${state.selected.size}`;
  });

  listEl.addEventListener("click", (event) => {
    const button = event.target.closest("[data-op]");
    if (!button) return;
    const row = button.closest(".ap-row");
    if (!row) return;
    const pkg = row.dataset.pkg;
    const op = button.dataset.op;
    if (op === "detail") showDetail(pkg);
    else if (op === "extract") extractOne(pkg);
    else singleOp(op, pkg);
  });

  detailEl.addEventListener("click", (event) => {
    if (event.target.closest("[data-d]")?.dataset.d === "close") closeDetail();
  });

  return {
    open() {
      load();
    },
    refresh() {
      load({ quiet: true });
    },
    close() {
      closeDetail();
    },
    onEscape() {
      if (state.detailPkg) {
        closeDetail();
        return true;
      }
      return false;
    },
    get busy() {
      return state.busy;
    },
    get count() {
      return state.rows.length;
    },
  };
}

export default mountAppPanel;
