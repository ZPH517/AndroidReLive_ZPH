/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

应用显示名 / 桌面图标识别。

问题：adb 的 `pm list packages` 只给包名（com.tencent.mm），
`dumpsys package` 也不给「应用叫什么」。桌面上看到的「微信」「设置」
是 PackageManager 读 APK 里 resources.arsc 得到的，shell 没有现成接口。

所以这里直接从设备上把 APK 里那几块内容捞出来，在浏览器里解：
  1. 设备上有 aapt  → `aapt dump badging`，一行就拿到中文名和图标路径（最省事）
  2. 否则用 `unzip -p APK resources.arsc | base64` → 只传资源表（通常几十~几百 KB）
     再按同样的办法取图标文件；浏览器端解析 resources.arsc 拿 app_name 和 ic_launcher 路径
  3. 设备连 unzip / base64 都没有 → 退回 ADB sync 把整个 APK 读成 Blob，
     浏览器端用最小 ZIP reader 自己解出这两块（慢，但一定可用）

任何一步失败都会把原始输出的前几行写进详细日志，方便真机核对，不做静默兜底。
解析结果按包名缓存在 localStorage；图标只在较小的时候才缓存，避免把 5MB 配额撑爆。
*/

import { GJ } from "../../js/core/core.js";

const CACHE_KEY = "relive.appMeta.v1";

/* 应用名的资源键：绝大多数 APK 用 app_name，少数用别的，按优先级排 */
const LABEL_KEYS = [
  "app_name",
  "application_label",
  "application_name",
  "app_label",
  "launcher_name",
  "app_title",
  "appname",
];
const ICON_KEY_RE = /^(ic_launcher|ic_launcher_round|app_icon|ic_app|launcher_icon|ic_logo|icon_launcher)/i;

/* ---------- 二进制小工具 ---------- */

function u16(b, o) {
  return (b[o] | (b[o + 1] << 8)) >>> 0;
}
function u32(b, o) {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

/** 资源字符串池里的长度字段：高位为 1 时用两个字节/两个 u16 表示 */
function readLen(b, p, utf8) {
  if (utf8) {
    let v = b[p++];
    if (v & 0x80) v = ((v & 0x7f) << 8) | b[p++];
    return { value: v, next: p };
  }
  let v = u16(b, p);
  p += 2;
  if (v & 0x8000) {
    v = ((v & 0x7fff) << 16) | u16(b, p);
    p += 2;
  }
  return { value: v, next: p };
}

/** RES_STRING_POOL_TYPE (0x0001) */
function readPool(b, start) {
  const empty = { strings: [], next: start + 8 };
  if (u16(b, start) !== 0x0001) return empty;
  const headerSize = u16(b, start + 2);
  const size = u32(b, start + 4);
  const count = u32(b, start + 8);
  if (!size || start + size > b.length || count > 200000) return empty;
  const flags = u32(b, start + 16);
  const stringsStart = u32(b, start + 20);
  const utf8 = !!(flags & 0x100);
  const dataStart = start + stringsStart;
  const offsets = start + headerSize;
  const dec8 = new TextDecoder("utf-8");
  const dec16 = new TextDecoder("utf-16le");
  const strings = [];
  for (let i = 0; i < count; i++) {
    let p = dataStart + u32(b, offsets + i * 4);
    try {
      if (utf8) {
        const chars = readLen(b, p, true);
        p = chars.next;
        const bytes = readLen(b, p, true);
        p = bytes.next;
        strings.push(dec8.decode(b.subarray(p, p + bytes.value)));
      } else {
        const chars = readLen(b, p, false);
        p = chars.next;
        strings.push(dec16.decode(b.subarray(p, p + chars.value * 2)));
      }
    } catch {
      strings.push("");
    }
  }
  return { strings, next: start + size };
}

/** 配置优先级：中文 > 默认 > 其它语言。国内应用的中文名一般在 zh / zh-rCN 配置里 */
function configRank(type) {
  const lang = String(type.lang || "").toLowerCase();
  const country = String(type.country || "").toUpperCase();
  if (lang === "zh" && (country === "CN" || country === "")) return 100;
  if (lang === "zh") return 90;
  if (!lang) return 60;
  return 10;
}

/** RES_TABLE_TYPE_TYPE (0x0201) */
function readTypeChunk(b, start, size, keyNames, typeNames, out) {
  const headerSize = u16(b, start + 2);
  const id = b[start + 8];
  const typeFlags = b[start + 9];
  const entryCount = u32(b, start + 12);
  const entriesStart = u32(b, start + 16);
  if (!headerSize || entryCount > 200000 || start + headerSize > start + size) return;

  // ResTable_config 紧跟在 20 字节固定头之后；size>=12 时前 8 字节是 mcc/mnc，
  // 再往后 2+2 就是 language / country（ASCII 直接存，未压缩的情况）
  const cfg = start + 20;
  const cfgSize = cfg + 4 <= start + size ? u32(b, cfg) : 0;
  let lang = "";
  let country = "";
  if (cfgSize >= 12) {
    const l1 = b[cfg + 8], l2 = b[cfg + 9], c1 = b[cfg + 10], c2 = b[cfg + 11];
    if (l1 >= 0x61 && l1 <= 0x7a && l2 >= 0x61 && l2 <= 0x7a) lang = String.fromCharCode(l1, l2);
    if (c1 >= 0x41 && c1 <= 0x5a && c2 >= 0x41 && c2 <= 0x5a) country = String.fromCharCode(c1, c2);
  }

  const offsetsBase = start + headerSize;
  const entriesBase = start + entriesStart;
  const pairs = [];
  // aapt2 会用 sparse / offset16 编码偏移表，不处理会漏掉大量条目
  if (typeFlags & 0x01) {
    for (let i = 0; i < entryCount; i++) {
      const idx = u16(b, offsetsBase + i * 4);
      const off = u16(b, offsetsBase + i * 4 + 2);
      pairs.push([idx, off * 4]);
    }
  } else if (typeFlags & 0x02) {
    for (let i = 0; i < entryCount; i++) {
      const off = u16(b, offsetsBase + i * 2);
      if (off !== 0xffff) pairs.push([i, off * 4]);
    }
  } else {
    for (let i = 0; i < entryCount; i++) {
      const off = u32(b, offsetsBase + i * 4);
      if (off !== 0xffffffff) pairs.push([i, off]);
    }
  }

  const entries = [];
  for (const [, off] of pairs) {
    const e = entriesBase + off;
    if (e + 8 > start + size) continue;
    const entrySize = u16(b, e);
    const entryFlags = u16(b, e + 2);
    const key = keyNames[u32(b, e + 4)] || "";
    if (entryFlags & 0x0001) continue; // FLAG_COMPLEX，是 bag/map 不是普通值
    const v = e + entrySize;
    if (v + 8 > start + size) continue;
    entries.push({ key, dataType: b[v + 3], data: u32(b, v + 4) });
  }
  out.push({ id, typeName: typeNames[id - 1] || "", lang, country, entries });
}

/** RES_TABLE_PACKAGE_TYPE (0x0200) */
function readPackage(b, start, size, global, out) {
  const headerSize = u16(b, start + 2);
  // ResTable_package: header(8) + id(4) + name(256) + typeStrings(4) + lastPublicType(4)
  //                   + keyStrings(4) + lastPublicKey(4) [+ typeIdOffset(4)]
  const typeStringsOff = u32(b, start + 268);
  const keyStringsOff = u32(b, start + 276);
  let typeNames = [];
  let keyNames = [];
  let p = start + headerSize;
  const end = start + size;
  while (p + 8 <= end) {
    const type = u16(b, p);
    const chunkSize = u32(b, p + 4);
    if (chunkSize < 8 || p + chunkSize > end) break;
    if (p === start + typeStringsOff) typeNames = readPool(b, p).strings;
    else if (p === start + keyStringsOff) keyNames = readPool(b, p).strings;
    else if (type === 0x0201) readTypeChunk(b, p, chunkSize, keyNames, typeNames, out);
    p += chunkSize;
  }
}

/** 解析 resources.arsc，返回应用名和图标路径 */
export function parseArsc(b) {
  if (u16(b, 0) !== 0x0002) throw new Error("resources.arsc 头不是 RES_TABLE_TYPE");
  const headerSize = u16(b, 2);
  const total = Math.min(u32(b, 4), b.length);
  let global = [];
  const types = [];
  let p = headerSize;
  let firstPool = true;
  while (p + 8 <= total) {
    const type = u16(b, p);
    const chunkSize = u32(b, p + 4);
    if (chunkSize < 8 || p + chunkSize > total) break;
    if (type === 0x0001) {
      const pool = readPool(b, p);
      if (firstPool) global = pool.strings; // 表级全局字符串池
      firstPool = false;
    } else if (type === 0x0200) {
      readPackage(b, p, chunkSize, global, types);
    }
    p += chunkSize;
  }

  const labels = [];
  const icons = [];
  for (const t of types) {
    const typeName = String(t.typeName || "").toLowerCase();
    const rank = configRank(t);
    for (const e of t.entries) {
      if (e.dataType !== 0x03) continue; // TYPE_STRING：值 = 全局字符串池下标
      const value = global[e.data] || "";
      if (!value) continue;
      if (typeName === "string") {
        const idx = LABEL_KEYS.indexOf(e.key.toLowerCase());
        if (idx >= 0) labels.push({ value, score: rank * 100 + (LABEL_KEYS.length - idx) });
      } else if (typeName === "mipmap" || typeName === "drawable") {
        if (ICON_KEY_RE.test(e.key) && /\.(png|webp|jpe?g)$/i.test(value)) {
          let density = 5;
          if (/xxxhdpi/i.test(value)) density = 30;
          else if (/xxhdpi/i.test(value)) density = 25;
          else if (/xhdpi/i.test(value)) density = 20;
          else if (/hdpi/i.test(value)) density = 15;
          else if (/mdpi/i.test(value)) density = 10;
          icons.push({ path: value, score: rank + density });
        }
      }
    }
  }
  labels.sort((a, b) => b.score - a.score);
  icons.sort((a, b) => b.score - a.score);
  return {
    label: labels[0]?.value || null,
    iconPath: icons[0]?.path || null,
    debug: {
      globalStrings: global.length,
      typeChunks: types.length,
      labelCandidates: labels.slice(0, 3).map((x) => x.value),
      iconCandidates: icons.slice(0, 3).map((x) => x.path),
    },
  };
}

/* ---------- ZIP（整包回退用） ---------- */

async function inflateRaw(bytes) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("浏览器不支持 deflate-raw 解压（需要 Chrome / Edge 103+）");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** 从 APK 的 Blob 里取一个条目（只切片读取需要的部分，不整包解压） */
export async function unzipEntry(blob, wanted) {
  const size = blob.size;
  const tailLen = Math.min(size, 262144);
  const tail = new Uint8Array(await blob.slice(size - tailLen).arrayBuffer());
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (u32(tail, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("APK 里找不到 ZIP 结尾记录");
  const cdSize = u32(tail, eocd + 12);
  const cdOffset = u32(tail, eocd + 16);
  const count = u16(tail, eocd + 10);
  const inTail = cdOffset - (size - tailLen);
  const cd = inTail >= 0 && inTail + cdSize <= tail.length
    ? tail.subarray(inTail, inTail + cdSize)
    : new Uint8Array(await blob.slice(cdOffset, cdOffset + cdSize).arrayBuffer());

  const decoder = new TextDecoder();
  let p = 0;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cd.length || u32(cd, p) !== 0x02014b50) break;
    const method = u16(cd, p + 10);
    const compSize = u32(cd, p + 20);
    const nameLen = u16(cd, p + 28);
    const extraLen = u16(cd, p + 30);
    const commentLen = u16(cd, p + 32);
    const local = u32(cd, p + 42);
    const name = decoder.decode(cd.subarray(p + 46, p + 46 + nameLen));
    if (name === wanted) {
      const head = new Uint8Array(await blob.slice(local, local + 30).arrayBuffer());
      if (u32(head, 0) !== 0x04034b50) throw new Error("APK 局部文件头损坏");
      const start = local + 30 + u16(head, 26) + u16(head, 28);
      const data = new Uint8Array(await blob.slice(start, start + compSize).arrayBuffer());
      if (method === 0) return data;
      if (method === 8) return inflateRaw(data);
      throw new Error(`APK 条目用了不支持的压缩方式 ${method}`);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

/* ---------- 编码 ---------- */

function maybeBase64Bytes(text) {
  const clean = String(text || "").replace(/\s+/g, "");
  if (clean.length < 16 || clean.length > 24 * 1024 * 1024) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;
  try {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToBase64(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192));
  return btoa(s);
}

function iconDataUrl(bytes, path) {
  if (!bytes?.length) return null;
  const mime = /\.webp$/i.test(path) ? "image/webp" : /\.jpe?g$/i.test(path) ? "image/jpeg" : "image/png";
  // 太大的图标不做 data URL，免得一张图把缓存和列表都拖慢
  if (bytes.length > 400_000) return null;
  return `data:${mime};base64,${bytesToBase64(bytes)}`;
}

/* ---------- aapt 捷径 ---------- */

function parseBadging(text) {
  let label = null;
  let zhLabel = null;
  let iconPath = null;
  let iconSize = -1;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    let m = line.match(/^application-label-zh(?:-CN|-TW|-HK)?:\s*'((?:[^'\\]|\\.)*)'/);
    if (m) { zhLabel = m[1].replace(/\\'/g, "'"); continue; }
    m = line.match(/^application-label:\s*'((?:[^'\\]|\\.)*)'/);
    if (m) { label = m[1].replace(/\\'/g, "'"); continue; }
    m = line.match(/^application-icon-(\d+):\s*'([^']+)'/);
    if (m && +m[1] > iconSize) { iconSize = +m[1]; iconPath = m[2]; }
  }
  return { label: zhLabel || label, iconPath };
}

/* ---------- 设备能力探测 ---------- */

/**
 * 只跑一次，把设备到底有没有 aapt / unzip / base64 写进详细日志。
 * 顺便取一段 dumpsys 样本，确认这个 ROM 有没有直接给 label（有的话以后能省掉解析）。
 */
export async function probeDevice(service, log) {
  const script =
    "echo __AAPT__; (aapt version 2>&1 || true) | head -2; " +
    "echo __UNZIP__; (unzip 2>&1 || true) | head -2; " +
    "echo __B64__; (printf gjwtest | base64 2>&1 || true) | head -2; " +
    "echo __DUMP__; (dumpsys package com.android.settings 2>/dev/null | grep -iE 'nonLocalizedLabel|labelRes|application-icon' | head -8); " +
    "echo __END__";
  let raw = "";
  try {
    raw = await service.text(script, { log: false, allowFailure: true });
  } catch (error) {
    log(`[识别] 能力探测失败：${error?.message || error}`, "err");
  }
  const section = (from, to) => {
    const start = raw.indexOf(`__${from}__`);
    const end = raw.indexOf(`__${to}__`, start + 1);
    return start < 0 ? "" : raw.slice(start + from.length + 4, end < 0 ? raw.length : end).trim();
  };
  const aaptText = section("AAPT", "UNZIP");
  const unzipText = section("UNZIP", "B64");
  const b64Text = section("B64", "DUMP");
  const dumpText = section("DUMP", "END");
  const usable = (s) => !!s && !/not found|No such file|inaccessible|unknown command/i.test(s);
  const caps = {
    aapt: usable(aaptText) && /aapt|Asset Packaging Tool/i.test(aaptText) ? "aapt" : null,
    unzip: usable(unzipText) && /unzip|usage|BusyBox|toybox/i.test(unzipText) ? "unzip" : null,
    base64: /Z2p3dGVzdA==|Z2p3dGVzdAo=/.test(b64Text) ? "base64" : null,
    dumpSample: dumpText.slice(0, 400),
    raw: raw.slice(0, 900),
  };
  log(`[识别] 设备能力：aapt=${caps.aapt || "无"} unzip=${caps.unzip || "无"} base64=${caps.base64 || "无"}`, "dim");
  log(`[识别] 探测原始输出：${caps.raw.replace(/\r?\n/g, " | ")}`, "dim");
  if (!caps.unzip || !caps.base64) log("[识别] 将改用 ADB 整包读取（慢一些，但一定能拿到资源表）", "dim");
  return caps;
}

/* ---------- 主流程 ---------- */

/**
 * 解析单个应用。返回 { label, iconPath, icon(data URL), source, debug }
 * 调用方负责 catch；这里所有关键步骤都留了日志线索。
 */
export async function resolveAppMeta({ service, driver, pkg, caps, log = () => {} }) {
  const paths = await service.paths(pkg); // pm path，已卸载的包会在这里抛错
  const apk = paths.find((p) => /base\.apk$/i.test(p)) || paths[0];
  if (!apk) throw new Error("没有拿到 APK 路径");

  let blob = null;
  const readEntry = async (entry) => {
    if (caps.unzip && caps.base64) {
      const cmd = `${caps.unzip} -p ${GJ.quote(apk)} ${GJ.quote(entry)} | ${caps.base64}`;
      const out = await service.text(cmd, { log: false, allowFailure: true });
      const bytes = maybeBase64Bytes(out);
      if (bytes) return bytes;
      log(`[识别] ${pkg}：设备端取 ${entry} 没拿到 base64（前 80 字：${String(out).slice(0, 80).replace(/\r?\n/g, " ")}），改走整包`, "dim");
    }
    if (!blob) {
      // 整包模式很慢，先问一句大小：超大 APK 直接跳过，别把整条识别拖死
      const sizeText = await service.text(`stat -c %s ${GJ.quote(apk)} 2>/dev/null`, { log: false, allowFailure: true });
      const size = parseInt(String(sizeText).trim(), 10);
      if (Number.isFinite(size) && size > 80 * 1024 * 1024) {
        throw new Error(`APK 有 ${Math.round(size / 1048576)}MB，整包模式跳过（设备端 unzip 不可用时才会这样）`);
      }
      blob = await driver.read(apk);
      log(`[识别] ${pkg}：整包读取 ${blob.size} 字节`, "dim");
    }
    return unzipEntry(blob, entry);
  };

  // 有的 ROM 自带 aapt，一行就够，不用解二进制
  if (caps.aapt) {
    try {
      const badging = await service.text(`${caps.aapt} dump badging ${GJ.quote(apk)} 2>/dev/null | head -80`, { log: false, allowFailure: true });
      const parsed = parseBadging(badging);
      if (parsed.label) {
        log(`[识别] ${pkg}：aapt 直接给出「${parsed.label}」`, "dim");
        let icon = null;
        if (parsed.iconPath) icon = iconDataUrl(await readEntry(parsed.iconPath), parsed.iconPath);
        return { label: parsed.label, iconPath: parsed.iconPath, icon, source: "aapt", debug: {} };
      }
      log(`[识别] ${pkg}：aapt 没有给出 label，改解 resources.arsc`, "dim");
    } catch (error) {
      log(`[识别] ${pkg}：aapt 失败（${error?.message || error}），改解 resources.arsc`, "dim");
    }
  }

  const arsc = await readEntry("resources.arsc");
  if (!arsc) throw new Error("APK 里找不到 resources.arsc");
  const meta = parseArsc(arsc);
  log(
    `[识别] ${pkg}：资源表 ${arsc.length} 字节，全局串 ${meta.debug.globalStrings}，类型块 ${meta.debug.typeChunks}，` +
      `名称候选 ${JSON.stringify(meta.debug.labelCandidates)}，图标候选 ${JSON.stringify(meta.debug.iconCandidates)}`,
    "dim"
  );
  let icon = null;
  if (meta.iconPath) {
    try {
      icon = iconDataUrl(await readEntry(meta.iconPath), meta.iconPath);
    } catch (error) {
      log(`[识别] ${pkg}：图标 ${meta.iconPath} 读取失败（${error?.message || error}）`, "dim");
    }
  }
  return { ...meta, icon, source: "arsc" };
}

/* ---------- 缓存 ---------- */

let cache = null;
export function metaCache() {
  if (!cache) {
    try { cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}") || {}; }
    catch { cache = {}; }
  }
  return cache;
}

export function getCachedMeta(pkg) {
  return metaCache()[pkg] || null;
}

export function saveMeta(pkg, meta) {
  const all = metaCache();
  all[pkg] = {
    label: meta.label || null,
    icon: meta.icon && meta.icon.length < 16000 ? meta.icon : null,
    at: Date.now(),
  };
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(all));
  } catch {
    // 配额满了：把所有图标丢掉，名称留着，至少识别结果还在
    for (const key of Object.keys(all)) all[key].icon = null;
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(all)); } catch {}
  }
  return all[pkg];
}

export function clearMetaCache() {
  cache = {};
  try { localStorage.removeItem(CACHE_KEY); } catch {}
}

export default { parseArsc, unzipEntry, probeDevice, resolveAppMeta, getCachedMeta, saveMeta, clearMetaCache, metaCache };
