/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

截图窗口：把主页「显示控制 → 截屏」那条实测过的 screencap 流程搬进投屏页。
不依赖主页的 GJ.Service.screenshot()，因为那条会去调软件设置里的下载目录
句柄和自动删图策略；这里只做三件事：设备端生成 PNG → ADB sync 读回 Blob
→ 删掉设备端临时文件。截图留在浏览器内存（本次会话有效），点下载才落盘。
*/

const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

export function mountScreenshotPanel({ container, getDriver, log = () => {} }) {
  container.innerHTML = `
    <div class="ss-bar">
      <span class="ss-title">截图</span>
      <button class="ss-btn primary" data-act="shot">立即截图</button>
      <button class="ss-btn" data-act="clear">清空</button>
      <span class="ss-spacer"></span>
      <span class="ss-state" id="ssState">本次会话 0 张</span>
    </div>
    <div class="ss-scroll">
      <div class="ss-grid" id="ssGrid"></div>
      <div class="ss-empty" id="ssEmpty">点「立即截图」抓一张平板画面。<br>截图只存在浏览器内存里，刷新页面会丢失，要留档记得点「下载」。</div>
    </div>`;

  const $ = (id) => container.querySelector("#" + id);
  const grid = $("ssGrid");
  const empty = $("ssEmpty");
  const stateEl = $("ssState");
  const items = [];
  let busy = false;
  let lightbox = null;
  let token = 0;

  function setState(text, kind = "") {
    stateEl.textContent = text;
    stateEl.className = "ss-state" + (kind ? " " + kind : "");
  }

  function render() {
    empty.hidden = items.length > 0;
    grid.innerHTML = items
      .map(
        (item, index) => `
      <div class="ss-item" data-i="${index}">
        <img src="${item.url}" alt="截图 ${index + 1}">
        <div class="ss-meta"><span>${esc(item.name)}</span><span>${formatSize(item.size)}</span></div>
        <div class="ss-ops">
          <button data-op="view" title="查看大图">查看</button>
          <button data-op="download" title="保存到电脑">下载</button>
          <button data-op="remove" title="从列表移除">移除</button>
        </div>
      </div>`
      )
      .join("");
    setState(`本次会话 ${items.length} 张`);
  }

  function closeLightbox() {
    if (!lightbox) return;
    lightbox.remove();
    lightbox = null;
    document.removeEventListener("keydown", onLightboxKey, true);
  }
  function onLightboxKey(event) {
    if (event.key !== "Escape") return;
    event.stopPropagation();
    event.preventDefault();
    closeLightbox();
  }
  function showLightbox(item) {
    closeLightbox();
    lightbox = document.createElement("div");
    lightbox.className = "ss-lightbox";
    lightbox.innerHTML = `
      <div class="ss-lightbox-bar"><span>${esc(item.name)} · ${formatSize(item.size)}</span>
        <button data-op="download">下载</button><button data-op="close">关闭（Esc）</button></div>
      <img src="${item.url}" alt="截图大图">`;
    // 挂到 body：窗口本身有 z-index，挂里面会被别的窗口盖住
    document.body.appendChild(lightbox);
    lightbox.addEventListener("click", (event) => {
      const op = event.target.closest("[data-op]")?.dataset.op;
      if (op === "download") download(item);
      if (op === "close" || event.target === lightbox) closeLightbox();
    });
    document.addEventListener("keydown", onLightboxKey, true);
  }

  function download(item) {
    const a = document.createElement("a");
    a.href = item.url;
    a.download = item.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    log(`[截图] 下载 ${item.name}（${formatSize(item.size)}）`, "dim");
  }

  async function shell(driver, command) {
    return String(
      await driver.adb.subprocess.noneProtocol.spawnWaitText([command + " 2>&1"])
    ).trim();
  }

  async function shoot() {
    if (busy) return;
    const driver = getDriver();
    if (!driver?.connected) {
      setState("设备未连接", "err");
      return;
    }
    busy = true;
    setState("正在截图…");
    const myToken = ++token;
    const remote = `/sdcard/gjw_shot_${stamp()}_${Math.random().toString(36).slice(2, 6)}.png`;
    let keepRemote = false;
    try {
      log(`[截图] 设备端执行：screencap -p ${remote}`, "dim");
      const out = await shell(driver, `screencap -p '${remote}'`);
      if (out) log(`[截图] screencap 输出：${out}`, "dim");
      const blob = await driver.read(remote);
      const head = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
      if (!PNG_SIGNATURE.every((b, i) => head[i] === b)) {
        keepRemote = true; // 留在设备上方便真机排查
        throw new Error(`读回的不是 PNG（${blob.size} 字节），原文件已保留在 ${remote}`);
      }
      const name = remote.split("/").pop();
      const item = { name, url: URL.createObjectURL(blob), size: blob.size, blob };
      items.unshift(item);
      render();
      setState(`已保存 ${items.length} 张`, "ok");
      log(`[截图] 完成：${name}（${formatSize(blob.size)}）`, "ok");
    } catch (error) {
      const message = error?.message || String(error);
      setState("截图失败：" + message, "err");
      log(`[截图] 失败：${message}`, "err");
      log(`[截图] 设备端临时文件：${remote}${keepRemote ? "（已保留）" : ""}`, "dim");
    } finally {
      if (!keepRemote) {
        try {
          await shell(getDriver(), `rm -f '${remote}'`);
          log(`[截图] 已清理设备端临时文件 ${remote}`, "dim");
        } catch (error) {
          log(`[截图] 清理临时文件失败（不影响截图）：${error?.message || error}`, "dim");
        }
      }
      if (myToken === token) busy = false;
    }
  }

  grid.addEventListener("click", (event) => {
    const card = event.target.closest(".ss-item");
    if (!card) return;
    const item = items[Number(card.dataset.i)];
    if (!item) return;
    const op = event.target.closest("[data-op]")?.dataset.op;
    if (op === "view") showLightbox(item);
    else if (op === "download") download(item);
    else if (op === "remove") {
      const index = items.indexOf(item);
      if (index >= 0) {
        URL.revokeObjectURL(item.url);
        items.splice(index, 1);
        render();
      }
    }
  });

  container.addEventListener("click", (event) => {
    const act = event.target.closest(".ss-bar [data-act]")?.dataset.act;
    if (act === "shot") shoot();
    else if (act === "clear") {
      closeLightbox();
      items.forEach((item) => URL.revokeObjectURL(item.url));
      items.length = 0;
      render();
      log("[截图] 已清空本次会话的截图", "dim");
    }
  });

  return {
    open() {},
    shoot,
    close() {
      closeLightbox();
    },
    clear() {
      closeLightbox();
      items.forEach((item) => URL.revokeObjectURL(item.url));
      items.length = 0;
      render();
    },
    onEscape() {
      if (!lightbox) return false;
      closeLightbox();
      return true;
    },
    get count() {
      return items.length;
    },
  };
}

export default mountScreenshotPanel;
