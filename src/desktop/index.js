/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

桌面窗口管理：投屏画面铺底当「桌面」，工具窗口浮在上面。
三条硬规矩，全是踩过坑换来的：

1. 桌面层 pointer-events:none，只有窗口自身 auto。之前有一层透明容器盖在
   画面上，鼠标点平板全被吞掉；这里连窗口内的 pointer 事件也在冒泡阶段
   截断，拖标题栏绝不会漏到画面的触摸注入上。
2. 窗口一律用 left/top 定位，绝不用 transform。文件预览的 .pv.max 是
   position:fixed，祖先一旦有 transform 就会被限制在窗口里，盖不满整屏。
3. 最小化只隐藏 DOM，不销毁面板：终端的 shell 会话、文件的当前目录、
   应用列表都留着，任务栏点一下就回来。
*/

const STORE_KEY = "relive.desktop.v1";

function clamp(value, lo, hi) {
  return Math.max(lo, Math.min(hi, value));
}

/**
 * @param {object} opts
 * @param {HTMLElement} opts.layer      桌面层（覆盖 main，pointer-events:none）
 * @param {HTMLElement} opts.taskbar    底部任务栏
 * @param {Array} opts.tools            工具定义，见下
 * @param {Function} opts.log
 *
 * tool = {
 *   id, title, mark, color, host, width, height, minWidth, minHeight,
 *   onMount(host)      → 首次打开时挂载面板，返回面板对象（之后会回传）
 *   onOpen(panel)      → 每次打开 / 恢复时调用
 *   onClose(panel)     → 真正关闭窗口时收尾
 *   onResize(panel)    → 窗口尺寸变化（终端靠它重排行列）
 *   onEscape(panel)    → 返回 true 表示 Esc 被面板自己吃了，不要关窗
 * }
 */
export function createDesktop({ layer, taskbar, tools = [], log = () => {} }) {
  const byId = new Map(tools.map((tool) => [tool.id, tool]));
  const wins = new Map();
  let zTop = 20;
  let activeId = null;
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem(STORE_KEY) || "{}") || {};
  } catch {
    saved = {};
  }

  const startBtn = taskbar.querySelector("#startBtn");
  const startMenu = taskbar.querySelector("#startMenu");
  const taskButtons = taskbar.querySelector("#taskButtons");
  const trayDevice = taskbar.querySelector("#trayDevice");
  const trayBattery = taskbar.querySelector("#trayBattery");
  const trayClock = taskbar.querySelector("#trayClock");

  /* 声音开关（喇叭按钮）：音频可用时才显示，点击静音/取消静音 */
  const trayAudio = document.createElement("button");
  trayAudio.id = "trayAudio";
  trayAudio.hidden = true;
  trayAudio.textContent = "🔊";
  trayAudio.title = "声音";
  trayAudio.style.cssText =
    "background:transparent;border:none;color:inherit;cursor:pointer;font-size:14px;padding:0 6px;line-height:1;";
  if (trayClock && trayClock.parentElement) {
    trayClock.parentElement.insertBefore(trayAudio, trayClock);
  }
  if (window.ReLive && window.ReLive.setAudioStateCb) {
    window.ReLive.setAudioStateCb((s) => {
      if (!s) return;
      if (s.error) {
        trayAudio.hidden = false;
        trayAudio.textContent = "🔇";
        trayAudio.title = "声音：" + s.error;
        return;
      }
      trayAudio.hidden = !s.available;
      trayAudio.textContent = s.muted ? "🔇" : "🔊";
      trayAudio.title = s.muted ? "声音已静音（点击开启）" : "声音开启（点击静音）";
    });
  }
  trayAudio.addEventListener("click", () => {
    if (!window.ReLive || !window.ReLive.toggleAudioMuted) return;
    const muted = window.ReLive.toggleAudioMuted();
    trayAudio.textContent = muted ? "🔇" : "🔊";
  });

  /* ---------- 位置记忆 ---------- */
  function persist() {
    for (const [id, win] of wins) {
      if (win.maximized) continue; // 最大化时是满屏尺寸，别把旧位置冲掉
      saved[id] = {
        left: win.el.offsetLeft,
        top: win.el.offsetTop,
        width: win.el.offsetWidth,
        height: win.el.offsetHeight,
      };
    }
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(saved));
    } catch {
      /* 配额满就算了，不影响使用 */
    }
  }

  /* ---------- 任务栏 ---------- */
  function hideStart() {
    if (startMenu) startMenu.hidden = true;
    if (startBtn) startBtn.classList.remove("on");
  }
  function renderTaskbar() {
    if (!taskButtons) return;
    taskButtons.replaceChildren();
    for (const [id, win] of wins) {
      const tool = byId.get(id);
      const btn = document.createElement("button");
      btn.className = "tb-task" + (id === activeId && !win.minimized ? " on" : "");
      const mark = document.createElement("span");
      mark.className = "tb-mark";
      mark.textContent = tool?.mark || "·";
      if (tool?.color) mark.style.background = tool.color;
      const label = document.createElement("span");
      label.className = "tb-label";
      label.textContent = tool?.title || id;
      btn.append(mark, label);
      btn.title = win.minimized ? "恢复窗口" : "最小化 / 置顶";
      btn.addEventListener("click", () => toggle(id));
      taskButtons.appendChild(btn);
    }
  }
  function renderStartMenu() {
    if (!startMenu) return;
    startMenu.replaceChildren();
    const head = document.createElement("div");
    head.className = "tb-start-head";
    head.textContent = "设备工具";
    startMenu.appendChild(head);
    for (const tool of tools) {
      const item = document.createElement("button");
      item.className = "tb-start-item";
      const mark = document.createElement("span");
      mark.className = "tb-mark";
      mark.textContent = tool.mark || "·";
      if (tool.color) mark.style.background = tool.color;
      const text = document.createElement("span");
      text.textContent = tool.title;
      item.append(mark, text);
      item.addEventListener("click", () => {
        hideStart();
        open(tool.id);
      });
      startMenu.appendChild(item);
    }
  }
  if (startBtn && startMenu) {
    startBtn.addEventListener("click", () => {
      const show = startMenu.hidden;
      startMenu.hidden = !show;
      startBtn.classList.toggle("on", show);
    });
    document.addEventListener("pointerdown", (event) => {
      if (startMenu.hidden) return;
      if (startMenu.contains(event.target) || startBtn.contains(event.target)) return;
      hideStart();
    });
  }
  renderStartMenu();

  /* 视口变窄 / 专注模式切换后，把越界窗口拉回可视区，别让右半截被裁掉 */
  const layerRo = new ResizeObserver(() => {
    for (const win of wins.values()) {
      if (win.maximized) {
        applyRect(win, { left: 0, top: 0, width: layer.clientWidth, height: layer.clientHeight });
        continue;
      }
      const w = Math.min(win.el.offsetWidth, layer.clientWidth);
      const h = Math.min(win.el.offsetHeight, layer.clientHeight);
      win.el.style.width = w + "px";
      win.el.style.height = h + "px";
      // 桌面层 overflow:hidden 会裁掉超出的部分，缩窄视口时把窗口完整拉回来
      win.el.style.left = clamp(win.el.offsetLeft, 0, Math.max(0, layer.clientWidth - w)) + "px";
      win.el.style.top = clamp(win.el.offsetTop, 0, Math.max(0, layer.clientHeight - h)) + "px";
    }
  });
  layerRo.observe(layer);

  /* 托盘时钟（每秒一次，纯本地，不碰设备连接） */
  const clockTimer = setInterval(() => {
    if (trayClock) trayClock.textContent = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  }, 1000);
  if (trayClock) trayClock.textContent = new Date().toLocaleTimeString("zh-CN", { hour12: false });

  /* ---------- 窗口 ---------- */
  function focus(id) {
    const win = wins.get(id);
    if (!win) return;
    win.el.style.zIndex = String(++zTop);
    activeId = id;
    renderTaskbar();
  }

  function applyRect(win, rect) {
    win.el.style.left = Math.round(rect.left) + "px";
    win.el.style.top = Math.round(rect.top) + "px";
    win.el.style.width = Math.round(rect.width) + "px";
    win.el.style.height = Math.round(rect.height) + "px";
  }

  function makeWindow(tool) {
    const el = document.createElement("div");
    el.className = "dw";
    el.dataset.id = tool.id;
    el.innerHTML = `
      <div class="dw-bar">
        <span class="dw-mark"></span>
        <span class="dw-title"></span>
        <span class="dw-spacer"></span>
        <button class="dw-act" data-act="min" title="最小化（收进任务栏，不关会话）">—</button>
        <button class="dw-act" data-act="max" title="最大化 / 还原">□</button>
        <button class="dw-act" data-act="close" title="关闭窗口">×</button>
      </div>
      <div class="dw-body"></div>
      <div class="dw-grip" title="拖动调整大小"></div>`;
    const mark = el.querySelector(".dw-mark");
    mark.textContent = tool.mark || "·";
    if (tool.color) mark.style.background = tool.color;
    el.querySelector(".dw-title").textContent = tool.title;

    const body = el.querySelector(".dw-body");
    const bar = el.querySelector(".dw-bar");
    const grip = el.querySelector(".dw-grip");

    const win = {
      id: tool.id,
      el,
      body,
      panel: null,
      minimized: false,
      maximized: false,
      restoreRect: null,
    };

    /* 冒泡阶段截断：面板内部元素先正常处理，事件不会再冒到 document / 画面 */
    el.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
      focus(tool.id);
    });

    /* 拖标题栏 */
    bar.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".dw-act")) return;
      event.preventDefault();
      event.stopPropagation();
      focus(tool.id);
      if (win.maximized) return;
      const startX = event.clientX;
      const startY = event.clientY;
      const left0 = el.offsetLeft;
      const top0 = el.offsetTop;
      try {
        bar.setPointerCapture(event.pointerId);
      } catch {
        /* 某些浏览器不支持，退化为普通监听也能用 */
      }
      const move = (e) => {
        e.stopPropagation();
        el.style.left =
          clamp(left0 + e.clientX - startX, 0, Math.max(0, layer.clientWidth - 150)) + "px";
        el.style.top =
          clamp(top0 + e.clientY - startY, 0, Math.max(0, layer.clientHeight - 40)) + "px";
      };
      const up = () => {
        bar.removeEventListener("pointermove", move);
        bar.removeEventListener("pointerup", up);
        bar.removeEventListener("pointercancel", up);
        persist();
      };
      bar.addEventListener("pointermove", move);
      bar.addEventListener("pointerup", up);
      bar.addEventListener("pointercancel", up);
    });

    /* 双击标题栏 = 最大化 / 还原 */
    bar.addEventListener("dblclick", (event) => {
      if (event.target.closest(".dw-act")) return;
      event.preventDefault();
      toggleMax(tool.id);
    });

    /* 右下角缩放 */
    grip.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      event.stopPropagation();
      focus(tool.id);
      if (win.maximized) return;
      const startX = event.clientX;
      const startY = event.clientY;
      const w0 = el.offsetWidth;
      const h0 = el.offsetHeight;
      const left = el.offsetLeft;
      const top = el.offsetTop;
      try {
        grip.setPointerCapture(event.pointerId);
      } catch {}
      const move = (e) => {
        e.stopPropagation();
        const w = clamp(w0 + e.clientX - startX, tool.minWidth || 460, Math.max(460, layer.clientWidth - left));
        const h = clamp(h0 + e.clientY - startY, tool.minHeight || 320, Math.max(320, layer.clientHeight - top));
        el.style.width = Math.round(w) + "px";
        el.style.height = Math.round(h) + "px";
      };
      const up = () => {
        grip.removeEventListener("pointermove", move);
        grip.removeEventListener("pointerup", up);
        grip.removeEventListener("pointercancel", up);
        persist();
      };
      grip.addEventListener("pointermove", move);
      grip.addEventListener("pointerup", up);
      grip.addEventListener("pointercancel", up);
    });

    /* 标题栏三个按钮 */
    bar.addEventListener("click", (event) => {
      const act = event.target.closest(".dw-act")?.dataset.act;
      if (!act) return;
      event.stopPropagation();
      if (act === "min") minimize(tool.id);
      else if (act === "max") toggleMax(tool.id);
      else if (act === "close") close(tool.id);
    });

    /* 尺寸变了通知面板（终端靠这个重排行列） */
    const ro = new ResizeObserver(() => {
      if (!win.panel || win.minimized || !el.isConnected) return;
      try {
        byId.get(tool.id)?.onResize?.(win.panel);
      } catch (error) {
        log(`[桌面] ${tool.title} 重排失败：${error?.message || error}`, "dim");
      }
    });
    ro.observe(body);
    win.ro = ro;

    return win;
  }

  function open(id) {
    const tool = byId.get(id);
    if (!tool) return null;
    const existing = wins.get(id);
    if (existing) {
      if (existing.minimized) {
        existing.minimized = false;
        existing.el.style.display = "";
      }
      focus(id);
      try {
        tool.onOpen?.(existing.panel);
      } catch (error) {
        log(`[桌面] ${tool.title} 打开失败：${error?.message || error}`, "err");
      }
      return existing;
    }

    const win = makeWindow(tool);
    const rect0 = saved[id];
    const offset = (wins.size % 6) * 28;
    const width = clamp(rect0?.width || tool.width || 900, tool.minWidth || 460, Math.max(460, layer.clientWidth - 20));
    const height = clamp(rect0?.height || tool.height || 620, tool.minHeight || 320, Math.max(320, layer.clientHeight - 20));
    applyRect(win, {
      left: clamp(rect0?.left ?? 40 + offset, 0, Math.max(0, layer.clientWidth - 150)),
      top: clamp(rect0?.top ?? 32 + offset, 0, Math.max(0, layer.clientHeight - 40)),
      width,
      height,
    });
    win.body.appendChild(tool.host); // 面板容器搬进窗口，模块内部一行都不用改
    layer.appendChild(win.el);
    wins.set(id, win);
    focus(id);
    renderTaskbar();

    try {
      win.panel = tool.onMount?.(tool.host) || null;
      tool.onOpen?.(win.panel);
    } catch (error) {
      log(`[桌面] ${tool.title} 挂载失败：${error?.message || error}`, "err");
    }
    return win;
  }

  function minimize(id) {
    const win = wins.get(id);
    if (!win || win.minimized) return;
    win.minimized = true;
    win.el.style.display = "none";
    if (activeId === id) activeId = null;
    renderTaskbar();
  }

  function toggleMax(id) {
    const win = wins.get(id);
    if (!win) return;
    if (win.maximized) {
      win.maximized = false;
      if (win.restoreRect) applyRect(win, win.restoreRect);
      win.el.classList.remove("max");
      const btn = win.el.querySelector('[data-act="max"]');
      btn.classList.remove("on");
      btn.title = "最大化";
    } else {
      win.restoreRect = {
        left: win.el.offsetLeft,
        top: win.el.offsetTop,
        width: win.el.offsetWidth,
        height: win.el.offsetHeight,
      };
      win.maximized = true;
      win.el.classList.add("max");
      const btn = win.el.querySelector('[data-act="max"]');
      btn.classList.add("on");
      btn.title = "还原";
      applyRect(win, { left: 0, top: 0, width: layer.clientWidth, height: layer.clientHeight });
    }
    focus(id);
    persist();
  }

  function close(id) {
    const win = wins.get(id);
    if (!win) return;
    const tool = byId.get(id);
    try {
      tool?.onClose?.(win.panel);
    } catch (error) {
      log(`[桌面] ${tool?.title || id} 收尾失败：${error?.message || error}`, "dim");
    }
    win.ro?.disconnect();
    // 容器搬回隐藏的宿主区，面板实例和它内部的 DOM / 会话留着下次直接用
    if (tool?.host) document.getElementById("winHosts")?.appendChild(tool.host);
    win.el.remove();
    wins.delete(id);
    if (activeId === id) activeId = null;
    renderTaskbar();
  }

  function toggle(id) {
    const win = wins.get(id);
    if (!win) return open(id);
    if (win.minimized) return open(id);
    if (activeId === id) return minimize(id);
    focus(id);
    return win;
  }

  function closeAll() {
    [...wins.keys()].forEach(close);
    hideStart();
  }

  /** Esc：开始菜单 → 当前窗口面板自己处理 → 关最上层窗口 */
  function onEscape() {
    if (startMenu && !startMenu.hidden) {
      hideStart();
      return true;
    }
    const win = activeId && wins.get(activeId);
    if (!win || win.minimized) return false;
    let handled = false;
    try {
      handled = !!byId.get(activeId)?.onEscape?.(win.panel);
    } catch {}
    if (!handled) close(activeId);
    return true;
  }

  function setTray({ device, battery } = {}) {
    if (trayDevice && device !== undefined) trayDevice.textContent = device || "未连接";
    if (trayBattery && battery !== undefined) {
      trayBattery.textContent = battery || "";
      trayBattery.hidden = !battery;
    }
  }

  function destroy() {
    clearInterval(clockTimer);
    layerRo.disconnect();
    closeAll();
  }

  return {
    open,
    close,
    toggle,
    minimize,
    toggleMax,
    focus,
    closeAll,
    onEscape,
    setTray,
    destroy,
    has: (id) => wins.has(id),
    get: (id) => wins.get(id) || null,
    get activeId() {
      return activeId;
    },
    get count() {
      return wins.size;
    },
  };
}

export default createDesktop;
