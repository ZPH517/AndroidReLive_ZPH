/*
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

输入映射：鼠标 / 键盘 / 触摸 → scrcpy 控制消息
设计原则：
 - 左键 = 手指按下，拖动 = 滑动，滚轮 = 滚动
 - 右键 = 返回，中键 = 桌面，侧键 = 最近任务
 - 键盘可打印字符走 injectText，功能键走 injectKeyCode
*/

/* Android KeyEvent 键值（只列用得上的） */
export const AndroidKey = {
  HOME: 3,
  BACK: 4,
  CALL: 5,
  ENDCALL: 6,
  VOLUME_UP: 24,
  VOLUME_DOWN: 25,
  POWER: 26,
  TAB: 61,
  ENTER: 66,
  DEL: 67,
  MENU: 82,
  ESCAPE: 111,
  FORWARD_DEL: 112,
  CTRL_LEFT: 113,
  MOVE_HOME: 122,
  MOVE_END: 123,
  PAGE_UP: 92,
  PAGE_DOWN: 93,
  SPACE: 62,
  APP_SWITCH: 187,
  ARROW_UP: 19,
  ARROW_DOWN: 20,
  ARROW_LEFT: 21,
  ARROW_RIGHT: 22,
};

/* 浏览器 KeyboardEvent.key → Android 键值 */
const KEY_MAP = {
  Enter: AndroidKey.ENTER,
  Backspace: AndroidKey.DEL,
  Delete: AndroidKey.FORWARD_DEL,
  Tab: AndroidKey.TAB,
  Escape: AndroidKey.ESCAPE,
  " ": AndroidKey.SPACE,
  ArrowUp: AndroidKey.ARROW_UP,
  ArrowDown: AndroidKey.ARROW_DOWN,
  ArrowLeft: AndroidKey.ARROW_LEFT,
  ArrowRight: AndroidKey.ARROW_RIGHT,
  Home: AndroidKey.MOVE_HOME,
  End: AndroidKey.MOVE_END,
  PageUp: AndroidKey.PAGE_UP,
  PageDown: AndroidKey.PAGE_DOWN,
};

const ACTION_DOWN = 0;
const ACTION_UP = 1;
const ACTION_MOVE = 2;
const ACTION_CANCEL = 3;
const BUTTON_PRIMARY = 1;

/* 事件计数器（每个画布一份，用于"只打前几条"） */
let eventSeq = 0;
const ACTION_NAME = { 0: "DOWN", 1: "UP", 2: "MOVE", 3: "CANCEL" };

/**
 * 给一个 canvas 绑定全套输入。
 * @param {object} ctx
 * @param {HTMLCanvasElement} ctx.canvas
 * @param {() => {width:number,height:number}} ctx.getSize 视频原始分辨率
 * @param {() => (object|null)} ctx.getController 控制通道（可能延迟就绪）
 * @param {(msg:string)=>void} [ctx.log]
 * @param {boolean} [ctx.hoverDot] 是否画本地光标点
 */
export function bindInput({ canvas, getSize, getController, log = () => {}, hoverDot = true }) {
  const disposed = { value: false };
  let pointerDown = false;

  const send = (fn) => {
    const controller = getController?.();
    if (!controller) return null;
    try {
      const result = fn(controller);
      if (result && typeof result.catch === "function") {
        result.catch((error) => log("控制消息发送失败：" + (error?.message || error)));
      }
      return result;
    } catch (error) {
      log("控制消息异常：" + (error?.message || error));
      return null;
    }
  };

  /* canvas 坐标 → 视频原始坐标 */
  const toDevice = (clientX, clientY) => {
    const rect = canvas.getBoundingClientRect();
    const size = getSize();
    if (!rect.width || !rect.height || !size?.width) return null;
    const x = Math.round((clientX - rect.left) * (size.width / rect.width));
    const y = Math.round((clientY - rect.top) * (size.height / rect.height));
    return {
      x: Math.max(0, Math.min(size.width - 1, x)),
      y: Math.max(0, Math.min(size.height - 1, y)),
      screenWidth: size.width,
      screenHeight: size.height,
    };
  };

  /**
   * 发送一条触摸消息。
   * 诊断策略：前 6 条事件（含 move 以外的全部 down/up）把浏览器原始事件和真正
   * 序列化出去的字段一起打出来。设备侧到底是"没收到 up"还是"收到了但没认"，
   * 靠这一对日志就能分开，不用猜。
   */
  const touch = (action, clientX, clientY, extra = {}) => {
    const point = toDevice(clientX, clientY);
    if (!point) {
      const rect = canvas.getBoundingClientRect();
      log(`[输入诊断] touch 被拒：rect=${rect.width}×${rect.height} size=${JSON.stringify(getSize())}`);
      return;
    }
    const controller = getController?.();
    if (!controller) {
      log(`[输入诊断] touch 被丢弃：控制通道还没就绪（action=${action}）`, "err");
      return;
    }
    const message = {
      pointerId: 0n,
      // 字段名必须严格用 pointerX/pointerY/videoWidth/videoHeight：
      // 之前传 x/y/screenWidth/screenHeight，结构体不认识这些键，
      // 坐标全部序列化成 0，server 收到 (0,0)+0×0 直接丢弃 —— 鼠标因此完全失效
      pointerX: point.x,
      pointerY: point.y,
      videoWidth: point.screenWidth,
      videoHeight: point.screenHeight,
      pressure: action === ACTION_UP ? 0 : 1,
      actionButton: action === ACTION_DOWN ? BUTTON_PRIMARY : 0,
      buttons: action === ACTION_UP || action === ACTION_CANCEL ? 0 : BUTTON_PRIMARY,
      ...extra,
    };
    const name = ACTION_NAME[action] || String(action);
    eventSeq += 1;
    // 只在前两条（一次按下+松手）用正常级别打出来：证明输入链路是通的。
    // 之后全归到详细级别，否则点几下就把右侧日志刷满。
    const important = eventSeq <= 2;
    if (important || action !== ACTION_MOVE) {
      const payload = { ...message, pointerId: String(message.pointerId) };
      log(`[输入] #${eventSeq} ${name} → ${JSON.stringify(payload)}`, important ? "" : "dim");
    }
    try {
      const result = controller.injectTouch({ action, ...message });
      if (result && typeof result.catch === "function") {
        result.catch((error) => log(`[输入] ${name} 发送失败：${error?.message || error}`, "err"));
      }
    } catch (error) {
      log(`[输入] ${name} 抛异常：${error?.message || error}`, "err");
    }
  };

  const tap = (clientX, clientY) => {
    touch(ACTION_DOWN, clientX, clientY);
    setTimeout(() => touch(ACTION_UP, clientX, clientY), 30);
  };

  /**
   * 强制结束一次"没收尾"的触摸。
   *
   * 为什么需要：如果我们发过 DOWN，而 UP 因为切标签页 / 丢焦点 / 指针捕获丢失
   * 没发出去，设备端的应用会永远停在"手指按着"的状态 —— 桌面就表现为常驻长按
   * 菜单，之后所有点击都不生效。这里发一条 CANCEL 把它收干净。
   */
  const cancelTouch = (reason) => {
    const size = getSize();
    const width = size?.width || 0;
    const height = size?.height || 0;
    if (!width || !height) return;
    pointerDown = false;
    // 直接用设备坐标，不走 client → device 的换算（CANCEL 是虚拟点，没有客户端坐标）
    const controller = getController?.();
    if (!controller) return;
    try {
      const result = controller.injectTouch({
        action: ACTION_CANCEL,
        pointerId: 0n,
        pointerX: Math.round(width / 2),
        pointerY: Math.round(height / 2),
        videoWidth: width,
        videoHeight: height,
        pressure: 0,
        actionButton: 0,
        buttons: 0,
      });
      if (result && typeof result.catch === "function") {
        result.catch((error) => log("[输入] CANCEL 发送失败：" + (error?.message || error), "err"));
      }
    } catch (error) {
      log("[输入] CANCEL 抛异常：" + (error?.message || error), "err");
    }
    if (reason) log(`[输入] 已补发 CANCEL 收尾（${reason}）`, "dim");
  };

  const key = (keyCode) => {
    send((c) => c.injectKeyCode({ action: ACTION_DOWN, keyCode, repeat: 0, metaState: 0 }));
    send((c) => c.injectKeyCode({ action: ACTION_UP, keyCode, repeat: 0, metaState: 0 }));
  };

  /* ---------- 鼠标 ---------- */

  const onPointerDown = (event) => {
    canvas.focus?.();

    // 右键 = 返回，中键 = 桌面
    if (event.button === 2) {
      event.preventDefault();
      key(AndroidKey.BACK);
      return;
    }
    if (event.button === 1) {
      event.preventDefault();
      key(AndroidKey.HOME);
      return;
    }
    if (event.button !== 0) return;

    // 上一次手势没收尾就来了新的 DOWN：设备端会一直停在"按下"，
    // 表现就是每次点击都弹长按菜单。先补 CANCEL 再开新手势。
    if (pointerDown) {
      log("[输入] 检测到上一条手势未结束，先补发 CANCEL", "dim");
      touch(ACTION_CANCEL, event.clientX, event.clientY);
    }

    pointerDown = true;
    try {
      canvas.setPointerCapture?.(event.pointerId);
    } catch (error) {
      log("[输入] setPointerCapture 失败：" + (error?.message || error), "dim");
    }
    touch(ACTION_DOWN, event.clientX, event.clientY);
  };

  const onPointerMove = (event) => {
    moveDot(event.clientX, event.clientY);
    if (!pointerDown) return;
    touch(ACTION_MOVE, event.clientX, event.clientY);
  };

  const onPointerUp = (event) => {
    if (!pointerDown) return;
    pointerDown = false;
    touch(ACTION_UP, event.clientX, event.clientY);
  };

  /* 兜底：指针捕获丢失 / 窗口失焦 / 页面切走时，UP 可能永远不到，
     设备端就会卡在"手指按着"。 */
  const onLostCapture = () => {
    if (pointerDown) cancelTouch("指针捕获丢失");
  };
  const onWindowBlur = () => {
    if (pointerDown) cancelTouch("窗口失去焦点");
  };
  const onVisibility = () => {
    if (document.hidden && pointerDown) cancelTouch("页面切到后台");
  };

  const onContextMenu = (event) => event.preventDefault();

  /* 滚轮：把像素增量折算成 0-1 的相对量，小步累积避免一滚就飞 */
  let scrollAccum = 0;
  const onWheel = (event) => {
    event.preventDefault();
    const point = toDevice(event.clientX, event.clientY);
    if (!point) return;

    scrollAccum += event.deltaY;
    const step = event.deltaMode === 1 ? 16 : 1;
    const threshold = 40 * step;
    if (Math.abs(scrollAccum) < threshold && !event.shiftKey) return;

    const amount = Math.max(-1, Math.min(1, scrollAccum / 400));
    scrollAccum = 0;
    if (!bindInput._scrollLogged) {
      bindInput._scrollLogged = true;
      // 3.3.1 的 ScrollController 内部会把值再除以 16，先把这个实际值打出来，
      // 滚动量不对时直接调这里，不用再猜
      log(`[输入诊断] 首次滚轮：scrollY=${-amount.toFixed(3)}（库内部还会 ÷16）`);
    }
    send((controller) =>
      controller.injectScroll({
        // 与 injectTouch 同理：字段名必须是 pointerX/pointerY/videoWidth/videoHeight
        pointerX: point.x,
        pointerY: point.y,
        videoWidth: point.screenWidth,
        videoHeight: point.screenHeight,
        scrollX: event.shiftKey ? -amount : 0,
        scrollY: event.shiftKey ? 0 : -amount,
        buttons: 0,
      })
    );
  };

  /* ---------- 键盘 ---------- */

  const onKeyDown = (event) => {
    if (event.isComposing) return; // 输入法组合中，交给 injectText 的 compositionend

    // Ctrl / Alt / Meta 组合键不拦，留给浏览器
    if (event.ctrlKey || event.metaKey) return;

    const mapped = KEY_MAP[event.key];
    if (mapped !== undefined) {
      event.preventDefault();
      send((c) => c.injectKeyCode({ action: ACTION_DOWN, keyCode: mapped, repeat: 0, metaState: 0 }));
      send((c) => c.injectKeyCode({ action: ACTION_UP, keyCode: mapped, repeat: 0, metaState: 0 }));
      return;
    }

    // 单字符：ASCII 走 injectText
    if (event.key.length === 1) {
      if (event.key.charCodeAt(0) < 128) {
        event.preventDefault();
        send((c) => c.injectText(event.key));
      } else {
        log("中文等非 ASCII 字符无法直接注入，请在平板上用输入法");
      }
    }
  };

  /* ---------- 本地光标点（纯视觉反馈） ---------- */
  let dot = null;
  function moveDot(x, y) {
    if (!hoverDot) return;
    if (!dot) {
      dot = document.createElement("div");
      dot.className = "gjw-cursor-dot";
      canvas.parentElement.style.position = canvas.parentElement.style.position || "relative";
      canvas.parentElement.appendChild(dot);
    }
    const rect = canvas.getBoundingClientRect();
    const parentRect = canvas.parentElement.getBoundingClientRect();
    dot.style.left = x - parentRect.left + "px";
    dot.style.top = y - parentRect.top + "px";
    dot.style.opacity = "1";
    clearTimeout(dot._timer);
    dot._timer = setTimeout(() => {
      if (dot) dot.style.opacity = "0";
    }, 1200);
  }

  canvas.addEventListener("pointerdown", onPointerDown);
  canvas.addEventListener("pointermove", onPointerMove);
  canvas.addEventListener("pointerup", onPointerUp);
  canvas.addEventListener("pointercancel", onPointerUp);
  canvas.addEventListener("lostpointercapture", onLostCapture);
  canvas.addEventListener("contextmenu", onContextMenu);
  canvas.addEventListener("wheel", onWheel, { passive: false });
  canvas.addEventListener("keydown", onKeyDown);
  window.addEventListener("blur", onWindowBlur);
  document.addEventListener("visibilitychange", onVisibility);
  canvas.setAttribute("tabindex", "0");
  canvas.style.outline = "none";

  // 连上之后先投一条 CANCEL：上一次会话（或刷新页面）如果留下"没松手"的触摸，
  // 设备端会一直停在按下状态 —— 每点一下都弹长按菜单就是这么来的。
  const resetTimer = setTimeout(() => {
    log("[输入] 发送 CANCEL 清理可能残留的触摸状态", "dim");
    cancelTouch();
  }, 500);

  return {
    /** 外部触发点击（用于按钮栏：返回/桌面/任务） */
    tap,
    key,
    /** 手动清一次卡住的触摸（顶栏按钮走这里） */
    cancelTouch,
    dispose() {
      disposed.value = true;
      clearTimeout(resetTimer);
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("pointercancel", onPointerUp);
      canvas.removeEventListener("lostpointercapture", onLostCapture);
      canvas.removeEventListener("contextmenu", onContextMenu);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("blur", onWindowBlur);
      document.removeEventListener("visibilitychange", onVisibility);
      // 关会话前先松手，否则这条触摸永远留在设备上
      if (pointerDown) cancelTouch();
      dot?.remove();
      dot = null;
    },
  };
}
