/**
 * ADB 终端面板（投屏页内浮层）
 *
 * 交互内核复用 js/core/terminal.js 的 GJTerminal.Controller：
 *   - xterm.js 渲染、Ctrl+C 中断 / 复制、窗口尺寸变化自动 resize、会话退出提示
 *   - driver.openTerminal() 开一条 ADB shell pty（ADB 支持多路复用，和投屏并存）
 * 主页那份文件一行不改，避免把已经跑通的终端弄坏。
 *
 * 这一层只补三样主页没有的：
 *   1. 常用命令一键执行（都是只读命令，点一下直接跑）
 *   2. 底部命令输入框 + ↑↓ 历史，历史存浏览器本地
 *   3. 状态栏 / 复制 / 清屏 / 中断 / 重开会话，并把关键动作写进「详细日志」
 *
 * 注意：Esc 不用于关闭本面板。终端里 Esc 是有效按键（vi、less、readline
 * 都要用），抢走会很难用；关闭走「✕ 关闭」按钮或点遮罩。
 */
import { GJTerminal } from "../../js/core/terminal.js";

const HISTORY_KEY = "relive.termHistory";
const HISTORY_MAX = 60;

/** 都是只读命令，点一下直接执行；要改参数可以先填进输入框再回车 */
const PRESETS = [
  ["机型", "getprop ro.product.model"],
  ["安卓版本", "getprop ro.build.version.release"],
  ["第三方应用", "pm list packages -3"],
  ["系统应用", "pm list packages -s"],
  ["电量", "dumpsys battery"],
  ["存储", "df -h /sdcard"],
  ["分辨率", "wm size"],
  ["当前界面", "dumpsys window | grep mCurrentFocus"],
  ["最近日志", "logcat -d -t 200"],
];

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);

function loadHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(value) ? value.filter((x) => typeof x === "string").slice(-HISTORY_MAX) : [];
  } catch {
    return [];
  }
}

export function mountTerminalPanel({ container, getDriver, log = () => {}, onClose = () => {} }) {
  container.innerHTML = `
    <div class="tm-bar">
      <span class="tm-title">ADB 终端</span>
      <span class="tm-state" id="tmState">终端未连接</span>
      <span class="tm-spacer"></span>
      <button class="tm-btn" data-act="copy" title="复制终端里的文字（有选中内容时只复制选中部分）">复制</button>
      <button class="tm-btn" data-act="clear" title="清空屏幕显示，不影响设备上的进程">清屏</button>
      <button class="tm-btn" data-act="interrupt" id="tmInterrupt" disabled title="发送 Ctrl+C 中断当前命令">中断</button>
      <button class="tm-btn" data-act="restart" id="tmRestart" disabled title="结束当前会话，重新开一个 shell">重开会话</button>
      <button class="tm-btn ghost" data-act="close" title="关闭面板（Esc 留给终端使用）">✕ 关闭</button>
    </div>
    <div class="tm-presets">
      <span class="tm-label">常用命令</span>
      ${PRESETS.map(([name, cmd], i) => `<button class="tm-chip" data-preset="${i}" title="${esc(cmd)}">${esc(name)}</button>`).join("")}
    </div>
    <div class="tm-screen" id="tmOutput"></div>
    <div class="tm-input">
      <span class="tm-prompt">$</span>
      <input id="tmCmd" placeholder="输入 shell 命令，回车执行；↑↓ 翻历史" autocomplete="off" spellcheck="false">
      <button class="tm-btn primary" data-act="run">执行</button>
    </div>
    <div class="tm-foot">
      <span>命令直接跑在设备上，删除 / 刷写类操作请先确认；Ctrl+C 中断，Ctrl+Shift+C 复制</span>
      <span>↑↓ 翻历史 · Esc 留给终端，点「✕ 关闭」退出</span>
    </div>
  `;

  const stateEl = container.querySelector("#tmState");
  const cmdEl = container.querySelector("#tmCmd");
  const interruptBtn = container.querySelector("#tmInterrupt");
  const restartBtn = container.querySelector("#tmRestart");

  let history = loadHistory();
  let historyIndex = history.length;
  let opening = null;

  function setState(text, kind = "") {
    stateEl.textContent = text;
    stateEl.className = "tm-state" + (kind ? " " + kind : "");
  }

  function saveHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // 隐私模式下写不进去就算了，不影响终端本身
    }
  }

  const controller = new GJTerminal.Controller({
    element: container.querySelector("#tmOutput"),
    onState: (message) => {
      if (message !== undefined) {
        const kind = /失败|关闭|结束|出错/.test(message) ? "err" : message === "Android shell" ? "ok" : "";
        setState(message, kind);
      }
      interruptBtn.disabled = !controller.active;
      restartBtn.disabled = !getDriver()?.connected;
    },
    onError: (error) => {
      const message = error?.message || String(error);
      setState("终端出错：" + message, "err");
      log("[终端] 会话异常：" + message, "err");
    },
  });

  /** 打开（或复用）设备上的 shell 会话；同一时刻只允许一次连接尝试 */
  async function ensureSession() {
    const driver = getDriver();
    if (!driver?.connected) {
      setState("设备未连接", "err");
      return false;
    }
    if (controller.active) return true;
    if (opening) return opening;
    if (!globalThis.Terminal || !globalThis.FitAddon?.FitAddon) {
      const message = "xterm.js / addon-fit.js 未加载，请检查 index.html 的脚本引用";
      setState("终端组件未加载", "err");
      log("[终端] " + message, "err");
      return false;
    }
    opening = (async () => {
      try {
        setState("正在连接终端…");
        await controller.open(driver);
        log("[终端] 已打开设备 shell 会话", "dim");
        return true;
      } catch (error) {
        const message = error?.message || String(error);
        setState("连接失败：" + message, "err");
        log("[终端] 打开 shell 失败：" + message, "err");
        return false;
      } finally {
        opening = null;
        restartBtn.disabled = !getDriver()?.connected;
      }
    })();
    return opening;
  }

  async function runCommand(raw) {
    const command = String(raw ?? "").trim();
    if (!command) return;
    if (!(await ensureSession())) return;
    // pty 里是交互式 shell，补回车才会执行；\n 在部分 ROM 上不触发
    controller.send(command + "\r");
    log("[终端] $ " + command, "dim");
    if (history[history.length - 1] !== command) history.push(command);
    if (history.length > HISTORY_MAX) history.shift();
    saveHistory();
    historyIndex = history.length;
    cmdEl.value = "";
  }

  container.addEventListener("click", async (event) => {
    const preset = event.target.closest("[data-preset]");
    if (preset) {
      const command = PRESETS[Number(preset.dataset.preset)]?.[1];
      if (command) {
        cmdEl.value = command;
        await runCommand(command);
        cmdEl.value = "";
      }
      return;
    }
    const button = event.target.closest("[data-act]");
    if (!button) return;
    switch (button.dataset.act) {
      case "close":
        onClose();
        break;
      case "run":
        await runCommand(cmdEl.value);
        break;
      case "clear":
        controller.clear();
        break;
      case "interrupt":
        controller.interrupt();
        break;
      case "restart":
        controller.close();
        await ensureSession();
        break;
      case "copy":
        try {
          await navigator.clipboard.writeText(controller.text());
          setState("已复制终端内容", "ok");
          setTimeout(() => {
            if (controller.active) setState("Android shell", "ok");
          }, 1800);
        } catch (error) {
          setState("复制失败：" + (error?.message || error), "err");
        }
        break;
      default:
        break;
    }
  });

  cmdEl.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      void runCommand(cmdEl.value);
    } else if (event.key === "ArrowUp") {
      if (!history.length) return;
      event.preventDefault();
      historyIndex = Math.max(0, historyIndex - 1);
      cmdEl.value = history[historyIndex] ?? "";
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      historyIndex = Math.min(history.length, historyIndex + 1);
      cmdEl.value = historyIndex === history.length ? "" : history[historyIndex] ?? "";
    }
  });

  return {
    /** 面板显示时调用：连上会话、按真实尺寸重排、把焦点放到命令输入框 */
    open() {
      requestAnimationFrame(() => {
        controller.fit();
        cmdEl.focus();
      });
      return ensureSession();
    },
    /** 只隐藏面板，会话留着，来回切文件/应用不用重连 */
    close() {
      onClose();
    },
    fit() {
      // 不抢焦点：面板打开后光标要留在下面的命令输入框里
      controller.fit();
    },
    /** 设备断开 / 页面关闭时调用，真正结束 pty */
    shutdown() {
      controller.close();
      setState("终端未连接");
    },
    /** Esc 不关本面板，交回终端自己处理 */
    onEscape() {
      return true;
    },
  };
}
