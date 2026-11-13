/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.

设备侧操作层（device side）
======================================
这一层只跟「设备上的 shell」打交道，完全不碰 WebUSB / 解码 / 画布，
所以能单独读懂、单独改、单独测：

  · shCmd()            —— 把整段脚本当成一个参数发给设备（这条踩过坑，见下）
  · 进程扫描 / 清理     —— 读 /proc/<pid>/cmdline 找 scrcpy server 并 kill
  · 反向转发清理        —— 撤掉 adb reverse 残留
  · 电源 / 唤醒        —— KEYCODE_WAKEUP、dumpsys power、常亮
  · 崩溃取证           —— logcat 各缓冲区 + 重放启动命令
  · 注入权限判定        —— 识别小米系 INJECT_EVENTS 拒绝

【重要】为什么所有命令都写成 shCmd(adb, 整段脚本)：
投屏库会把参数数组用空格拼成一条字符串交给设备的 sh -c 执行。若写成
  spawnWaitText(["sh", "-c", "A=1; kill -9 $A"])
设备端只把 -c 后面第一个词（"A=1;"）当脚本，其余全变成位置参数，
于是变量恒为空、管道恒返回 0、for 循环报 syntax error —— 而且不会报错失败，
只会静默给出「清理完成 / 没有残留 / 退出码 0」这种假结论。
代价是我们为这个坑排查了五轮。详见 docs/技术方案.md。
*/

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const SCRCPY_MARKER = "com.genymobile.scrcpy.Server";

/** 把 "com..." 变成 "[c]om..."：让 grep 模式匹配真实进程但放过正在执行它的 shell 自己 */
function bracket(marker) {
  return `[${marker[0]}]${marker.slice(1)}`;
}

/**
 * 在设备上执行一段 shell 脚本 —— 这是唯一正确的调用方式，务必照此写。
 *
 * 踩了很久的坑：库把参数数组用**空格拼成一条字符串**发给设备
 * （@yume-chan/adb 的 service.js：`exec:${command.join(" ")}`），
 * 设备端再把这一整条字符串丢给 `sh -c` 执行。所以写成
 *     spawnWaitText(["sh", "-c", "A=$(...); B=1; echo $A $B"])
 * 拼出来是
 *     sh -c A=$(...); B=1; echo $A $B
 * 设备 shell 只把 `-c` 后面**第一个词**当脚本（`A=` 或 `for`），后面的全变成
 * $0/$1… 位置参数。后果非常隐蔽：
 *   · `kill -9 $PIDS` 里 PIDS 是空的 → 一个进程都没杀到，但日志照样打"清理完成"；
 *   · `PIDS=... | wc -l` 变成跑一句 `grep` → 永远返回 0 → "没有残留进程"是假的；
 *   · `for d in ...; do` 直接被拆成 `for` + `d` + ... → "syntax error: unexpected 'do'"。
 * 这就是「关掉主屏镜像再打开必 Aborted」一直治不好的真正原因：旧 server 从没被杀掉过，
 * 一直占着展锐唯一那路硬件编码器。
 *
 * 正确做法：把整段脚本当成**一个参数**传进去，让设备端的 sh 完整执行它。
 */
function shCmd(adb, script) {
  return adb.subprocess.noneProtocol.spawnWaitText([script]);
}

/**
 * 生成"列出 scrcpy 服务端进程 PID"的 shell 片段。
 *
 * 为什么不用 ps：这台展锐平板的 `ps` 对 `-A -o PID,ARGS` 支持不稳，命令会静默失败。
 * 之前一直拿 ps 过滤，结果「清理残留进程」其实一个都没杀到（还打了句假成功日志），
 * 旧 server 一直活着占着唯一那路硬件编码器 —— 这就是「第一次能起、关掉再开必 Aborted」
 * 的真正原因。直接读 /proc/<pid>/cmdline 最可靠，跟 ps 实现无关：
 *   cmdline 是 NUL 分隔的完整命令行，grep -l 能匹配到类名或 scid，
 *   `cut -d/ -f3` 把 /proc/<pid>/cmdline 里的 pid 取出来。
 */
function scanPidsCmd(scid) {
  // 用 `[c]` 括号技巧（见 bracket()）：模式写成 `[c]om...`，既匹配真实进程命令行里的
  // `com...`，又不会匹配到"正在跑这条扫描命令的 shell 自己"，否则 kill -9 会把自己所在的
  // shell 也杀掉，进程清理半途而废。
  const marker = bracket(scid ? `scid=${scid}` : SCRCPY_MARKER);
  return `grep -l "${marker}" /proc/[0-9]*/cmdline 2>/dev/null | cut -d/ -f3`;
}

/** 数一下还剩几个 scrcpy 服务端进程；出错返回 -1（表示"不确定"） */
async function countScrcpyProcs(adb, scid = null) {
  try {
    const text = await shCmd(adb, `${scanPidsCmd(scid)} | wc -l`);
    const n = parseInt(String(text).trim(), 10);
    return Number.isFinite(n) ? n : -1;
  } catch {
    return -1;
  }
}

/**
 * 杀掉 scrcpy 服务端进程，并**验证**是否真的杀干净。
 * 返回剩余数量（-1 表示没验证成功）。
 *
 * 关键：库的 process.kill() 只是关掉浏览器这边的 ADB socket，设备端的 app_process
 * 并不会退出。必须由我们自己杀，而且必须确认它真的死了，否则编码器一直锁着。
 *
 * 先 SIGTERM 再 SIGKILL：直接 -9 会让服务端来不及释放 MediaCodec/Surface，
 * 厂商编码器组件（c2.unisoc.avc.encoder）会停在"被占用"状态，下一次启动更容易崩。
 * 杀完必须再数一遍，把真实剩余数打进日志 —— 以前这里打的是假成功。
 */
async function killScrcpyProcs(adb, scid = null, log = () => {}) {
  const scan = scanPidsCmd(scid);
  const script = [
    `PIDS=$(${scan})`,
    `N=0`,
    `if [ -n "$PIDS" ]; then N=$(echo $PIDS | wc -w | tr -d ' '); kill -15 $PIDS 2>/dev/null; sleep 0.5; fi`,
    `LEFT=$(${scan} | wc -l | tr -d ' ')`,
    `if [ "$LEFT" != "0" ] && [ -n "$LEFT" ]; then kill -9 $(${scan}) 2>/dev/null; sleep 0.3; fi`,
    `LEFT=$(${scan} | wc -l | tr -d ' ')`,
    `echo "KILLED=$N LEFT=$LEFT"`,
  ].join("\n");
  try {
    const out = String(await shCmd(adb, script));
    const m = out.match(/KILLED=(\d+)\s+LEFT=(\d+)/);
    if (m) {
      const killed = Number(m[1]);
      const left = Number(m[2]);
      if (killed) log(`[清理] 杀掉 ${killed} 个 scrcpy 进程，剩余 ${left} 个`, "dim");
      else log(`[清理] 没有残留 scrcpy 进程（剩余 ${left}）`, "dim");
      return left;
    }
    // 没匹配到统计行：说明这段脚本没被设备端完整执行（拼参数的老毛病），
    // 单独再数一次，宁可拿到 -1 也不能假报"已清理"。
    log(`[清理] 统计输出异常：${out.trim() || "（空）"}`, "dim");
    return await countScrcpyProcs(adb, scid);
  } catch (error) {
    log("[清理] 扫描/杀进程失败（可继续）：" + (error?.message || error), "dim");
    return -1;
  }
}

/**
 * 清掉设备端所有残留的 scrcpy server 进程。
 * 刷新页面、关闭窗口后上一次的 server 不会自动退出，它会一直占着硬件编码器，
 * 导致新实例直接 Aborted。
 */
async function pkillServer(adb, log = () => {}) {
  const left = await killScrcpyProcs(adb, null, log);
  if (left > 0) {
    log(`[清理] 干掉后仍有 ${left} 个进程没死（可能是 D 状态/编码器驱动卡住），继续尝试启动`, "err");
  }
}

/**
 * 清理设备上所有 scrcpy 相关的反向转发（adb reverse）。
 *
 * 这是「关掉主屏镜像再点开就 Aborted」的头号根因：
 * tunnel_forward 模式靠 `adb reverse tcp:27183 → localabstract:scrcpy_<scid>`
 * 把服务端连回浏览器。会话关闭时库的 dispose() 对这条转发的 remove 是
 * 「发射后不管、不 await、失败就吞掉」，而 initialize() 又只 remove 当前 scid
 * 的那一条（我们每次 scid 都变），于是上一次残留的转发永远撤不掉。
 * 下一次启动用新 scid 去注册同一个 tcp 端口，连到了一条已死的旧 socket，
 * 服务端瞬间 Aborted。每次启动前先把所有 scrcpy 转发清干净最稳。
 *
 * 注意：必须在「没有别的会话在跑」时才清，否则会把正在用的窗口/镜像转发一起干掉。
 */
async function clearScrcpyReverse(adb, log = () => {}) {
  try {
    const forwards = await adb.reverse.list();
    let removed = 0;
    for (const f of forwards) {
      const local = f.localName || "";
      const remote = f.remoteName || "";
      // local 是电脑侧端口（tcp:27183），remote 是设备侧 socket（localabstract:scrcpy_<scid>）
      if (remote.includes("scrcpy") || local === "tcp:27183") {
        try {
          await adb.reverse.remove(local);
          removed += 1;
        } catch {
          /* 删不掉也无所谓，下一步会重试 */
        }
      }
    }
    if (removed) log(`[诊断] 已清理 ${removed} 条残留反向转发`, "dim");
  } catch (error) {
    // 拿不到列表就放弃，别让这一步阻塞启动
    log(`[诊断] 清理反向转发失败（可继续）：${error?.message || error}`, "dim");
  }
}

/* ---------- 电源 / 熄屏 ---------- *
 * 这台展锐平板有个硬毛病：屏幕一熄，再起 scrcpy 服务端就立刻 Aborted，
 * 连一条 Device 行都打不出来（10:41 能起、10:42 熄屏后同一条命令就起不来）。
 * 所以连接期间默认「接 USB 不熄屏」，启动前再兜底唤醒一次。
 */

/**
 * 小米 / 红米 / POCO（MIUI、HyperOS）把「允许电脑模拟点击」单独做成一个开关，
 * 叫「USB 调试（安全设置）」。只开普通「USB 调试」时：能连、能投屏、能跑 shell
 * 命令，但所有 injectInputEvent 都被拒 —— 现象就是「画面有、鼠标点不动、
 * 熄屏也叫不亮」。终端查信息正常，恰恰因为它不需要注入输入。
 *
 * 设备会自己把下面这几行打出来，这里认下来并上报给页面，别让用户在几百行
 * 日志里自己翻。别的厂商有类似限制时，同一套关键字也能兜住。
 */
const INJECT_DENIED =
  /INJECT_EVENTS|Injecting input events requires|USB debugging \(Security Settings\)/i;
let injectIssueReported = false;

function reportInjectIssue(log, onIssue, source, raw = "") {
  if (raw) log(`[输入权限] ${source} 原始输出：${raw}`, "dim");
  if (injectIssueReported) return;
  injectIssueReported = true;
  log("[输入权限] 设备拒绝了电脑模拟点击/按键：鼠标、键盘、点亮屏幕都用不了", "err");
  log("[输入权限] 小米/红米/POCO：开发者选项 →「USB 调试（安全设置）」→ 打开并重启手机", "err");
  onIssue?.({ source, message: "设备拒绝了电脑模拟点击" });
}

/**
 * 每次新建投屏会话前把「已提示过输入权限」的标记清掉。
 * 用户可能刚在手机上开完「USB 调试（安全设置）」，重连就该重新判一次；
 * 这个标记在 device.js 内部，所以要给会话层（session.js）一个重置入口，
 * 别在 session.js 里直接写 injectIssueReported —— 那不是它的变量（会报未定义）。
 */
function resetInjectIssue() {
  injectIssueReported = false;
}

/**
 * 等设备上残留的 scrcpy server 进程真正退出。
 *
 * 为什么必须等：这台展锐只有一路硬件编码器，server 进程哪怕还在"正在退出"的状态，
 * 占着的编码器/抽象 socket 就不会释放。上一个镜像刚 stop 就立刻重开，新 server 一
 * 启动去抢编码器，直接 Aborted / "scrcpy server exited prematurely"。之前只 sleep 300ms
 * 太短，进程经常没退干净。这里改成轮询：直到 ps 里再也找不到 scrcpy.Server 才放行。
 */
async function waitForServerGone(adb, log = () => {}, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  let lastCount = 0;
  while (Date.now() < deadline) {
    const count = await countScrcpyProcs(adb, null);
    if (count === 0) {
      if (lastCount > 0) log("[诊断] 旧 server 已全部退出，可以启动", "dim");
      return true;
    }
    if (count < 0) return true; // 扫描失败就当没了，别卡住启动
    lastCount = count;
    log(`[诊断] 还有 ${count} 个 scrcpy server 没退干净，等它退出再启动…`, "dim");
    await sleep(300);
  }
  log("[诊断] 等旧 server 退出超时（仍会尝试启动，失败会自动重试）", "dim");
  return false;
}

/** 共享：把一条唤醒/自检命令的 stdout+stderr 一起收回来 */
async function wakeLike(adb, command, log = () => {}) {
  try {
    return String(await shCmd(adb, `${command} 2>&1`)).trim();
  } catch (error) {
    return `执行失败：${error?.message || error}`;
  }
}

/**
 * 主动自检：发一条点亮按键，把 stdout + stderr 一起收回来。
 * 这条既是验证（能不能注入）也是唤醒（能注入就顺手把屏幕点亮）。
 * 原文一律打进日志，匹配不上时用户贴回来我们照着调，不靠猜。
 */
async function checkInputPermission(adb, log = () => {}) {
  // 用名字写法 KEYCODE_WAKEUP：部分 ROM（展锐平板）的 input 工具拒绝数字 224，
  // 会回一行 "Usage: input ..."；名字写法更通用。
  // wakeLike 是 async，漏了 await 拿到的是 Promise，所有 .test() 都恒为 false，
  // 于是"点亮成功"永远为真、拦截永远判不出来。必须 await。
  const text = await wakeLike(adb, 'input keyevent KEYCODE_WAKEUP; echo "EXIT=$?"', log);
  log(`[输入权限] 自检输出：${text || "（无输出）"}`, "dim");
  if (/[Uu]sage:/.test(text)) {
    // 本机 input 两种写法都不认，无法用命令确认；真正的拦截信息来自服务端，这里不误报
    log("[输入权限] 自检命令在本机 input 工具上不可用，是否拦截以画面/服务端实际表现为准", "dim");
    return { ok: true, denied: false, text };
  }
  const denied = INJECT_DENIED.test(text);
  return { ok: !denied, denied, text };
}

/** 读屏幕状态。dumpsys power 有几千行，只抓关键那几行 */
async function getPowerState(adb) {
  try {
    const text = await shCmd(
      adb,
      "dumpsys power 2>/dev/null | grep -m3 -E 'mWakefulness=|mScreenOn=' | tr -d ' '"
    );
    const raw = String(text)
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .join(" ");
    const match = raw.match(/mWakefulness=([A-Za-z]+)/);
    const wakefulness = match ? match[1] : null;
    return {
      awake: wakefulness ? wakefulness === "Awake" : null,
      wakefulness,
      raw: raw || "（没有匹配到 mWakefulness）",
    };
  } catch (error) {
    return { awake: null, wakefulness: null, raw: `读取失败：${error?.message || error}` };
  }
}

/**
 * 只发点亮命令，不读任何状态 —— 启动路径专用。
 *
 * 惨痛教训：`dumpsys power` 在这台展锐平板首次调用要 22 秒（11:56:43 连上、
 * 11:57:05 才打印出屏幕状态），把"连上就能用"拖成"卡住不动"。而唤醒命令
 * 是幂等的：亮屏时发一次等于什么都没做，睡着时正好救回来，几十毫秒就完事。
 * 状态读取只留给失败取证和「☀ 唤醒」按钮（用户主动点，才值得等）。
 */
async function sendWakeup(adb, log = () => {}, onIssue = null) {
  // 两种写法都试：大部分 ROM 认数字 224，但展锐平板的 input 工具只认名字，
  // 喂数字会回一行 "Usage: input ..."。任一写法成功即可，避免"亮屏命令失败"的假报错。
  const forms = [
    ["KEYCODE_WAKEUP（名字）", "input keyevent KEYCODE_WAKEUP"],
    ["224（数字）", "input keyevent 224"],
  ];
  for (const [label, cmd] of forms) {
    const text = await wakeLike(adb, cmd, log);
    // 小米拒绝注入：SecurityException 打在 stderr，被 2>&1 并进来了
    if (INJECT_DENIED.test(text)) {
      reportInjectIssue(log, onIssue, "点亮屏幕", text);
      return false;
    }
    // 本机 input 不支持这种写法（回 Usage），换另一种试试
    if (/[Uu]sage:/.test(text)) {
      const first = text.split("\n")[0];
      log(`[唤醒] 本机 input 不支持 ${label}（${first}），换一种写法`, "dim");
      continue;
    }
    // 没报错也没回 Usage，视为成功
    try {
      await adb.subprocess.noneProtocol.spawnWaitText(["wm", "dismiss-keyguard"]);
    } catch {
      /* 有锁屏密码时这条会失败，不影响 */
    }
    log("[唤醒] 已发送点亮命令", "dim");
    return true;
  }
  log("[唤醒] 本机 input 命令无法点亮（已开启接 USB 常亮，正常不会睡）", "dim");
  return false;
}

/** 「☀ 唤醒」按钮用：发命令后读一次状态，好告诉用户到底叫醒没有 */
async function wakeScreen(adb, log = () => {}, onIssue = null) {
  await sendWakeup(adb, log, onIssue);
  await sleep(350);
  return getPowerState(adb);
}

/**
 * 接 USB 时不熄屏。
 * 展锐这台机器一旦真熄屏，scrcpy 服务端起不来（Aborted），
 * 连接期间就让屏幕保持亮着最省事；断开时恢复系统默认。
 */
async function keepAwake(adb, on, log = () => {}) {
  try {
    await adb.subprocess.noneProtocol.spawnWaitText(["svc", "power", "stayon", on ? "usb" : "false"]);
    log(on ? "[常亮] 已开启：接 USB 期间不自动熄屏" : "[常亮] 已关闭：恢复系统默认的熄屏行为", "dim");
    return true;
  } catch (error) {
    log(`[常亮] 设置失败（不影响投屏）：${error?.message || error}`, "dim");
    return false;
  }
}

/** server 的异常栈走 logcat / stderr，浏览器看不到，只能回头翻设备日志 */
async function dumpCrashLog(adb, log = () => {}) {
  const commands = [
    // 先确认连接还活着：熄屏后有些机器会掐掉 USB 数据，此时后面所有命令都是空
    ["连接存活", "echo alive"],
    // 直接列 scrcpy 进程：如果这里还有进程，说明旧编码器被它占着，新 server 必然 Aborted。
    // 同样用 [c]om 括号技巧，避免把跑这条命令的 shell 自己列进去。
    ["scrcpy 进程", `for d in $(grep -l "[c]om.genymobile.scrcpy.Server" /proc/[0-9]*/cmdline 2>/dev/null); do pid=$(echo $d | cut -d/ -f3); echo "pid=$pid $(cat $d 2>/dev/null | tr '\\0' ' ')"; done`],
    ["屏幕状态", "timeout 4 dumpsys power 2>/dev/null | grep -m3 -E 'mWakefulness=|mScreenOn=' | tr -d ' '"],
    // crash 缓冲区专存致命信号与 Java 崩溃，比在 main 里翻更准
    ["crash 缓冲区", "logcat -d -b crash -v threadtime 2>&1 | tail -40"],
    // 被信号打死不一定会进 crash 缓冲区，全缓冲区再筛一遍（含 AM 杀进程的记录）
    ["全缓冲区", "logcat -d -b all -v brief -t 600 2>&1 | grep -iE 'scrcpy|app_process|AndroidRuntime|abort|am_kill|lowmemorykiller' | tail -20"],
    // main 缓冲区只取最后 3000 行再筛，避免崩溃记录被刷走
    ["main 缓冲区", "logcat -d -v threadtime -t 3000 2>&1 | grep -iE 'scrcpy|AndroidRuntime|Fatal|avc' | tail -25"],
    // 设备到底支不支持/允许多少个虚拟显示：new_display 建不出来时这就是答案
    ["显示能力", "timeout 4 dumpsys display 2>&1 | grep -E 'mDisplayId=|DisplayDeviceInfo|maxVirtualDisplay|type ' | head -20"],
  ];
  for (const [label, command] of commands) {
    try {
      const text = await shCmd(adb, command);
      const lines = String(text)
        .split("\n")
        .map((s) => s.replace(/\r$/, "").trimEnd())
        .filter((s) => s.trim());
      if (lines.length) {
        log(`设备端日志·${label}（${lines.length} 行）：`, "err");
        lines.forEach((line) => log("  " + line, "err"));
      } else {
        // 没输出也是结论：说明这条命令本身没拿到东西，而不是"没有崩溃"
        log(`设备端日志·${label}：无输出`, "dim");
      }
    } catch (error) {
      log(`设备端日志·${label}：读取失败（${error?.message || error}）`, "dim");
    }
  }
}

/** 只杀掉指定 scid 的那一个 server，不动别的会话；返回剩余数量 */
async function killServerByScid(adb, scid, log = () => {}) {
  if (!scid) return 0;
  return killScrcpyProcs(adb, scid, log);
}

/**
 * 自己再存一份服务端输出。
 *
 * 为什么需要：AdbScrcpyClient.start 失败时，回传的是"当场已经收到的行"。
 * 进程刚崩时输出还堆在管道里没送到，于是只剩最后一行 shell 的 "Aborted"，
 * 真正的原因（Java 异常栈 / 编码器报错 / 显示创建失败）全丢了。
 * 这里用 tee 复制一条流自己读完，退出后一定能拿到完整输出。
 */
function createOutputCapture(adb) {
  const capture = { args: null, text: "", finished: null };
  capture.spawner = {
    async spawn(command, signal) {
      capture.args = [...command];
      const process = await adb.subprocess.noneProtocol.spawn(command, signal);
      let output = process.output;
      try {
        const [keep, copy] = process.output.tee();
        output = keep;
        const decoder = new TextDecoder();
        // 保存 promise：失败时要知道"复制流是否已经读完"，否则拿到的还是空字符串
        capture.finished = copy
          .pipeTo(
            new WritableStream({
              write(chunk) {
                capture.text += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
              },
              close() {
                capture.text += decoder.decode();
              },
            })
          )
          .catch((error) => {
            capture.text += `（输出复制中断：${error?.message || error}）\n`;
          });
      } catch (error) {
        capture.text += `（输出复制失败：${error?.message || error}）\n`;
      }
      // 只透传 client 需要的三样东西
      return {
        get output() {
          return output;
        },
        get exited() {
          return process.exited;
        },
        get stdin() {
          return process.stdin;
        },
        kill: () => process.kill(),
      };
    },
  };
  /**
   * 等复制流落完再读文本。
   * 之前失败时直接读 capture.text，读到的永远是空 —— 复制流还在微任务队列里，
   * 服务端的真实报错根本没来得及写进来，所以只剩 client 自己收到的那一行 "Aborted"。
   */
  capture.flush = async (ms = 800) => {
    if (capture.finished) {
      await Promise.race([capture.finished.catch(() => {}), new Promise((r) => setTimeout(r, ms))]);
    }
    await new Promise((r) => setTimeout(r, 120));
    return capture.text;
  };
  return capture;
}

/**
 * 把刚失败的那条命令原样重放一遍，拿完整输出。
 *
 * 客户端那条管道是"边跑边读"，进程被信号打死时输出可能丢；重放是把整条命令
 * 交给 sh 同步跑完再一次性取回，服务端到底打印了什么一目了然。
 * 用 timeout 兜底：命令真的能跑起来时会挂在等 socket，超时后被杀，退出码 124。
 * 崩掉的场景都是秒退，6 秒足够；太长会让"点一下主屏镜像"干等。
 */
async function replayServerCommand(adb, args, log = () => {}, seconds = 6) {
  if (!Array.isArray(args) || !args.length) {
    log("[重放] 没有拿到原始命令行，跳过", "dim");
    return;
  }
  const safe = args.filter((item) => typeof item === "string" && item && !item.includes("'"));
  if (safe.length !== args.length) {
    log("[重放] 命令行里有引号，跳过重放", "dim");
    return;
  }
  const [head, ...rest] = safe;
  const hasEnv = /^[A-Z_]+=/.test(head);
  const env = hasEnv ? head + " " : "";
  const bin = hasEnv ? rest.shift() : head;
  // 退出码含义：124=还活着（只是没人连它）；134=SIGABRT；1=Java 抛异常
  const script = `${env}timeout ${seconds} ${bin} ${rest.join(" ")} 2>&1; echo "__EXIT=$?"`;
  log(`[重放] 原样再跑一遍这条命令，最多等 ${seconds} 秒…`, "dim");
  let text = "";
  try {
    text = await shCmd(adb, script);
  } catch (error) {
    log("[重放] 执行失败：" + (error?.message || error), "err");
    return;
  }
  const lines = String(text)
    .split("\n")
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim());
  const exitLine = lines.find((line) => line.includes("__EXIT="));
  const exitCode = exitLine ? Number(exitLine.split("__EXIT=")[1]) : NaN;
  const code = Number.isFinite(exitCode) ? exitCode : null;
  if (code === null) {
    log(`[重放] 跑了 ${lines.length} 行，但没拿到退出码`, "dim");
  } else {
    // 这一行是结论，必须默认可见
    log(`[重放] 退出码 ${code}${describeExit(code)}`);
  }
  lines
    .filter((line) => !line.includes("__EXIT="))
    .slice(-40)
    .forEach((line) => log("  " + line, "err"));
}

function describeExit(code) {
  if (code === 124) return "（进程活得好好的，只是在等 socket —— 说明这条命令本身没问题）";
  if (code === 134) return "（SIGABRT：原生层 abort，异常栈在 logcat crash 缓冲区）";
  if (code === 139) return "（SIGSEGV：原生层段错误）";
  if (code === 1) return "（Java 层抛异常，上面应该能看到 Error 行）";
  if (code === 0) return "（正常退出）";
  return "";
}

/** 读取 Android SDK 版本号（如 Android 13 = 33）；拿不到返回 0。音频只在 SDK>=31（Android 12+）可用。 */
export async function getAndroidSdk(adb) {
  try {
    const out = String(await shCmd(adb, "getprop ro.build.version.sdk")).trim();
    const n = parseInt(out, 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

export {
  INJECT_DENIED,
  SCRCPY_MARKER,
  bracket,
  checkInputPermission,
  clearScrcpyReverse,
  countScrcpyProcs,
  createOutputCapture,
  describeExit,
  dumpCrashLog,
  getPowerState,
  keepAwake,
  killScrcpyProcs,
  killServerByScid,
  pkillServer,
  replayServerCommand,
  reportInjectIssue,
  resetInjectIssue,
  scanPidsCmd,
  sendWakeup,
  shCmd,
  waitForServerGone,
  wakeLike,
  wakeScreen,
};
