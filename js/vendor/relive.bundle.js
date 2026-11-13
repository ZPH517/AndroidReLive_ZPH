var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/relive/device.js
var sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
var SCRCPY_MARKER = "com.genymobile.scrcpy.Server";
function bracket(marker) {
  return `[${marker[0]}]${marker.slice(1)}`;
}
function shCmd(adb, script) {
  return adb.subprocess.noneProtocol.spawnWaitText([script]);
}
function scanPidsCmd(scid) {
  const marker = bracket(scid ? `scid=${scid}` : SCRCPY_MARKER);
  return `grep -l "${marker}" /proc/[0-9]*/cmdline 2>/dev/null | cut -d/ -f3`;
}
async function countScrcpyProcs(adb, scid = null) {
  try {
    const text = await shCmd(adb, `${scanPidsCmd(scid)} | wc -l`);
    const n = parseInt(String(text).trim(), 10);
    return Number.isFinite(n) ? n : -1;
  } catch {
    return -1;
  }
}
async function killScrcpyProcs(adb, scid = null, log = () => {
}) {
  const scan = scanPidsCmd(scid);
  const script = [
    `PIDS=$(${scan})`,
    `N=0`,
    `if [ -n "$PIDS" ]; then N=$(echo $PIDS | wc -w | tr -d ' '); kill -15 $PIDS 2>/dev/null; sleep 0.5; fi`,
    `LEFT=$(${scan} | wc -l | tr -d ' ')`,
    `if [ "$LEFT" != "0" ] && [ -n "$LEFT" ]; then kill -9 $(${scan}) 2>/dev/null; sleep 0.3; fi`,
    `LEFT=$(${scan} | wc -l | tr -d ' ')`,
    `echo "KILLED=$N LEFT=$LEFT"`
  ].join("\n");
  try {
    const out = String(await shCmd(adb, script));
    const m = out.match(/KILLED=(\d+)\s+LEFT=(\d+)/);
    if (m) {
      const killed = Number(m[1]);
      const left = Number(m[2]);
      if (killed) log(`[\u6E05\u7406] \u6740\u6389 ${killed} \u4E2A scrcpy \u8FDB\u7A0B\uFF0C\u5269\u4F59 ${left} \u4E2A`, "dim");
      else log(`[\u6E05\u7406] \u6CA1\u6709\u6B8B\u7559 scrcpy \u8FDB\u7A0B\uFF08\u5269\u4F59 ${left}\uFF09`, "dim");
      return left;
    }
    log(`[\u6E05\u7406] \u7EDF\u8BA1\u8F93\u51FA\u5F02\u5E38\uFF1A${out.trim() || "\uFF08\u7A7A\uFF09"}`, "dim");
    return await countScrcpyProcs(adb, scid);
  } catch (error) {
    log("[\u6E05\u7406] \u626B\u63CF/\u6740\u8FDB\u7A0B\u5931\u8D25\uFF08\u53EF\u7EE7\u7EED\uFF09\uFF1A" + (error?.message || error), "dim");
    return -1;
  }
}
async function pkillServer(adb, log = () => {
}) {
  const left = await killScrcpyProcs(adb, null, log);
  if (left > 0) {
    log(`[\u6E05\u7406] \u5E72\u6389\u540E\u4ECD\u6709 ${left} \u4E2A\u8FDB\u7A0B\u6CA1\u6B7B\uFF08\u53EF\u80FD\u662F D \u72B6\u6001/\u7F16\u7801\u5668\u9A71\u52A8\u5361\u4F4F\uFF09\uFF0C\u7EE7\u7EED\u5C1D\u8BD5\u542F\u52A8`, "err");
  }
}
async function clearScrcpyReverse(adb, log = () => {
}) {
  try {
    const forwards = await adb.reverse.list();
    let removed = 0;
    for (const f of forwards) {
      const local = f.localName || "";
      const remote = f.remoteName || "";
      if (remote.includes("scrcpy") || local === "tcp:27183") {
        try {
          await adb.reverse.remove(local);
          removed += 1;
        } catch {
        }
      }
    }
    if (removed) log(`[\u8BCA\u65AD] \u5DF2\u6E05\u7406 ${removed} \u6761\u6B8B\u7559\u53CD\u5411\u8F6C\u53D1`, "dim");
  } catch (error) {
    log(`[\u8BCA\u65AD] \u6E05\u7406\u53CD\u5411\u8F6C\u53D1\u5931\u8D25\uFF08\u53EF\u7EE7\u7EED\uFF09\uFF1A${error?.message || error}`, "dim");
  }
}
var INJECT_DENIED = /INJECT_EVENTS|Injecting input events requires|USB debugging \(Security Settings\)/i;
var injectIssueReported = false;
function reportInjectIssue(log, onIssue, source, raw = "") {
  if (raw) log(`[\u8F93\u5165\u6743\u9650] ${source} \u539F\u59CB\u8F93\u51FA\uFF1A${raw}`, "dim");
  if (injectIssueReported) return;
  injectIssueReported = true;
  log("[\u8F93\u5165\u6743\u9650] \u8BBE\u5907\u62D2\u7EDD\u4E86\u7535\u8111\u6A21\u62DF\u70B9\u51FB/\u6309\u952E\uFF1A\u9F20\u6807\u3001\u952E\u76D8\u3001\u70B9\u4EAE\u5C4F\u5E55\u90FD\u7528\u4E0D\u4E86", "err");
  log("[\u8F93\u5165\u6743\u9650] \u5C0F\u7C73/\u7EA2\u7C73/POCO\uFF1A\u5F00\u53D1\u8005\u9009\u9879 \u2192\u300CUSB \u8C03\u8BD5\uFF08\u5B89\u5168\u8BBE\u7F6E\uFF09\u300D\u2192 \u6253\u5F00\u5E76\u91CD\u542F\u624B\u673A", "err");
  onIssue?.({ source, message: "\u8BBE\u5907\u62D2\u7EDD\u4E86\u7535\u8111\u6A21\u62DF\u70B9\u51FB" });
}
function resetInjectIssue() {
  injectIssueReported = false;
}
async function waitForServerGone(adb, log = () => {
}, timeoutMs = 6e3) {
  const deadline = Date.now() + timeoutMs;
  let lastCount = 0;
  while (Date.now() < deadline) {
    const count = await countScrcpyProcs(adb, null);
    if (count === 0) {
      if (lastCount > 0) log("[\u8BCA\u65AD] \u65E7 server \u5DF2\u5168\u90E8\u9000\u51FA\uFF0C\u53EF\u4EE5\u542F\u52A8", "dim");
      return true;
    }
    if (count < 0) return true;
    lastCount = count;
    log(`[\u8BCA\u65AD] \u8FD8\u6709 ${count} \u4E2A scrcpy server \u6CA1\u9000\u5E72\u51C0\uFF0C\u7B49\u5B83\u9000\u51FA\u518D\u542F\u52A8\u2026`, "dim");
    await sleep(300);
  }
  log("[\u8BCA\u65AD] \u7B49\u65E7 server \u9000\u51FA\u8D85\u65F6\uFF08\u4ECD\u4F1A\u5C1D\u8BD5\u542F\u52A8\uFF0C\u5931\u8D25\u4F1A\u81EA\u52A8\u91CD\u8BD5\uFF09", "dim");
  return false;
}
async function wakeLike(adb, command, log = () => {
}) {
  try {
    return String(await shCmd(adb, `${command} 2>&1`)).trim();
  } catch (error) {
    return `\u6267\u884C\u5931\u8D25\uFF1A${error?.message || error}`;
  }
}
async function checkInputPermission(adb, log = () => {
}) {
  const text = await wakeLike(adb, 'input keyevent KEYCODE_WAKEUP; echo "EXIT=$?"', log);
  log(`[\u8F93\u5165\u6743\u9650] \u81EA\u68C0\u8F93\u51FA\uFF1A${text || "\uFF08\u65E0\u8F93\u51FA\uFF09"}`, "dim");
  if (/[Uu]sage:/.test(text)) {
    log("[\u8F93\u5165\u6743\u9650] \u81EA\u68C0\u547D\u4EE4\u5728\u672C\u673A input \u5DE5\u5177\u4E0A\u4E0D\u53EF\u7528\uFF0C\u662F\u5426\u62E6\u622A\u4EE5\u753B\u9762/\u670D\u52A1\u7AEF\u5B9E\u9645\u8868\u73B0\u4E3A\u51C6", "dim");
    return { ok: true, denied: false, text };
  }
  const denied = INJECT_DENIED.test(text);
  return { ok: !denied, denied, text };
}
async function getPowerState(adb) {
  try {
    const text = await shCmd(
      adb,
      "dumpsys power 2>/dev/null | grep -m3 -E 'mWakefulness=|mScreenOn=' | tr -d ' '"
    );
    const raw = String(text).split("\n").map((line) => line.trim()).filter(Boolean).join(" ");
    const match = raw.match(/mWakefulness=([A-Za-z]+)/);
    const wakefulness = match ? match[1] : null;
    return {
      awake: wakefulness ? wakefulness === "Awake" : null,
      wakefulness,
      raw: raw || "\uFF08\u6CA1\u6709\u5339\u914D\u5230 mWakefulness\uFF09"
    };
  } catch (error) {
    return { awake: null, wakefulness: null, raw: `\u8BFB\u53D6\u5931\u8D25\uFF1A${error?.message || error}` };
  }
}
async function sendWakeup(adb, log = () => {
}, onIssue = null) {
  const forms = [
    ["KEYCODE_WAKEUP\uFF08\u540D\u5B57\uFF09", "input keyevent KEYCODE_WAKEUP"],
    ["224\uFF08\u6570\u5B57\uFF09", "input keyevent 224"]
  ];
  for (const [label, cmd] of forms) {
    const text = await wakeLike(adb, cmd, log);
    if (INJECT_DENIED.test(text)) {
      reportInjectIssue(log, onIssue, "\u70B9\u4EAE\u5C4F\u5E55", text);
      return false;
    }
    if (/[Uu]sage:/.test(text)) {
      const first = text.split("\n")[0];
      log(`[\u5524\u9192] \u672C\u673A input \u4E0D\u652F\u6301 ${label}\uFF08${first}\uFF09\uFF0C\u6362\u4E00\u79CD\u5199\u6CD5`, "dim");
      continue;
    }
    try {
      await adb.subprocess.noneProtocol.spawnWaitText(["wm", "dismiss-keyguard"]);
    } catch {
    }
    log("[\u5524\u9192] \u5DF2\u53D1\u9001\u70B9\u4EAE\u547D\u4EE4", "dim");
    return true;
  }
  log("[\u5524\u9192] \u672C\u673A input \u547D\u4EE4\u65E0\u6CD5\u70B9\u4EAE\uFF08\u5DF2\u5F00\u542F\u63A5 USB \u5E38\u4EAE\uFF0C\u6B63\u5E38\u4E0D\u4F1A\u7761\uFF09", "dim");
  return false;
}
async function wakeScreen(adb, log = () => {
}, onIssue = null) {
  await sendWakeup(adb, log, onIssue);
  await sleep(350);
  return getPowerState(adb);
}
async function keepAwake(adb, on, log = () => {
}) {
  try {
    await adb.subprocess.noneProtocol.spawnWaitText(["svc", "power", "stayon", on ? "usb" : "false"]);
    log(on ? "[\u5E38\u4EAE] \u5DF2\u5F00\u542F\uFF1A\u63A5 USB \u671F\u95F4\u4E0D\u81EA\u52A8\u7184\u5C4F" : "[\u5E38\u4EAE] \u5DF2\u5173\u95ED\uFF1A\u6062\u590D\u7CFB\u7EDF\u9ED8\u8BA4\u7684\u7184\u5C4F\u884C\u4E3A", "dim");
    return true;
  } catch (error) {
    log(`[\u5E38\u4EAE] \u8BBE\u7F6E\u5931\u8D25\uFF08\u4E0D\u5F71\u54CD\u6295\u5C4F\uFF09\uFF1A${error?.message || error}`, "dim");
    return false;
  }
}
async function dumpCrashLog(adb, log = () => {
}) {
  const commands = [
    // 先确认连接还活着：熄屏后有些机器会掐掉 USB 数据，此时后面所有命令都是空
    ["\u8FDE\u63A5\u5B58\u6D3B", "echo alive"],
    // 直接列 scrcpy 进程：如果这里还有进程，说明旧编码器被它占着，新 server 必然 Aborted。
    // 同样用 [c]om 括号技巧，避免把跑这条命令的 shell 自己列进去。
    ["scrcpy \u8FDB\u7A0B", `for d in $(grep -l "[c]om.genymobile.scrcpy.Server" /proc/[0-9]*/cmdline 2>/dev/null); do pid=$(echo $d | cut -d/ -f3); echo "pid=$pid $(cat $d 2>/dev/null | tr '\\0' ' ')"; done`],
    ["\u5C4F\u5E55\u72B6\u6001", "timeout 4 dumpsys power 2>/dev/null | grep -m3 -E 'mWakefulness=|mScreenOn=' | tr -d ' '"],
    // crash 缓冲区专存致命信号与 Java 崩溃，比在 main 里翻更准
    ["crash \u7F13\u51B2\u533A", "logcat -d -b crash -v threadtime 2>&1 | tail -40"],
    // 被信号打死不一定会进 crash 缓冲区，全缓冲区再筛一遍（含 AM 杀进程的记录）
    ["\u5168\u7F13\u51B2\u533A", "logcat -d -b all -v brief -t 600 2>&1 | grep -iE 'scrcpy|app_process|AndroidRuntime|abort|am_kill|lowmemorykiller' | tail -20"],
    // main 缓冲区只取最后 3000 行再筛，避免崩溃记录被刷走
    ["main \u7F13\u51B2\u533A", "logcat -d -v threadtime -t 3000 2>&1 | grep -iE 'scrcpy|AndroidRuntime|Fatal|avc' | tail -25"],
    // 设备到底支不支持/允许多少个虚拟显示：new_display 建不出来时这就是答案
    ["\u663E\u793A\u80FD\u529B", "timeout 4 dumpsys display 2>&1 | grep -E 'mDisplayId=|DisplayDeviceInfo|maxVirtualDisplay|type ' | head -20"]
  ];
  for (const [label, command] of commands) {
    try {
      const text = await shCmd(adb, command);
      const lines = String(text).split("\n").map((s) => s.replace(/\r$/, "").trimEnd()).filter((s) => s.trim());
      if (lines.length) {
        log(`\u8BBE\u5907\u7AEF\u65E5\u5FD7\xB7${label}\uFF08${lines.length} \u884C\uFF09\uFF1A`, "err");
        lines.forEach((line) => log("  " + line, "err"));
      } else {
        log(`\u8BBE\u5907\u7AEF\u65E5\u5FD7\xB7${label}\uFF1A\u65E0\u8F93\u51FA`, "dim");
      }
    } catch (error) {
      log(`\u8BBE\u5907\u7AEF\u65E5\u5FD7\xB7${label}\uFF1A\u8BFB\u53D6\u5931\u8D25\uFF08${error?.message || error}\uFF09`, "dim");
    }
  }
}
async function killServerByScid(adb, scid, log = () => {
}) {
  if (!scid) return 0;
  return killScrcpyProcs(adb, scid, log);
}
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
        capture.finished = copy.pipeTo(
          new WritableStream({
            write(chunk) {
              capture.text += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
            },
            close() {
              capture.text += decoder.decode();
            }
          })
        ).catch((error) => {
          capture.text += `\uFF08\u8F93\u51FA\u590D\u5236\u4E2D\u65AD\uFF1A${error?.message || error}\uFF09
`;
        });
      } catch (error) {
        capture.text += `\uFF08\u8F93\u51FA\u590D\u5236\u5931\u8D25\uFF1A${error?.message || error}\uFF09
`;
      }
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
        kill: () => process.kill()
      };
    }
  };
  capture.flush = async (ms = 800) => {
    if (capture.finished) {
      await Promise.race([capture.finished.catch(() => {
      }), new Promise((r) => setTimeout(r, ms))]);
    }
    await new Promise((r) => setTimeout(r, 120));
    return capture.text;
  };
  return capture;
}
async function replayServerCommand(adb, args, log = () => {
}, seconds = 6) {
  if (!Array.isArray(args) || !args.length) {
    log("[\u91CD\u653E] \u6CA1\u6709\u62FF\u5230\u539F\u59CB\u547D\u4EE4\u884C\uFF0C\u8DF3\u8FC7", "dim");
    return;
  }
  const safe = args.filter((item) => typeof item === "string" && item && !item.includes("'"));
  if (safe.length !== args.length) {
    log("[\u91CD\u653E] \u547D\u4EE4\u884C\u91CC\u6709\u5F15\u53F7\uFF0C\u8DF3\u8FC7\u91CD\u653E", "dim");
    return;
  }
  const [head, ...rest] = safe;
  const hasEnv = /^[A-Z_]+=/.test(head);
  const env = hasEnv ? head + " " : "";
  const bin = hasEnv ? rest.shift() : head;
  const script = `${env}timeout ${seconds} ${bin} ${rest.join(" ")} 2>&1; echo "__EXIT=$?"`;
  log(`[\u91CD\u653E] \u539F\u6837\u518D\u8DD1\u4E00\u904D\u8FD9\u6761\u547D\u4EE4\uFF0C\u6700\u591A\u7B49 ${seconds} \u79D2\u2026`, "dim");
  let text = "";
  try {
    text = await shCmd(adb, script);
  } catch (error) {
    log("[\u91CD\u653E] \u6267\u884C\u5931\u8D25\uFF1A" + (error?.message || error), "err");
    return;
  }
  const lines = String(text).split("\n").map((line) => line.replace(/\r$/, "")).filter((line) => line.trim());
  const exitLine = lines.find((line) => line.includes("__EXIT="));
  const exitCode = exitLine ? Number(exitLine.split("__EXIT=")[1]) : NaN;
  const code = Number.isFinite(exitCode) ? exitCode : null;
  if (code === null) {
    log(`[\u91CD\u653E] \u8DD1\u4E86 ${lines.length} \u884C\uFF0C\u4F46\u6CA1\u62FF\u5230\u9000\u51FA\u7801`, "dim");
  } else {
    log(`[\u91CD\u653E] \u9000\u51FA\u7801 ${code}${describeExit(code)}`);
  }
  lines.filter((line) => !line.includes("__EXIT=")).slice(-40).forEach((line) => log("  " + line, "err"));
}
function describeExit(code) {
  if (code === 124) return "\uFF08\u8FDB\u7A0B\u6D3B\u5F97\u597D\u597D\u7684\uFF0C\u53EA\u662F\u5728\u7B49 socket \u2014\u2014 \u8BF4\u660E\u8FD9\u6761\u547D\u4EE4\u672C\u8EAB\u6CA1\u95EE\u9898\uFF09";
  if (code === 134) return "\uFF08SIGABRT\uFF1A\u539F\u751F\u5C42 abort\uFF0C\u5F02\u5E38\u6808\u5728 logcat crash \u7F13\u51B2\u533A\uFF09";
  if (code === 139) return "\uFF08SIGSEGV\uFF1A\u539F\u751F\u5C42\u6BB5\u9519\u8BEF\uFF09";
  if (code === 1) return "\uFF08Java \u5C42\u629B\u5F02\u5E38\uFF0C\u4E0A\u9762\u5E94\u8BE5\u80FD\u770B\u5230 Error \u884C\uFF09";
  if (code === 0) return "\uFF08\u6B63\u5E38\u9000\u51FA\uFF09";
  return "";
}
async function getAndroidSdk(adb) {
  try {
    const out = String(await shCmd(adb, "getprop ro.build.version.sdk")).trim();
    const n = parseInt(out, 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

// node_modules/@yume-chan/scrcpy/esm/base/audio.js
var ScrcpyAudioCodec = class _ScrcpyAudioCodec {
  static Opus = /* @__PURE__ */ new _ScrcpyAudioCodec("opus", 1869641075, "audio/opus", "opus");
  static Aac = /* @__PURE__ */ new _ScrcpyAudioCodec("aac", 6381923, "audio/aac", "mp4a.66");
  static Flac = /* @__PURE__ */ new _ScrcpyAudioCodec("flac", 1718378851, "audio/flac", "flac");
  static Raw = /* @__PURE__ */ new _ScrcpyAudioCodec("raw", 7496055, "audio/raw", "");
  optionValue;
  metadataValue;
  mimeType;
  webCodecId;
  constructor(optionValue, metadataValue, mimeType, webCodecId) {
    this.optionValue = optionValue;
    this.metadataValue = metadataValue;
    this.mimeType = mimeType;
    this.webCodecId = webCodecId;
  }
  toOptionValue() {
    return this.optionValue;
  }
};

// node_modules/@yume-chan/scrcpy/esm/base/control-message-type.js
var ScrcpyControlMessageType = {
  InjectKeyCode: 0,
  InjectText: 1,
  InjectTouch: 2,
  InjectScroll: 3,
  BackOrScreenOn: 4,
  ExpandNotificationPanel: 5,
  ExpandSettingPanel: 6,
  CollapseNotificationPanel: 7,
  GetClipboard: 8,
  SetClipboard: 9,
  SetDisplayPower: 10,
  RotateDevice: 11,
  UHidCreate: 12,
  UHidInput: 13,
  UHidDestroy: 14,
  OpenHardKeyboardSettings: 15,
  StartApp: 16,
  ResetVideo: 17
};

// node_modules/@yume-chan/scrcpy/esm/base/device-message.js
var ScrcpyDeviceMessageParsers = class {
  #parsers = [];
  get parsers() {
    return this.#parsers;
  }
  #add(id, parser) {
    if (this.#parsers[id]) {
      throw new Error(`Duplicate parser for id ${id}`);
    }
    this.#parsers[id] = parser;
  }
  add(parser) {
    if (Array.isArray(parser.id)) {
      for (const id of parser.id) {
        this.#add(id, parser);
      }
    } else {
      this.#add(parser.id, parser);
    }
    return parser;
  }
  async parse(id, stream) {
    const parser = this.#parsers[id];
    if (!parser) {
      throw new Error(`Unknown device message id ${id}`);
    }
    return parser.parse(id, stream);
  }
  close() {
    for (const parser of this.#parsers) {
      parser.close();
    }
  }
  error(e) {
    for (const parser of this.#parsers) {
      parser.error(e);
    }
  }
};

// node_modules/@yume-chan/scrcpy/esm/base/option-value.js
function isScrcpyOptionValue(value) {
  return typeof value === "object" && value !== null && "toOptionValue" in value && typeof value.toOptionValue === "function";
}
function toScrcpyOptionValue(value, empty) {
  if (isScrcpyOptionValue(value)) {
    value = value.toOptionValue();
  }
  if (value === void 0) {
    return empty;
  }
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    throw new TypeError(`Invalid option value: ${JSON.stringify(value)}`);
  }
  return value.toString();
}

// node_modules/@yume-chan/scrcpy/esm/base/video.js
var ScrcpyVideoCodecId = {
  H264: 1748121140,
  H265: 1748121141,
  AV1: 6387249
};

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/index.js
var impl_exports = {};
__export(impl_exports, {
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes,
  Crop: () => Crop,
  Defaults: () => Defaults,
  InjectScrollControlMessage: () => InjectScrollControlMessage,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  ScrollController: () => ScrollController,
  SerializeOrder: () => SerializeOrder,
  SetClipboardControlMessage: () => SetClipboardControlMessage,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation,
  createMediaStreamTransformer: () => createMediaStreamTransformer,
  createScrollController: () => createScrollController,
  parseDisplay: () => parseDisplay,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays
});

// node_modules/@yume-chan/scrcpy/esm/android/key-event.js
var AndroidKeyEventAction = {
  Down: 0,
  Up: 1
};

// node_modules/@yume-chan/scrcpy/esm/control/empty.js
import { struct, u8 } from "@yume-chan/struct";
var EmptyControlMessage = struct({ type: u8 }, { littleEndian: false });

// node_modules/@yume-chan/scrcpy/esm/control/inject-key-code.js
import { struct as struct2, u32, u8 as u82 } from "@yume-chan/struct";
var ScrcpyInjectKeyCodeControlMessage = /* @__PURE__ */ (() => struct2({
  type: u82(ScrcpyControlMessageType.InjectKeyCode),
  action: u82(),
  keyCode: u32(),
  repeat: u32,
  metaState: u32()
}, { littleEndian: false }))();

// node_modules/@yume-chan/scrcpy/esm/control/inject-text.js
import { string, struct as struct3, u32 as u322, u8 as u83 } from "@yume-chan/struct";
var ScrcpyInjectTextControlMessage = struct3({ type: u83, text: string(u322) }, { littleEndian: false });

// node_modules/@yume-chan/scrcpy/esm/control/message-type-map.js
var ScrcpyControlMessageTypeMap = class {
  #types;
  constructor(options) {
    this.#types = options.controlMessageTypes;
  }
  get(type) {
    const value = this.#types.indexOf(type);
    if (value === -1) {
      throw new TypeError("Invalid or unsupported control message type");
    }
    return value;
  }
  fillMessageType(message, type) {
    message.type = this.get(type);
    return message;
  }
};

// node_modules/@yume-chan/scrcpy/esm/control/set-screen-power-mode.js
import { struct as struct4, u8 as u84 } from "@yume-chan/struct";
var ScrcpySetDisplayPowerControlMessage = struct4({ type: u84, mode: u84() }, { littleEndian: false });

// node_modules/@yume-chan/scrcpy/esm/control/start-app.js
import { string as string2, struct as struct5, u8 as u85 } from "@yume-chan/struct";
var ScrcpyStartAppControlMessage = struct5({
  type: u85,
  name: string2(u85)
}, { littleEndian: false });

// node_modules/@yume-chan/scrcpy/esm/control/uhid.js
import { buffer, struct as struct6, u16, u8 as u86 } from "@yume-chan/struct";
var ScrcpyUHidInputControlMessage = /* @__PURE__ */ (() => struct6({
  type: u86(ScrcpyControlMessageType.UHidInput),
  id: u16,
  data: buffer(u16)
}, { littleEndian: false }))();
var ScrcpyUHidDestroyControlMessage = struct6({ type: u86, id: u16 }, { littleEndian: false });

// node_modules/@yume-chan/scrcpy/esm/control/serializer.js
var ScrcpyControlMessageSerializer = class {
  #options;
  #typeMap;
  #scrollController;
  constructor(options) {
    this.#options = options;
    this.#typeMap = new ScrcpyControlMessageTypeMap(options);
    this.#scrollController = options.createScrollController();
  }
  injectKeyCode(message) {
    return ScrcpyInjectKeyCodeControlMessage.serialize(this.#typeMap.fillMessageType(message, ScrcpyControlMessageType.InjectKeyCode));
  }
  injectText(text) {
    return ScrcpyInjectTextControlMessage.serialize({
      text,
      type: this.#typeMap.get(ScrcpyControlMessageType.InjectText)
    });
  }
  /**
   * `pressure` is a float value between 0 and 1.
   */
  injectTouch(message) {
    return this.#options.serializeInjectTouchControlMessage(this.#typeMap.fillMessageType(message, ScrcpyControlMessageType.InjectTouch));
  }
  /**
   * `scrollX` and `scrollY` are float values between 0 and 1.
   */
  injectScroll(message) {
    return this.#scrollController.serializeScrollMessage(this.#typeMap.fillMessageType(message, ScrcpyControlMessageType.InjectScroll));
  }
  backOrScreenOn(action) {
    return this.#options.serializeBackOrScreenOnControlMessage({
      action,
      type: this.#typeMap.get(ScrcpyControlMessageType.BackOrScreenOn)
    });
  }
  setDisplayPower(mode) {
    return ScrcpySetDisplayPowerControlMessage.serialize({
      mode,
      type: this.#typeMap.get(ScrcpyControlMessageType.SetDisplayPower)
    });
  }
  expandNotificationPanel() {
    return EmptyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.ExpandNotificationPanel)
    });
  }
  expandSettingPanel() {
    return EmptyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.ExpandSettingPanel)
    });
  }
  collapseNotificationPanel() {
    return EmptyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.CollapseNotificationPanel)
    });
  }
  rotateDevice() {
    return EmptyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.RotateDevice)
    });
  }
  setClipboard(message) {
    return this.#options.serializeSetClipboardControlMessage({
      ...message,
      type: this.#typeMap.get(ScrcpyControlMessageType.SetClipboard)
    });
  }
  uHidCreate(message) {
    if (!this.#options.serializeUHidCreateControlMessage) {
      throw new Error("UHid not supported");
    }
    return this.#options.serializeUHidCreateControlMessage(this.#typeMap.fillMessageType(message, ScrcpyControlMessageType.UHidCreate));
  }
  uHidInput(message) {
    return ScrcpyUHidInputControlMessage.serialize(this.#typeMap.fillMessageType(message, ScrcpyControlMessageType.UHidInput));
  }
  uHidDestroy(id) {
    return ScrcpyUHidDestroyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.UHidDestroy),
      id
    });
  }
  startApp(name, options) {
    if (options?.searchByName) {
      name = "?" + name;
    }
    if (options?.forceStop) {
      name = "+" + name;
    }
    return ScrcpyStartAppControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.StartApp),
      name
    });
  }
  resetVideo() {
    return EmptyControlMessage.serialize({
      type: this.#typeMap.get(ScrcpyControlMessageType.ResetVideo)
    });
  }
};

// node_modules/@yume-chan/scrcpy/esm/control/writer.js
import { Consumable } from "@yume-chan/stream-extra";
var ScrcpyControlMessageWriter = class {
  #writer;
  #serializer;
  constructor(writer, options) {
    this.#writer = writer;
    this.#serializer = new ScrcpyControlMessageSerializer(options);
  }
  write(message) {
    return Consumable.WritableStream.write(this.#writer, message);
  }
  injectKeyCode(message) {
    return this.write(this.#serializer.injectKeyCode(message));
  }
  injectText(text) {
    return this.write(this.#serializer.injectText(text));
  }
  /**
   * `pressure` is a float value between 0 and 1.
   */
  injectTouch(message) {
    return this.write(this.#serializer.injectTouch(message));
  }
  /**
   * `scrollX` and `scrollY` are float values between 0 and 1.
   */
  async injectScroll(message) {
    const data = this.#serializer.injectScroll(message);
    if (data) {
      await this.write(data);
    }
  }
  async backOrScreenOn(action) {
    const data = this.#serializer.backOrScreenOn(action);
    if (data) {
      await this.write(data);
    }
  }
  setScreenPowerMode(mode) {
    return this.write(this.#serializer.setDisplayPower(mode));
  }
  expandNotificationPanel() {
    return this.write(this.#serializer.expandNotificationPanel());
  }
  expandSettingPanel() {
    return this.write(this.#serializer.expandSettingPanel());
  }
  collapseNotificationPanel() {
    return this.write(this.#serializer.collapseNotificationPanel());
  }
  rotateDevice() {
    return this.write(this.#serializer.rotateDevice());
  }
  async setClipboard(message) {
    const result = this.#serializer.setClipboard(message);
    if (result instanceof Uint8Array) {
      await this.write(result);
    } else {
      await this.write(result[0]);
      await result[1];
    }
  }
  uHidCreate(message) {
    return this.write(this.#serializer.uHidCreate(message));
  }
  uHidInput(message) {
    return this.write(this.#serializer.uHidInput(message));
  }
  uHidDestroy(id) {
    return this.write(this.#serializer.uHidDestroy(id));
  }
  startApp(name, options) {
    return this.write(this.#serializer.startApp(name, options));
  }
  resetVideo() {
    return this.write(this.#serializer.resetVideo());
  }
  releaseLock() {
    this.#writer.releaseLock();
  }
  async close() {
    await this.#writer.close();
  }
};

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/back-or-screen-on.js
var BackOrScreenOnControlMessage = EmptyControlMessage;
function serializeBackOrScreenOnControlMessage(message) {
  if (message.action === AndroidKeyEventAction.Down) {
    return BackOrScreenOnControlMessage.serialize(message);
  }
  return void 0;
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/clipboard-stream.js
import { PushReadableStream } from "@yume-chan/stream-extra";
import { string as string3, struct as struct7, u32 as u323 } from "@yume-chan/struct";
var ClipboardDeviceMessage = struct7({ content: string3(u323) }, { littleEndian: false });
var ClipboardStream = class extends PushReadableStream {
  #controller;
  id = 0;
  constructor() {
    let controller;
    super((controller_) => {
      controller = controller_;
    });
    this.#controller = controller;
  }
  async parse(_id, stream) {
    const message = await ClipboardDeviceMessage.deserialize(stream);
    await this.#controller.enqueue(message.content);
  }
  close() {
    this.#controller.close();
  }
  error(e) {
    this.#controller.error(e);
  }
};

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/control-message-types.js
var ControlMessageTypes = /* @__PURE__ */ (() => [
  /*  0 */
  ScrcpyControlMessageType.InjectKeyCode,
  /*  1 */
  ScrcpyControlMessageType.InjectText,
  /*  2 */
  ScrcpyControlMessageType.InjectTouch,
  /*  3 */
  ScrcpyControlMessageType.InjectScroll,
  /*  4 */
  ScrcpyControlMessageType.BackOrScreenOn,
  /*  5 */
  ScrcpyControlMessageType.ExpandNotificationPanel,
  /*  6 */
  ScrcpyControlMessageType.CollapseNotificationPanel,
  /*  7 */
  ScrcpyControlMessageType.GetClipboard,
  /*  8 */
  ScrcpyControlMessageType.SetClipboard,
  /*  9 */
  ScrcpyControlMessageType.SetDisplayPower,
  /* 10 */
  ScrcpyControlMessageType.RotateDevice
])();

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/init.js
var VideoOrientation = {
  Unlocked: -1,
  Portrait: 0,
  Landscape: 1,
  PortraitFlipped: 2,
  LandscapeFlipped: 3
};
function toDashCase(input) {
  return input.replace(/([A-Z])/g, "-$1").toLowerCase();
}
var CodecOptionTypes = {
  repeatPreviousFrameAfter: "long",
  maxPtsGapToEncoder: "long"
};
var CodecOptions = class _CodecOptions {
  static Empty = /* @__PURE__ */ new _CodecOptions();
  options;
  constructor(options = {}) {
    for (const [key, value] of Object.entries(options)) {
      if (value === void 0) {
        continue;
      }
      if (typeof value !== "number") {
        throw new Error(`Invalid option value for ${key}: ${String(value)}`);
      }
    }
    this.options = options;
  }
  toOptionValue() {
    const entries = Object.entries(this.options).filter(([, value]) => value !== void 0);
    if (entries.length === 0) {
      return void 0;
    }
    return entries.map(([key, value]) => {
      let result = toDashCase(key);
      const type = CodecOptionTypes[key];
      if (type) {
        result += `:${type}`;
      }
      result += `=${value}`;
      return result;
    }).join(",");
  }
};
var Crop = class {
  width;
  height;
  x;
  y;
  constructor(width, height, x, y) {
    this.width = width;
    this.height = height;
    this.x = x;
    this.y = y;
  }
  toOptionValue() {
    return `${this.width}:${this.height}:${this.x}:${this.y}`;
  }
};

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/defaults.js
var Defaults = {
  logLevel: "debug",
  maxSize: 0,
  bitRate: 8e6,
  maxFps: 0,
  lockVideoOrientation: VideoOrientation.Unlocked,
  tunnelForward: false,
  crop: void 0,
  sendFrameMeta: true,
  control: true,
  displayId: 0,
  showTouches: false,
  stayAwake: false,
  codecOptions: void 0
};

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/inject-touch.js
import { getUint16, setUint16 } from "@yume-chan/no-data-view";
import { field, struct as struct8, u16 as u162, u32 as u324, u64, u8 as u87 } from "@yume-chan/struct";

// node_modules/@yume-chan/scrcpy/esm/utils/clamp.js
function clamp(value, min, max) {
  if (value < min) {
    return min;
  }
  if (value > max) {
    return max;
  }
  return value;
}

// node_modules/@yume-chan/scrcpy/esm/utils/constants.js
var DefaultServerPath = "/data/local/tmp/scrcpy-server.jar";

// node_modules/@yume-chan/scrcpy/esm/utils/omit.js
// @__NO_SIDE_EFFECTS__
function omit(value, ...keys) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/inject-touch.js
var UnsignedFloat = field(2, "byob", (source, { buffer: buffer7, index, littleEndian }) => {
  source = clamp(source, -1, 1);
  source = source === 1 ? 65535 : source * 65536;
  setUint16(buffer7, index, source, littleEndian);
}, function* (then, reader, { littleEndian }) {
  const data = yield* then(reader.readExactly(2));
  const value = getUint16(data, 0, littleEndian);
  return value === 65535 ? 1 : value / 65536;
});
var PointerId = {
  Mouse: -1n,
  Finger: -2n,
  VirtualMouse: -3n,
  VirtualFinger: -4n
};
var InjectTouchControlMessage = struct8({
  type: u87,
  action: u87(),
  pointerId: u64,
  pointerX: u324,
  pointerY: u324,
  videoWidth: u162,
  videoHeight: u162,
  pressure: UnsignedFloat,
  buttons: u324
}, { littleEndian: false });
function serializeInjectTouchControlMessage(message) {
  return InjectTouchControlMessage.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/media-stream-transformer.js
import { StructDeserializeStream, TransformStream } from "@yume-chan/stream-extra";
import { buffer as buffer2, struct as struct9, u32 as u325, u64 as u642 } from "@yume-chan/struct";
var MediaStreamRawPacket = struct9({ pts: u642, data: buffer2(u325) }, { littleEndian: false });
var PtsConfig = 1n << 63n;
function createMediaStreamTransformer(options) {
  if (!options.sendFrameMeta) {
    return new TransformStream({
      transform(chunk, controller) {
        controller.enqueue({
          type: "data",
          data: chunk
        });
      }
    });
  }
  const deserializeStream = new StructDeserializeStream(MediaStreamRawPacket);
  return {
    writable: deserializeStream.writable,
    readable: deserializeStream.readable.pipeThrough(new TransformStream({
      transform(packet, controller) {
        if (packet.pts === PtsConfig) {
          controller.enqueue({
            type: "configuration",
            data: packet.data
          });
          return;
        }
        controller.enqueue({
          type: "data",
          pts: packet.pts,
          data: packet.data
        });
      }
    }))
  };
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/parse-display.js
function parseDisplay(line) {
  const match = line.match(/^\s+scrcpy --display (\d+)$/);
  if (match) {
    return {
      id: Number.parseInt(match[1], 10)
    };
  }
  return void 0;
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/parse-video-stream-metadata.js
import { getUint16BigEndian, getUint32BigEndian } from "@yume-chan/no-data-view";
import { BufferedReadableStream } from "@yume-chan/stream-extra";
import { decodeUtf8 } from "@yume-chan/struct";
async function readString(stream, maxLength) {
  const buffer7 = await stream.readExactly(maxLength);
  return decodeUtf8(buffer7.subarray(0, buffer7.indexOf(0)));
}
async function readU16(stream) {
  const buffer7 = await stream.readExactly(2);
  return getUint16BigEndian(buffer7, 0);
}
async function readU32(stream) {
  const buffer7 = await stream.readExactly(4);
  return getUint32BigEndian(buffer7, 0);
}
async function parseVideoStreamMetadata(stream) {
  const buffered = new BufferedReadableStream(stream);
  const metadata = {
    codec: ScrcpyVideoCodecId.H264
  };
  metadata.deviceName = await readString(buffered, 64);
  metadata.width = await readU16(buffered);
  metadata.height = await readU16(buffered);
  return { stream: buffered.release(), metadata };
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/scroll-controller.js
import { s32, struct as struct10, u16 as u163, u32 as u326, u8 as u88 } from "@yume-chan/struct";
var InjectScrollControlMessage = struct10({
  type: u88,
  pointerX: u326,
  pointerY: u326,
  videoWidth: u163,
  videoHeight: u163,
  scrollX: s32,
  scrollY: s32
}, { littleEndian: false });
var ScrollController = class {
  #accumulatedX = 0;
  #accumulatedY = 0;
  processMessage(message) {
    if (message.scrollX) {
      if (Math.sign(message.scrollX) !== Math.sign(this.#accumulatedX)) {
        this.#accumulatedX = message.scrollX;
      } else {
        this.#accumulatedX += message.scrollX;
      }
    }
    if (message.scrollY) {
      if (Math.sign(message.scrollY) !== Math.sign(this.#accumulatedY)) {
        this.#accumulatedY = message.scrollY;
      } else {
        this.#accumulatedY += message.scrollY;
      }
    }
    const integerX = this.#accumulatedX | 0;
    this.#accumulatedX -= integerX;
    const integerY = this.#accumulatedY | 0;
    this.#accumulatedY -= integerY;
    if (integerX === 0 && integerY === 0) {
      return void 0;
    }
    message.scrollX = integerX;
    message.scrollY = integerY;
    return message;
  }
  serializeScrollMessage(message) {
    const processed = this.processMessage(message);
    if (!processed) {
      return void 0;
    }
    return InjectScrollControlMessage.serialize(processed);
  }
};
function createScrollController() {
  return new ScrollController();
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/serialize-order.js
var SerializeOrder = [
  "logLevel",
  "maxSize",
  "bitRate",
  "maxFps",
  "lockVideoOrientation",
  "tunnelForward",
  "crop",
  "sendFrameMeta",
  "control",
  "displayId",
  "showTouches",
  "stayAwake",
  "codecOptions"
];

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/serialize.js
function serialize(options, order) {
  return order.map((key) => toScrcpyOptionValue(options[key], "-"));
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/set-clipboard.js
import { string as string4, struct as struct11, u32 as u327, u8 as u89 } from "@yume-chan/struct";
var SetClipboardControlMessage = struct11({ type: u89, content: string4(u327) }, { littleEndian: false });
function serializeSetClipboardControlMessage(message) {
  return SetClipboardControlMessage.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/1_15/impl/set-list-display.js
function setListDisplays(options) {
  options.displayId = -1;
}

// node_modules/@yume-chan/scrcpy/esm/1_17/impl/index.js
var impl_exports2 = {};
__export(impl_exports2, {
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes,
  Crop: () => Crop,
  Defaults: () => Defaults2,
  EncoderRegex: () => EncoderRegex,
  InjectScrollControlMessage: () => InjectScrollControlMessage,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  ScrollController: () => ScrollController,
  SerializeOrder: () => SerializeOrder2,
  SetClipboardControlMessage: () => SetClipboardControlMessage,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation,
  createMediaStreamTransformer: () => createMediaStreamTransformer,
  createScrollController: () => createScrollController,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_17/impl/defaults.js
var Defaults2 = /* @__PURE__ */ (() => ({
  ...impl_exports.Defaults,
  encoderName: void 0
}))();

// node_modules/@yume-chan/scrcpy/esm/1_17/impl/parse-encoder.js
function parseEncoder(line, encoderNameRegex) {
  const match = line.match(encoderNameRegex);
  if (match) {
    return { type: "video", name: match[1] };
  }
  return void 0;
}
var EncoderRegex = /^\s+scrcpy --encoder-name '([^']+)'$/;

// node_modules/@yume-chan/scrcpy/esm/1_17/impl/serialize-order.js
var SerializeOrder2 = /* @__PURE__ */ (() => [
  ...impl_exports.SerializeOrder,
  "encoderName"
])();

// node_modules/@yume-chan/scrcpy/esm/1_17/impl/set-list-encoder.js
function setListEncoders(options) {
  options.encoderName = "_";
}

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/index.js
var impl_exports3 = {};
__export(impl_exports3, {
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults3,
  EncoderRegex: () => EncoderRegex2,
  InjectScrollControlMessage: () => InjectScrollControlMessage,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  ScrollController: () => ScrollController,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer,
  createScrollController: () => createScrollController,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/back-or-screen-on.js
import { extend, u8 as u810 } from "@yume-chan/struct";
var BackOrScreenOnControlMessage2 = extend(impl_exports2.BackOrScreenOnControlMessage, { action: u810() });
function serializeBackOrScreenOnControlMessage2(message) {
  return BackOrScreenOnControlMessage2.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/control-message-types.js
var ControlMessageTypes2 = /* @__PURE__ */ (() => {
  const result = impl_exports2.ControlMessageTypes.slice();
  result.splice(6, 0, ScrcpyControlMessageType.ExpandSettingPanel);
  return result;
})();

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/init.js
var VideoOrientation2 = {
  Initial: -2,
  Unlocked: -1,
  Portrait: 0,
  Landscape: 1,
  PortraitFlipped: 2,
  LandscapeFlipped: 3
};

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/defaults.js
var Defaults3 = /* @__PURE__ */ (() => ({
  ...impl_exports2.Defaults,
  logLevel: "debug",
  lockVideoOrientation: VideoOrientation2.Unlocked,
  powerOffOnClose: false
}))();

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/parse-encoder.js
var EncoderRegex2 = /^\s+scrcpy --encoder '([^']+)'$/;

// node_modules/@yume-chan/scrcpy/esm/1_18/impl/serialize-order.js
var SerializeOrder3 = /* @__PURE__ */ (() => [
  ...impl_exports2.SerializeOrder,
  "powerOffOnClose"
])();

// node_modules/@yume-chan/scrcpy/esm/1_21/impl/index.js
var impl_exports4 = {};
__export(impl_exports4, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults4,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  ScrollController: () => ScrollController,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer,
  createScrollController: () => createScrollController,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_21/impl/defaults.js
var Defaults4 = /* @__PURE__ */ (() => ({
  ...impl_exports3.Defaults,
  clipboardAutosync: true
}))();

// node_modules/@yume-chan/scrcpy/esm/1_21/impl/parse-encoder.js
var EncoderRegex3 = /^\s+scrcpy --encoder-name '([^']+)'$/;

// node_modules/@yume-chan/scrcpy/esm/1_21/impl/serialize.js
function toSnakeCase(input) {
  return input.replace(/([A-Z])/g, "_$1").toLowerCase();
}
function serialize2(options, defaults) {
  const result = [];
  for (const [key, value] of Object.entries(options)) {
    const serializedValue = toScrcpyOptionValue(value, void 0);
    if (serializedValue === void 0) {
      continue;
    }
    const defaultValue = toScrcpyOptionValue(defaults[key], void 0);
    if (serializedValue === defaultValue) {
      continue;
    }
    result.push(`${toSnakeCase(key)}=${serializedValue}`);
  }
  return result;
}

// node_modules/@yume-chan/scrcpy/esm/1_21/impl/set-clipboard.js
import { PromiseResolver } from "@yume-chan/async";
import { string as string5, struct as struct12, u32 as u328, u64 as u643, u8 as u811 } from "@yume-chan/struct";
var AckClipboardDeviceMessage = struct12({ sequence: u643 }, { littleEndian: false });
var SetClipboardControlMessage2 = struct12({
  type: u811,
  sequence: u643,
  paste: u811(),
  content: string5(u328)
}, { littleEndian: false });
var AckClipboardHandler = class {
  #resolvers = /* @__PURE__ */ new Map();
  #closed = false;
  id = 1;
  async parse(_id, stream) {
    const message = await AckClipboardDeviceMessage.deserialize(stream);
    const resolver = this.#resolvers.get(message.sequence);
    if (resolver) {
      resolver.resolve();
      this.#resolvers.delete(message.sequence);
    }
  }
  close() {
    for (const resolver of this.#resolvers.values()) {
      resolver.reject();
    }
    this.#resolvers.clear();
    this.#closed = true;
  }
  error(e) {
    for (const resolver of this.#resolvers.values()) {
      resolver.reject(e);
    }
    this.#resolvers.clear();
    this.#closed = true;
  }
  serializeSetClipboardControlMessage(message) {
    if (message.sequence === 0n) {
      return SetClipboardControlMessage2.serialize(message);
    }
    if (this.#closed) {
      throw new Error();
    }
    const resolver = new PromiseResolver();
    this.#resolvers.set(message.sequence, resolver);
    return [
      SetClipboardControlMessage2.serialize(message),
      resolver.promise
    ];
  }
};

// node_modules/@yume-chan/scrcpy/esm/1_22/impl/index.js
var impl_exports5 = {};
__export(impl_exports5, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults5,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage2,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  ScrollController: () => ScrollController2,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer,
  createScrollController: () => createScrollController2,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata2,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_22/impl/defaults.js
var Defaults5 = /* @__PURE__ */ (() => ({
  ...impl_exports4.Defaults,
  downsizeOnError: true,
  sendDeviceMeta: true,
  sendDummyByte: true
}))();

// node_modules/@yume-chan/scrcpy/esm/1_22/impl/parse-video-stream-metadata.js
async function parseVideoStreamMetadata2(options, stream) {
  if (!options.sendDeviceMeta) {
    return { stream, metadata: { codec: ScrcpyVideoCodecId.H264 } };
  } else {
    return impl_exports4.parseVideoStreamMetadata(stream);
  }
}

// node_modules/@yume-chan/scrcpy/esm/1_22/impl/scroll-controller.js
import { extend as extend2, s32 as s322 } from "@yume-chan/struct";
var InjectScrollControlMessage2 = extend2(impl_exports4.InjectScrollControlMessage, { buttons: s322 });
var ScrollController2 = class extends impl_exports4.ScrollController {
  serializeScrollMessage(message) {
    const processed = this.processMessage(message);
    if (!processed) {
      return void 0;
    }
    return InjectScrollControlMessage2.serialize(processed);
  }
};
function createScrollController2() {
  return new ScrollController2();
}

// node_modules/@yume-chan/scrcpy/esm/1_23/impl/index.js
var impl_exports6 = {};
__export(impl_exports6, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults6,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage2,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController2,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController2,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata2,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_23/impl/defaults.js
var Defaults6 = /* @__PURE__ */ (() => ({
  ...impl_exports5.Defaults,
  cleanup: true
}))();

// node_modules/@yume-chan/scrcpy/esm/1_23/impl/media-stream-transformer.js
import { StructDeserializeStream as StructDeserializeStream2, TransformStream as TransformStream2 } from "@yume-chan/stream-extra";
var PtsKeyframe = 1n << 62n;
function createMediaStreamTransformer2(options) {
  if (!options.sendFrameMeta) {
    return new TransformStream2({
      transform(chunk, controller) {
        controller.enqueue({
          type: "data",
          data: chunk
        });
      }
    });
  }
  const deserializeStream = new StructDeserializeStream2(impl_exports5.MediaStreamRawPacket);
  return {
    writable: deserializeStream.writable,
    readable: deserializeStream.readable.pipeThrough(new TransformStream2({
      transform(packet, controller) {
        if (packet.pts === impl_exports5.PtsConfig) {
          controller.enqueue({
            type: "configuration",
            data: packet.data
          });
          return;
        }
        if (packet.pts & PtsKeyframe) {
          controller.enqueue({
            type: "data",
            keyframe: true,
            pts: packet.pts & ~PtsKeyframe,
            data: packet.data
          });
          return;
        }
        controller.enqueue({
          type: "data",
          keyframe: false,
          pts: packet.pts,
          data: packet.data
        });
      }
    }))
  };
}

// node_modules/@yume-chan/scrcpy/esm/1_24/impl/defaults.js
var Defaults7 = /* @__PURE__ */ (() => ({
  ...impl_exports6.Defaults,
  powerOn: true
}))();

// node_modules/@yume-chan/scrcpy/esm/1_25/impl/index.js
var impl_exports7 = {};
__export(impl_exports7, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults7,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseDisplay: () => parseDisplay,
  parseEncoder: () => parseEncoder,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata2,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays,
  setListEncoders: () => setListEncoders
});

// node_modules/@yume-chan/scrcpy/esm/1_25/impl/scroll-controller.js
import { getInt16, setInt16 } from "@yume-chan/no-data-view";
import { field as field2, struct as struct13, u16 as u164, u32 as u329, u8 as u812 } from "@yume-chan/struct";
var SignedFloat = field2(2, "byob", (value, { buffer: buffer7, index, littleEndian }) => {
  value = clamp(value, -1, 1);
  value = value === 1 ? 32767 : value * 32768;
  setInt16(buffer7, index, value, littleEndian);
}, function* (then, reader, { littleEndian }) {
  const data = yield* then(reader.readExactly(2));
  const value = getInt16(data, 0, littleEndian);
  return value === 32767 ? 1 : value / 32768;
});
var InjectScrollControlMessage3 = /* @__PURE__ */ (() => struct13({
  type: u812(ScrcpyControlMessageType.InjectScroll),
  pointerX: u329,
  pointerY: u329,
  videoWidth: u164,
  videoHeight: u164,
  scrollX: SignedFloat,
  scrollY: SignedFloat,
  buttons: u329
}, { littleEndian: false }))();
var ScrollController3 = class {
  serializeScrollMessage(message) {
    return InjectScrollControlMessage3.serialize(message);
  }
};
function createScrollController3() {
  return new ScrollController3();
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/index.js
var impl_exports8 = {};
__export(impl_exports8, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults8,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay2,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/defaults.js
var Defaults8 = /* @__PURE__ */ (() => ({
  ...omit(impl_exports7.Defaults, "bitRate", "codecOptions", "encoderName"),
  scid: void 0,
  videoCodec: "h264",
  videoBitRate: 8e6,
  videoCodecOptions: void 0,
  videoEncoder: void 0,
  audio: true,
  audioCodec: "opus",
  audioBitRate: 128e3,
  audioCodecOptions: void 0,
  audioEncoder: void 0,
  listEncoders: false,
  listDisplays: false,
  sendCodecMeta: true
}))();

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/init.js
var InstanceId = class _InstanceId {
  static NONE = /* @__PURE__ */ new _InstanceId(-1);
  static random() {
    return new _InstanceId(Math.random() * 2147483648 | 0);
  }
  value;
  constructor(value) {
    this.value = value;
  }
  toOptionValue() {
    if (this.value < 0) {
      return void 0;
    }
    return this.value.toString(16);
  }
};

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/inject-touch.js
import { struct as struct14, u16 as u165, u32 as u3210, u64 as u644, u8 as u813 } from "@yume-chan/struct";
var InjectTouchControlMessage2 = /* @__PURE__ */ (() => struct14({
  type: u813(ScrcpyControlMessageType.InjectTouch),
  action: u813(),
  pointerId: u644,
  pointerX: u3210,
  pointerY: u3210,
  videoWidth: u165,
  videoHeight: u165,
  pressure: impl_exports7.UnsignedFloat,
  actionButton: u3210,
  buttons: u3210
}, { littleEndian: false }))();
function serializeInjectTouchControlMessage2(message) {
  return InjectTouchControlMessage2.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/parse-audio-stream-metadata.js
import { getUint32BigEndian as getUint32BigEndian2 } from "@yume-chan/no-data-view";
import { BufferedReadableStream as BufferedReadableStream2, PushReadableStream as PushReadableStream2 } from "@yume-chan/stream-extra";
async function parseAudioStreamMetadata(stream, options) {
  const buffered = new BufferedReadableStream2(stream);
  const buffer7 = await buffered.readExactly(4);
  const codecMetadataValue = getUint32BigEndian2(buffer7, 0);
  switch (codecMetadataValue) {
    case 0:
      return {
        type: "disabled"
      };
    case 1:
      return {
        type: "errored"
      };
  }
  if (options.sendCodecMeta) {
    let codec2;
    switch (codecMetadataValue) {
      case ScrcpyAudioCodec.Raw.metadataValue:
        codec2 = ScrcpyAudioCodec.Raw;
        break;
      case ScrcpyAudioCodec.Opus.metadataValue:
        codec2 = ScrcpyAudioCodec.Opus;
        break;
      case ScrcpyAudioCodec.Aac.metadataValue:
        codec2 = ScrcpyAudioCodec.Aac;
        break;
      case ScrcpyAudioCodec.Flac.metadataValue:
        codec2 = ScrcpyAudioCodec.Flac;
        break;
      default:
        throw new Error(`Unknown audio codec metadata value: ${codecMetadataValue}`);
    }
    return {
      type: "success",
      codec: codec2,
      stream: buffered.release()
    };
  }
  let codec;
  switch (options.audioCodec) {
    case "raw":
      codec = ScrcpyAudioCodec.Raw;
      break;
    case "opus":
      codec = ScrcpyAudioCodec.Opus;
      break;
    case "aac":
      codec = ScrcpyAudioCodec.Aac;
      break;
    case "flac":
      codec = ScrcpyAudioCodec.Flac;
      break;
    default:
      throw new Error(`Unknown audio codec metadata value: ${codecMetadataValue}`);
  }
  return {
    type: "success",
    codec,
    stream: new PushReadableStream2(async (controller) => {
      await controller.enqueue(buffer7);
      const stream2 = buffered.release();
      const reader = stream2.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        await controller.enqueue(value);
      }
    })
  };
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/parse-display.js
function parseDisplay2(line) {
  const match = line.match(/^\s+--display=(\d+)\s+\(([^)]+)\)$/);
  if (match) {
    const display = {
      id: Number.parseInt(match[1], 10)
    };
    if (match[2] !== "size unknown") {
      display.resolution = match[2];
    }
    return display;
  }
  return void 0;
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/parse-encoder.js
var EncoderRegex4 = /^\s+--(video|audio)-codec=(\S+)\s+--\1-encoder='([^']+)'$/;
function parseEncoder2(line) {
  const match = line.match(EncoderRegex4);
  return match ? {
    type: match[1],
    name: match[3],
    codec: match[2]
  } : void 0;
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/parse-video-stream-metadata.js
import { BufferedReadableStream as BufferedReadableStream3 } from "@yume-chan/stream-extra";
function toCodecId(codec) {
  switch (codec) {
    case "h264":
      return ScrcpyVideoCodecId.H264;
    case "h265":
      return ScrcpyVideoCodecId.H265;
    case "av1":
      return ScrcpyVideoCodecId.AV1;
    default:
      throw new Error(`Unknown video codec: ${codec}`);
  }
}
async function parseAsync(options, stream) {
  const buffered = new BufferedReadableStream3(stream);
  let deviceName;
  if (options.sendDeviceMeta) {
    deviceName = await impl_exports7.readString(buffered, 64);
  }
  let codec;
  let width;
  let height;
  if (options.sendCodecMeta) {
    codec = await impl_exports7.readU32(buffered);
    width = await impl_exports7.readU32(buffered);
    height = await impl_exports7.readU32(buffered);
  } else {
    codec = toCodecId(options.videoCodec);
  }
  return {
    stream: buffered.release(),
    metadata: { deviceName, codec, width, height }
  };
}
function parseVideoStreamMetadata3(options, stream) {
  if (!options.sendDeviceMeta && !options.sendCodecMeta) {
    return {
      stream,
      metadata: { codec: toCodecId(options.videoCodec) }
    };
  }
  return parseAsync(options, stream);
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/set-list-display.js
function setListDisplays2(options) {
  options.listDisplays = true;
}

// node_modules/@yume-chan/scrcpy/esm/2_0/impl/set-list-encoder.js
function setListEncoders2(options) {
  options.listEncoders = true;
}

// node_modules/@yume-chan/scrcpy/esm/2_1/impl/index.js
var impl_exports9 = {};
__export(impl_exports9, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults9,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay2,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_1/impl/defaults.js
var Defaults9 = /* @__PURE__ */ (() => ({
  ...impl_exports8.Defaults,
  video: true,
  audioSource: "output"
}))();

// node_modules/@yume-chan/scrcpy/esm/2_2/impl/defaults.js
var Defaults10 = /* @__PURE__ */ (() => ({
  ...impl_exports9.Defaults,
  videoSource: "display",
  displayId: 0,
  cameraId: void 0,
  cameraSize: void 0,
  cameraFacing: void 0,
  cameraAr: void 0,
  cameraFps: void 0,
  cameraHighSpeed: false,
  listCameras: false,
  listCameraSizes: false
}))();

// node_modules/@yume-chan/scrcpy/esm/2_2/impl/parse-display.js
function parseDisplay3(line) {
  const match = line.match(/^\s+--display-id=(\d+)\s+\(([^)]+)\)$/);
  if (match) {
    const display = {
      id: Number.parseInt(match[1], 10)
    };
    if (match[2] !== "size unknown") {
      display.resolution = match[2];
    }
    return display;
  }
  return void 0;
}

// node_modules/@yume-chan/scrcpy/esm/2_3/impl/index.js
var impl_exports10 = {};
__export(impl_exports10, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes2,
  Crop: () => Crop,
  Defaults: () => Defaults10,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_4/impl/index.js
var impl_exports11 = {};
__export(impl_exports11, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes3,
  Crop: () => Crop,
  Defaults: () => Defaults10,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_4/impl/control-message-types.js
var ControlMessageTypes3 = /* @__PURE__ */ (() => [
  ...impl_exports10.ControlMessageTypes,
  ScrcpyControlMessageType.UHidCreate,
  ScrcpyControlMessageType.UHidInput,
  ScrcpyControlMessageType.OpenHardKeyboardSettings
])();

// node_modules/@yume-chan/scrcpy/esm/2_4/impl/serialize-uhid-create.js
import { buffer as buffer3, struct as struct15, u16 as u166, u8 as u814 } from "@yume-chan/struct";
var UHidCreateControlMessage = struct15({
  type: u814,
  id: u166,
  data: buffer3(u166)
}, { littleEndian: false });
function serializeUHidCreateControlMessage(message) {
  return UHidCreateControlMessage.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/2_4/impl/uhid-output-stream.js
import { PushReadableStream as PushReadableStream3 } from "@yume-chan/stream-extra";
import { buffer as buffer4, struct as struct16, u16 as u167 } from "@yume-chan/struct";
var UHidOutputDeviceMessage = struct16({
  id: u167,
  data: buffer4(u167)
}, { littleEndian: false });
var UHidOutputStream = class extends PushReadableStream3 {
  #controller;
  id = 2;
  constructor() {
    let controller;
    super((controller_) => {
      controller = controller_;
    });
    this.#controller = controller;
  }
  async parse(_id, stream) {
    const message = await UHidOutputDeviceMessage.deserialize(stream);
    await this.#controller.enqueue(message);
  }
  close() {
    this.#controller.close();
  }
  error(e) {
    this.#controller.error(e);
  }
};

// node_modules/@yume-chan/scrcpy/esm/2_6/impl/index.js
var impl_exports12 = {};
__export(impl_exports12, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes3,
  Crop: () => Crop,
  Defaults: () => Defaults11,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_6/impl/defaults.js
var Defaults11 = /* @__PURE__ */ (() => ({
  ...impl_exports11.Defaults,
  audioDup: false
}))();

// node_modules/@yume-chan/scrcpy/esm/2_7/impl/index.js
var impl_exports13 = {};
__export(impl_exports13, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes4,
  Crop: () => Crop,
  Defaults: () => Defaults11,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage2,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder2,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage2,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/2_7/impl/control-message-types.js
var ControlMessageTypes4 = /* @__PURE__ */ (() => {
  const result = impl_exports12.ControlMessageTypes.slice();
  result.splice(14, 0, ScrcpyControlMessageType.UHidDestroy);
  return result;
})();

// node_modules/@yume-chan/scrcpy/esm/2_7/impl/serialize-uhid-create.js
import { buffer as buffer5, string as string6, struct as struct17, u16 as u168, u8 as u815 } from "@yume-chan/struct";
var UHidCreateControlMessage2 = struct17({
  type: u815,
  id: u168,
  name: string6(u815),
  data: buffer5(u168)
}, { littleEndian: false });
function serializeUHidCreateControlMessage2(message) {
  return UHidCreateControlMessage2.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/3_0/impl/index.js
var impl_exports14 = {};
__export(impl_exports14, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  CaptureOrientation: () => CaptureOrientation,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes5,
  Crop: () => Crop,
  Defaults: () => Defaults12,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  LockOrientation: () => LockOrientation,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  NewDisplay: () => NewDisplay,
  Orientation: () => Orientation,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage2,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder3,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage2,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/3_0/impl/control-message-types.js
var ControlMessageTypes5 = /* @__PURE__ */ (() => [
  ...impl_exports13.ControlMessageTypes,
  ScrcpyControlMessageType.StartApp,
  ScrcpyControlMessageType.ResetVideo
])();

// node_modules/@yume-chan/scrcpy/esm/3_0/impl/defaults.js
var Defaults12 = /* @__PURE__ */ (() => ({
  ...omit(impl_exports13.Defaults, "lockVideoOrientation"),
  captureOrientation: void 0,
  angle: 0,
  screenOffTimeout: void 0,
  listApps: false,
  newDisplay: void 0,
  vdSystemDecorations: true
}))();

// node_modules/@yume-chan/scrcpy/esm/3_0/impl/init.js
var LockOrientation = {
  Unlocked: 0,
  LockedInitial: 1,
  LockedValue: 2
};
var Orientation = {
  Orient0: 0,
  Orient90: 90,
  Orient180: 180,
  Orient270: 270
};
var CaptureOrientation = class _CaptureOrientation {
  static Unlocked = /* @__PURE__ */ (() => new _CaptureOrientation(LockOrientation.Unlocked, Orientation.Orient0, false))();
  lock;
  orientation;
  flip;
  constructor(lock, orientation, flip = false) {
    this.lock = lock;
    this.orientation = orientation;
    this.flip = flip;
  }
  toOptionValue() {
    if (this.lock === LockOrientation.Unlocked && this.orientation === Orientation.Orient0 && !this.flip) {
      return void 0;
    }
    if (this.lock === LockOrientation.LockedInitial) {
      return "@";
    }
    return (this.lock === LockOrientation.LockedValue ? "@" : "") + (this.flip ? "flip" : "") + this.orientation;
  }
};
var NewDisplay = class _NewDisplay {
  static Default = /* @__PURE__ */ new _NewDisplay();
  width;
  height;
  dpi;
  constructor(a, b, c) {
    if (a === void 0) {
      return;
    }
    if (b === void 0) {
      this.dpi = a;
      return;
    }
    this.width = a;
    this.height = b;
    this.dpi = c;
  }
  toOptionValue() {
    if (this.width === void 0 && this.height === void 0 && this.dpi === void 0) {
      return "";
    }
    if (this.width === void 0) {
      return `/${this.dpi}`;
    }
    if (this.dpi === void 0) {
      return `${this.width}x${this.height}`;
    }
    return `${this.width}x${this.height}/${this.dpi}`;
  }
};

// node_modules/@yume-chan/scrcpy/esm/3_0/impl/parse-encoder.js
var EncoderRegex5 = /^\s+--(video|audio)-codec=(\S+)\s+--\1-encoder=(\S+)(?:\s*\((sw|hw|hybrid)\))?(?:\s*\[vendor\])?(?:\s*\(alias for (\S+)\))?$/;
function toHardwareType(value) {
  switch (value) {
    case "sw":
      return "software";
    case "hw":
      return "hardware";
    case "hybrid":
      return "hybrid";
    default:
      throw new Error(`Unknown hardware type: ${value}`);
  }
}
function parseEncoder3(line) {
  const match = line.match(EncoderRegex5);
  return match ? {
    type: match[1],
    name: match[3],
    codec: match[2],
    hardwareType: match[4] ? toHardwareType(match[4]) : void 0,
    vendor: !!match[5],
    aliasFor: match[6]
  } : void 0;
}

// node_modules/@yume-chan/scrcpy/esm/3_1/impl/index.js
var impl_exports15 = {};
__export(impl_exports15, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  CaptureOrientation: () => CaptureOrientation,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes5,
  Crop: () => Crop,
  Defaults: () => Defaults13,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  LockOrientation: () => LockOrientation,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  NewDisplay: () => NewDisplay,
  Orientation: () => Orientation,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage3,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder3,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage3,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/3_1/impl/defaults.js
var Defaults13 = /* @__PURE__ */ (() => ({
  ...impl_exports14.Defaults,
  vdDestroyContent: false
}))();

// node_modules/@yume-chan/scrcpy/esm/3_1/impl/serialize-uhid-create.js
import { buffer as buffer6, string as string7, struct as struct18, u16 as u169, u8 as u816 } from "@yume-chan/struct";
var UHidCreateControlMessage3 = struct18({
  type: u816,
  id: u169,
  vendorId: u169,
  productId: u169,
  name: string7(u816),
  data: buffer6(u169)
}, { littleEndian: false });
function serializeUHidCreateControlMessage3(message) {
  return UHidCreateControlMessage3.serialize(message);
}

// node_modules/@yume-chan/scrcpy/esm/3_2/impl/index.js
var impl_exports16 = {};
__export(impl_exports16, {
  AckClipboardDeviceMessage: () => AckClipboardDeviceMessage,
  AckClipboardHandler: () => AckClipboardHandler,
  BackOrScreenOnControlMessage: () => BackOrScreenOnControlMessage2,
  CaptureOrientation: () => CaptureOrientation,
  ClipboardDeviceMessage: () => ClipboardDeviceMessage,
  ClipboardStream: () => ClipboardStream,
  CodecOptions: () => CodecOptions,
  ControlMessageTypes: () => ControlMessageTypes5,
  Crop: () => Crop,
  Defaults: () => Defaults14,
  EncoderRegex: () => EncoderRegex3,
  InjectScrollControlMessage: () => InjectScrollControlMessage3,
  InjectTouchControlMessage: () => InjectTouchControlMessage2,
  InstanceId: () => InstanceId,
  LockOrientation: () => LockOrientation,
  MediaStreamRawPacket: () => MediaStreamRawPacket,
  NewDisplay: () => NewDisplay,
  Orientation: () => Orientation,
  PointerId: () => PointerId,
  PtsConfig: () => PtsConfig,
  PtsKeyframe: () => PtsKeyframe,
  ScrollController: () => ScrollController3,
  SerializeOrder: () => SerializeOrder3,
  SetClipboardControlMessage: () => SetClipboardControlMessage2,
  SignedFloat: () => SignedFloat,
  UHidCreateControlMessage: () => UHidCreateControlMessage3,
  UHidOutputDeviceMessage: () => UHidOutputDeviceMessage,
  UHidOutputStream: () => UHidOutputStream,
  UnsignedFloat: () => UnsignedFloat,
  VideoOrientation: () => VideoOrientation2,
  createMediaStreamTransformer: () => createMediaStreamTransformer2,
  createScrollController: () => createScrollController3,
  parseAudioStreamMetadata: () => parseAudioStreamMetadata,
  parseDisplay: () => parseDisplay3,
  parseEncoder: () => parseEncoder3,
  parseVideoStreamMetadata: () => parseVideoStreamMetadata3,
  readString: () => readString,
  readU16: () => readU16,
  readU32: () => readU32,
  serialize: () => serialize2,
  serializeBackOrScreenOnControlMessage: () => serializeBackOrScreenOnControlMessage2,
  serializeInjectTouchControlMessage: () => serializeInjectTouchControlMessage2,
  serializeSetClipboardControlMessage: () => serializeSetClipboardControlMessage,
  serializeUHidCreateControlMessage: () => serializeUHidCreateControlMessage3,
  setListDisplays: () => setListDisplays2,
  setListEncoders: () => setListEncoders2
});

// node_modules/@yume-chan/scrcpy/esm/3_2/impl/defaults.js
var Defaults14 = /* @__PURE__ */ (() => ({
  ...impl_exports15.Defaults,
  displayImePolicy: void 0
}))();

// node_modules/@yume-chan/scrcpy/esm/3_3_1/impl/scroll-controller.js
var ScrollController4 = class {
  serializeScrollMessage(message) {
    message = {
      ...message,
      scrollX: message.scrollX / 16,
      scrollY: message.scrollY / 16
    };
    return impl_exports16.InjectScrollControlMessage.serialize(message);
  }
};
function createScrollController4() {
  return new ScrollController4();
}

// node_modules/@yume-chan/scrcpy/esm/3_3_1/options.js
var ScrcpyOptions3_3_1 = class {
  static Defaults = Defaults14;
  value;
  get controlMessageTypes() {
    return ControlMessageTypes5;
  }
  #clipboard;
  get clipboard() {
    return this.#clipboard;
  }
  #ackClipboardHandler;
  #uHidOutput;
  get uHidOutput() {
    return this.#uHidOutput;
  }
  #deviceMessageParsers = new ScrcpyDeviceMessageParsers();
  get deviceMessageParsers() {
    return this.#deviceMessageParsers;
  }
  constructor(init) {
    this.value = { ...Defaults14, ...init };
    if (this.value.videoSource === "camera") {
      this.value.control = false;
    }
    if (this.value.audioDup) {
      this.value.audioSource = "playback";
    }
    if (this.value.control) {
      if (this.value.clipboardAutosync) {
        this.#clipboard = this.#deviceMessageParsers.add(new ClipboardStream());
        this.#ackClipboardHandler = this.#deviceMessageParsers.add(new AckClipboardHandler());
      }
      this.#uHidOutput = this.#deviceMessageParsers.add(new UHidOutputStream());
    }
  }
  serialize() {
    return serialize2(this.value, Defaults14);
  }
  setListDisplays() {
    setListDisplays2(this.value);
  }
  parseDisplay(line) {
    return parseDisplay3(line);
  }
  setListEncoders() {
    setListEncoders2(this.value);
  }
  parseEncoder(line) {
    return parseEncoder3(line);
  }
  parseVideoStreamMetadata(stream) {
    return parseVideoStreamMetadata3(this.value, stream);
  }
  parseAudioStreamMetadata(stream) {
    return parseAudioStreamMetadata(stream, this.value);
  }
  createMediaStreamTransformer() {
    return createMediaStreamTransformer2(this.value);
  }
  serializeInjectTouchControlMessage(message) {
    return serializeInjectTouchControlMessage2(message);
  }
  serializeBackOrScreenOnControlMessage(message) {
    return serializeBackOrScreenOnControlMessage2(message);
  }
  serializeSetClipboardControlMessage(message) {
    return this.#ackClipboardHandler.serializeSetClipboardControlMessage(message);
  }
  createScrollController() {
    return createScrollController4();
  }
  serializeUHidCreateControlMessage(message) {
    return serializeUHidCreateControlMessage3(message);
  }
};

// node_modules/@yume-chan/scrcpy/esm/codec/av1.js
var AndroidAv1Profile = {
  Main8: 1 << 0,
  Main10: 1 << 1,
  Main10Hdr10: 1 << 12,
  Main10Hdr10Plus: 1 << 13
};
var AndroidAv1Level = {
  Level2: 1 << 0,
  Level21: 1 << 1,
  Level22: 1 << 2,
  Level23: 1 << 3,
  Level3: 1 << 4,
  Level31: 1 << 5,
  Level32: 1 << 6,
  Level33: 1 << 7,
  Level4: 1 << 8,
  Level41: 1 << 9,
  Level42: 1 << 10,
  Level43: 1 << 11,
  Level5: 1 << 12,
  Level51: 1 << 13,
  Level52: 1 << 14,
  Level53: 1 << 15,
  Level6: 1 << 16,
  Level61: 1 << 17,
  Level62: 1 << 18,
  Level63: 1 << 19,
  Level7: 1 << 20,
  Level71: 1 << 21,
  Level72: 1 << 22,
  Level73: 1 << 23
};
var BitReader = class {
  #data;
  #byte;
  #bytePosition = 0;
  #bitPosition = 7;
  get byteAligned() {
    return this.#bitPosition === 7;
  }
  get ended() {
    return this.#bytePosition >= this.#data.length;
  }
  constructor(data) {
    this.#data = data;
    this.#byte = data[0];
  }
  f1() {
    const value = this.#byte >> this.#bitPosition;
    this.#bitPosition -= 1;
    if (this.#bitPosition < 0) {
      this.#bytePosition += 1;
      this.#bitPosition = 7;
      this.#byte = this.#data[this.#bytePosition];
    }
    return value & 1;
  }
  f(n) {
    let value = 0;
    for (; n > 0; n -= 1) {
      value <<= 1;
      value |= this.f1();
    }
    return value;
  }
  skip(n) {
    if (n <= this.#bitPosition + 1) {
      this.#bytePosition += 1;
      this.#bitPosition = 7;
      this.#byte = this.#data[this.#bytePosition];
      return;
    }
    n -= this.#bitPosition + 1;
    this.#bytePosition += 1;
    const bytes = n / 8 | 0;
    if (bytes > 0) {
      this.#bytePosition += bytes;
      n -= bytes * 8;
    }
    this.#bitPosition = 7 - n;
    this.#byte = this.#data[this.#bytePosition];
  }
  readBytes(n) {
    if (!this.byteAligned) {
      throw new Error("Bytes must be byte-aligned");
    }
    const value = this.#data.subarray(this.#bytePosition, this.#bytePosition + n);
    this.#bytePosition += n;
    this.#byte = this.#data[this.#bytePosition];
    return value;
  }
  getPosition() {
    return [this.#bytePosition, this.#bitPosition];
  }
  setPosition([bytePosition, bitPosition]) {
    this.#bytePosition = bytePosition;
    this.#bitPosition = bitPosition;
    this.#byte = this.#data[bytePosition];
  }
};
var ObuType = {
  SequenceHeader: 1,
  TemporalDelimiter: 2,
  FrameHeader: 3,
  TileGroup: 4,
  Metadata: 5,
  Frame: 6,
  RedundantFrameHeader: 7,
  TileList: 8,
  Padding: 15
};
var ColorPrimaries = {
  Bt709: 1,
  Unspecified: 2,
  Bt470M: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  GenericFilm: 8,
  Bt2020: 9,
  Xyz: 10,
  Smpte431: 11,
  Smpte432: 12,
  Ebu3213: 22
};
var TransferCharacteristics = {
  Bt709: 1,
  Unspecified: 2,
  Bt470M: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  Linear: 8,
  Log100: 9,
  Log100Sqrt10: 10,
  Iec61966: 11,
  Bt1361: 12,
  Srgb: 13,
  Bt2020Ten: 14,
  Bt2020Twelve: 15,
  Smpte2084: 16,
  Smpte428: 17,
  Hlg: 18
};
var MatrixCoefficients = {
  Identity: 0,
  Bt709: 1,
  Unspecified: 2,
  Fcc: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  YCgCo: 8,
  Bt2020Ncl: 9,
  Bt2020Cl: 10,
  Smpte2085: 11,
  ChromatNcl: 12,
  ChromatCl: 13,
  ICtCp: 14
};
var Av1 = class _Av1 extends BitReader {
  static ObuType = ObuType;
  static ColorPrimaries = ColorPrimaries;
  static TransferCharacteristics = TransferCharacteristics;
  static MatrixCoefficients = MatrixCoefficients;
  #Leb128Bytes = 0;
  uvlc() {
    let leadingZeros = 0;
    while (!this.f1()) {
      leadingZeros += 1;
    }
    if (leadingZeros >= 32) {
      return 2 ** 32 - 1;
    }
    const value = this.f(leadingZeros);
    return value + (1 << leadingZeros >>> 0) - 1;
  }
  leb128() {
    if (!this.byteAligned) {
      throw new Error("LEB128 must be byte-aligned");
    }
    let value = 0n;
    this.#Leb128Bytes = 0;
    for (let i = 0n; i < 8n; i += 1n) {
      const leb128_byte = this.f(8);
      value |= BigInt(leb128_byte & 127) << 7n * i;
      this.#Leb128Bytes += 1;
      if ((leb128_byte & 128) == 0) {
        break;
      }
    }
    return value;
  }
  *annexBBitstream() {
    while (!this.ended) {
      const temporal_unit_size = this.leb128();
      yield* this.temporalUnit(temporal_unit_size);
    }
  }
  *temporalUnit(sz) {
    while (sz > 0) {
      const frame_unit_size = this.leb128();
      sz -= BigInt(this.#Leb128Bytes);
      yield* this.frameUnit(frame_unit_size);
      sz -= frame_unit_size;
    }
  }
  *frameUnit(sz) {
    while (sz > 0) {
      const obu_length = this.leb128();
      sz -= BigInt(this.#Leb128Bytes);
      const obu = this.openBitstreamUnit(obu_length);
      if (obu) {
        yield obu;
      }
      sz -= obu_length;
    }
  }
  #OperatingPointIdc = 0;
  openBitstreamUnit(sz) {
    const obu_header = this.obuHeader();
    let obu_size;
    if (obu_header.obu_has_size_field) {
      obu_size = this.leb128();
    } else if (sz !== void 0) {
      obu_size = sz - 1n - (obu_header.obu_extension_flag ? 1n : 0n);
    } else {
      throw new Error("obu_has_size_field must be true");
    }
    const startPosition = this.getPosition();
    if (obu_header.obu_type !== _Av1.ObuType.SequenceHeader && obu_header.obu_type !== _Av1.ObuType.TemporalDelimiter && this.#OperatingPointIdc !== 0 && obu_header.obu_extension_header) {
      const inTemporalLayer = !!(this.#OperatingPointIdc & 1 << obu_header.obu_extension_header.temporal_id);
      const inSpatialLayer = !!(this.#OperatingPointIdc & 1 << obu_header.obu_extension_header.spatial_id + 8);
      if (!inTemporalLayer || !inSpatialLayer) {
        this.skip(Number(obu_size));
        return;
      }
    }
    let sequence_header_obu;
    switch (obu_header.obu_type) {
      case _Av1.ObuType.SequenceHeader:
        sequence_header_obu = this.sequenceHeaderObu();
        break;
    }
    const currentPosition = this.getPosition();
    const payloadBits = (currentPosition[0] - startPosition[0]) * 8 + (startPosition[1] - currentPosition[1]);
    if (obu_size > 0) {
      this.skip(Number(obu_size) * 8 - payloadBits);
    }
    return {
      obu_header,
      obu_size,
      sequence_header_obu
    };
  }
  obuHeader() {
    const obu_forbidden_bit = !!this.f1();
    if (obu_forbidden_bit) {
      throw new Error("Invalid data");
    }
    const obu_type = this.f(4);
    const obu_extension_flag = !!this.f1();
    const obu_has_size_field = !!this.f1();
    this.f1();
    let obu_extension_header;
    if (obu_extension_flag) {
      obu_extension_header = this.obuExtensionHeader();
    }
    return {
      obu_type,
      obu_extension_flag,
      obu_has_size_field,
      obu_extension_header
    };
  }
  obuExtensionHeader() {
    const temporal_id = this.f(3);
    const spatial_id = this.f(2);
    this.skip(3);
    return { temporal_id, spatial_id };
  }
  static SelectScreenContentTools = 2;
  static SelectIntegerMv = 2;
  sequenceHeaderObu() {
    const seq_profile = this.f(3);
    const still_picture = !!this.f1();
    const reduced_still_picture_header = !!this.f1();
    let timing_info_present_flag = false;
    let timing_info;
    let decoder_model_info_present_flag = false;
    let decoder_model_info;
    let initial_display_delay_present_flag = false;
    let operating_points_cnt_minus_1 = 0;
    const operating_point_idc = [];
    const seq_level_idx = [];
    const seq_tier = [];
    const decoder_model_present_for_this_op = [];
    const initial_display_delay_present_for_this_op = [];
    let operating_parameters_info;
    let initial_display_delay_minus_1;
    if (reduced_still_picture_header) {
      operating_point_idc[0] = 0;
      seq_level_idx[0] = this.f(5);
      seq_tier[0] = 0;
      decoder_model_present_for_this_op[0] = false;
      initial_display_delay_present_for_this_op[0] = false;
    } else {
      timing_info_present_flag = !!this.f1();
      if (timing_info_present_flag) {
        timing_info = this.timingInfo();
        decoder_model_info_present_flag = !!this.f1();
        if (decoder_model_info_present_flag) {
          decoder_model_info = this.decoderModelInfo();
          operating_parameters_info = [];
        }
      }
      initial_display_delay_present_flag = !!this.f1();
      if (initial_display_delay_present_flag) {
        initial_display_delay_minus_1 = [];
      }
      operating_points_cnt_minus_1 = this.f(5);
      for (let i = 0; i <= operating_points_cnt_minus_1; i += 1) {
        operating_point_idc[i] = this.f(12);
        seq_level_idx[i] = this.f(5);
        if (seq_level_idx[i] > 7) {
          seq_tier[i] = this.f1();
        } else {
          seq_tier[i] = 0;
        }
        if (decoder_model_info_present_flag) {
          decoder_model_present_for_this_op[i] = !!this.f1();
          if (decoder_model_present_for_this_op[i]) {
            operating_parameters_info[i] = this.operatingParametersInfo(decoder_model_info);
          }
        } else {
          decoder_model_present_for_this_op[i] = false;
        }
        if (initial_display_delay_present_flag) {
          initial_display_delay_present_for_this_op[i] = !!this.f1();
          if (initial_display_delay_present_for_this_op[i]) {
            initial_display_delay_minus_1[i] = this.f(4);
          }
        }
      }
    }
    const operatingPoint = this.chooseOperatingPoint();
    this.#OperatingPointIdc = operating_point_idc[operatingPoint];
    const frame_width_bits_minus_1 = this.f(4);
    const frame_height_bits_minus_1 = this.f(4);
    const max_frame_width_minus_1 = this.f(frame_width_bits_minus_1 + 1);
    const max_frame_height_minus_1 = this.f(frame_height_bits_minus_1 + 1);
    let frame_id_numbers_present_flag = false;
    let delta_frame_id_length_minus_2;
    let additional_frame_id_length_minus_1;
    if (!reduced_still_picture_header) {
      frame_id_numbers_present_flag = !!this.f1();
      if (frame_id_numbers_present_flag) {
        delta_frame_id_length_minus_2 = this.f(4);
        additional_frame_id_length_minus_1 = this.f(3);
      }
    }
    const use_128x128_superblock = !!this.f1();
    const enable_filter_intra = !!this.f1();
    const enable_intra_edge_filter = !!this.f1();
    let enable_interintra_compound = false;
    let enable_masked_compound = false;
    let enable_warped_motion = false;
    let enable_dual_filter = false;
    let enable_order_hint = false;
    let enable_jnt_comp = false;
    let enable_ref_frame_mvs = false;
    let seq_choose_screen_content_tools = false;
    let seq_force_screen_content_tools = _Av1.SelectScreenContentTools;
    let seq_choose_integer_mv = false;
    let seq_force_integer_mv = _Av1.SelectIntegerMv;
    let order_hint_bits_minus_1;
    if (!reduced_still_picture_header) {
      enable_interintra_compound = !!this.f1();
      enable_masked_compound = !!this.f1();
      enable_warped_motion = !!this.f1();
      enable_dual_filter = !!this.f1();
      enable_order_hint = !!this.f1();
      if (enable_order_hint) {
        enable_jnt_comp = !!this.f1();
        enable_ref_frame_mvs = !!this.f1();
      }
      seq_choose_screen_content_tools = !!this.f1();
      if (!seq_choose_screen_content_tools) {
        seq_force_screen_content_tools = this.f1();
      }
      if (seq_force_screen_content_tools > 0) {
        seq_choose_integer_mv = !!this.f1();
        if (!seq_choose_integer_mv) {
          seq_force_integer_mv = this.f1();
        }
      }
      if (enable_order_hint) {
        order_hint_bits_minus_1 = this.f(3);
      }
    }
    const enable_superres = !!this.f1();
    const enable_cdef = !!this.f1();
    const enable_restoration = !!this.f1();
    const color_config = this.colorConfig(seq_profile);
    const film_grain_params_present = !!this.f1();
    return {
      seq_profile,
      still_picture,
      reduced_still_picture_header,
      timing_info_present_flag,
      timing_info,
      decoder_model_info_present_flag,
      decoder_model_info,
      initial_display_delay_present_flag,
      initial_display_delay_minus_1,
      operating_points_cnt_minus_1,
      operating_point_idc,
      seq_level_idx,
      seq_tier,
      decoder_model_present_for_this_op,
      operating_parameters_info,
      initial_display_delay_present_for_this_op,
      frame_width_bits_minus_1,
      frame_height_bits_minus_1,
      max_frame_width_minus_1,
      max_frame_height_minus_1,
      frame_id_numbers_present_flag,
      delta_frame_id_length_minus_2,
      additional_frame_id_length_minus_1,
      use_128x128_superblock,
      enable_filter_intra,
      enable_intra_edge_filter,
      enable_interintra_compound,
      enable_masked_compound,
      enable_warped_motion,
      enable_dual_filter,
      enable_order_hint,
      enable_jnt_comp,
      enable_ref_frame_mvs,
      seq_choose_screen_content_tools,
      seq_force_screen_content_tools,
      seq_choose_integer_mv,
      seq_force_integer_mv,
      order_hint_bits_minus_1,
      enable_superres,
      enable_cdef,
      enable_restoration,
      color_config,
      film_grain_params_present
    };
  }
  searchSequenceHeaderObu() {
    while (!this.ended) {
      const obu = this.openBitstreamUnit();
      if (!obu) {
        continue;
      }
      if (obu.sequence_header_obu) {
        return obu.sequence_header_obu;
      }
    }
    return void 0;
  }
  timingInfo() {
    const num_units_in_display_tick = this.f(32);
    const time_scale = this.f(32);
    const equal_picture_interval = !!this.f1();
    let num_ticks_per_picture_minus_1;
    if (equal_picture_interval) {
      num_ticks_per_picture_minus_1 = this.uvlc();
    }
    return {
      num_units_in_display_tick,
      time_scale,
      equal_picture_interval,
      num_ticks_per_picture_minus_1
    };
  }
  decoderModelInfo() {
    const buffer_delay_length_minus_1 = this.f(5);
    const num_units_in_decoding_tick = this.f(32);
    const buffer_removal_time_length_minus_1 = this.f(5);
    const frame_presentation_time_length_minus_1 = this.f(5);
    return {
      buffer_delay_length_minus_1,
      num_units_in_decoding_tick,
      buffer_removal_time_length_minus_1,
      frame_presentation_time_length_minus_1
    };
  }
  operatingParametersInfo(decoderModelInfo) {
    const n = decoderModelInfo.buffer_delay_length_minus_1 + 1;
    const decoder_buffer_delay = this.f(n);
    const encoder_buffer_delay = this.f(n);
    const low_delay_mode_flag = !!this.f1();
    return {
      decoder_buffer_delay,
      encoder_buffer_delay,
      low_delay_mode_flag
    };
  }
  chooseOperatingPoint() {
    return 0;
  }
  colorConfig(seq_profile) {
    const high_bitdepth = !!this.f1();
    let twelve_bit = false;
    let BitDepth = 8;
    if (seq_profile === 2 && high_bitdepth) {
      twelve_bit = !!this.f1();
      BitDepth = twelve_bit ? 12 : 10;
    } else if (seq_profile <= 2) {
      BitDepth = high_bitdepth ? 10 : 8;
    }
    let mono_chrome = false;
    if (seq_profile === 1) {
      mono_chrome = !!this.f1();
    }
    const color_description_present_flag = !!this.f1();
    let color_primaries = _Av1.ColorPrimaries.Unspecified;
    let transfer_characteristics = _Av1.TransferCharacteristics.Unspecified;
    let matrix_coefficients = _Av1.MatrixCoefficients.Unspecified;
    if (color_description_present_flag) {
      color_primaries = this.f(8);
      transfer_characteristics = this.f(8);
      matrix_coefficients = this.f(8);
    }
    let color_range = false;
    let subsampling_x;
    let subsampling_y;
    let chroma_sample_position = 0;
    let separate_uv_delta_q = false;
    if (mono_chrome) {
      color_range = !!this.f1();
      subsampling_x = true;
      subsampling_y = true;
    } else {
      if (color_primaries === _Av1.ColorPrimaries.Bt709 && transfer_characteristics === _Av1.TransferCharacteristics.Srgb && matrix_coefficients === _Av1.MatrixCoefficients.Identity) {
        color_range = true;
        subsampling_x = false;
        subsampling_y = false;
      } else {
        color_range = !!this.f1();
        switch (seq_profile) {
          case 0:
            subsampling_x = true;
            subsampling_y = true;
            break;
          case 1:
            subsampling_x = false;
            subsampling_y = false;
            break;
          default:
            if (BitDepth == 12) {
              subsampling_x = !!this.f1();
              if (subsampling_x) {
                subsampling_y = !!this.f1();
              } else {
                subsampling_y = false;
              }
            } else {
              subsampling_x = true;
              subsampling_y = false;
            }
            break;
        }
        if (subsampling_x && subsampling_y) {
          chroma_sample_position = this.f(2);
        }
      }
      separate_uv_delta_q = !!this.f1();
    }
    return {
      high_bitdepth,
      twelve_bit,
      BitDepth,
      mono_chrome,
      color_description_present_flag,
      color_primaries,
      transfer_characteristics,
      matrix_coefficients,
      color_range,
      subsampling_x,
      subsampling_y,
      chroma_sample_position,
      separate_uv_delta_q
    };
  }
};

// node_modules/@yume-chan/scrcpy/esm/codec/nalu.js
function* annexBSplitNalu(buffer7) {
  let start2 = -1;
  let zeroCount = 0;
  let inEmulation = false;
  for (let i = 0; i < buffer7.length; i += 1) {
    const byte = buffer7[i];
    if (inEmulation) {
      if (byte > 3) {
        throw new Error("Invalid data");
      }
      inEmulation = false;
      continue;
    }
    if (byte === 0) {
      zeroCount += 1;
      continue;
    }
    const prevZeroCount = zeroCount;
    zeroCount = 0;
    if (start2 === -1) {
      if (prevZeroCount >= 2 && byte === 1) {
        start2 = i + 1;
        continue;
      }
      throw new Error("Invalid data");
    }
    if (prevZeroCount < 2) {
      continue;
    }
    if (byte === 1) {
      yield buffer7.subarray(start2, i - prevZeroCount);
      start2 = i + 1;
      continue;
    }
    if (prevZeroCount > 2) {
      throw new Error("Invalid data");
    }
    switch (byte) {
      case 2:
        throw new Error("Invalid data");
      case 3:
        inEmulation = true;
        break;
      default:
        break;
    }
  }
  if (inEmulation) {
    throw new Error("Invalid data");
  }
  yield buffer7.subarray(start2, buffer7.length);
}
var NaluSodbBitReader = class {
  #nalu;
  // logical length is `#byteLength * 8 + (7 - #stopBitIndex)`
  #byteLength;
  #stopBitIndex;
  #zeroCount = 0;
  // logical position is `#bytePosition * 8 + (7 - #bitPosition)`
  #bytePosition = 0;
  #bitPosition = 7;
  #byte = 0;
  get byteLength() {
    return this.#byteLength;
  }
  get stopBitIndex() {
    return this.#stopBitIndex;
  }
  get bytePosition() {
    return this.#bytePosition;
  }
  get bitPosition() {
    return this.#bitPosition;
  }
  get ended() {
    return this.#bytePosition >= this.#byteLength && this.#bitPosition <= this.#stopBitIndex;
  }
  constructor(nalu) {
    this.#nalu = nalu;
    for (let i = nalu.length - 1; i >= 0; i -= 1) {
      if (this.#nalu[i] === 0) {
        continue;
      }
      const byte = nalu[i];
      for (let j = 0; j < 8; j += 1) {
        if ((byte >> j & 1) === 1) {
          this.#byteLength = i;
          this.#stopBitIndex = j;
          this.#loadByte();
          return;
        }
      }
    }
    throw new Error("Stop bit not found");
  }
  #loadByte() {
    this.#byte = this.#nalu[this.#bytePosition];
    if (this.#zeroCount === 2 && this.#byte === 3) {
      this.#zeroCount = 0;
      this.#bytePosition += 1;
      this.#loadByte();
      return;
    }
    if (this.#byte === 0) {
      this.#zeroCount += 1;
    } else {
      this.#zeroCount = 0;
    }
  }
  next() {
    if (this.ended) {
      throw new Error("Bit index out of bounds");
    }
    const value = this.#byte >> this.#bitPosition & 1;
    this.#bitPosition -= 1;
    if (this.#bitPosition < 0) {
      this.#bytePosition += 1;
      this.#bitPosition = 7;
      this.#loadByte();
    }
    return value;
  }
  read(length) {
    if (length > 32) {
      throw new Error("Read length too large");
    }
    let result = 0;
    for (let i = 0; i < length; i += 1) {
      result = result << 1 | this.next();
    }
    return result;
  }
  /**
   * Throws an error if the current position is invalid for `skip`.
   *
   * Usually it will throw if `ended` is `true`,
   * except when the bit position is at the stop bit,
   * in which case `ended` will be `true`, but it won't throw.
   * `skip` can skip all remaining bits, and stop at the end position.
   * The next `next` call will throw since there is no more bits to read.
   */
  #checkSkipPosition() {
    if (this.#bytePosition >= this.#byteLength && this.#bitPosition < this.#stopBitIndex) {
      throw new Error("Bit index out of bounds");
    }
  }
  skip(length) {
    if (length <= this.#bitPosition + 1) {
      this.#bitPosition -= length;
      this.#checkSkipPosition();
      return;
    }
    length -= this.#bitPosition + 1;
    this.#bytePosition += 1;
    this.#bitPosition = 7;
    this.#loadByte();
    this.#checkSkipPosition();
    for (; length >= 8; length -= 8) {
      this.#bytePosition += 1;
      this.#loadByte();
      this.#checkSkipPosition();
    }
    this.#bitPosition = 7 - length;
    this.#checkSkipPosition();
  }
  decodeExponentialGolombNumber() {
    let length = 0;
    while (this.next() === 0) {
      length += 1;
    }
    if (length === 0) {
      return 0;
    }
    return (1 << length | this.read(length)) - 1;
  }
  #save() {
    return {
      zeroCount: this.#zeroCount,
      bytePosition: this.#bytePosition,
      bitPosition: this.#bitPosition,
      byte: this.#byte
    };
  }
  #restore(state) {
    this.#zeroCount = state.zeroCount;
    this.#bytePosition = state.bytePosition;
    this.#bitPosition = state.bitPosition;
    this.#byte = state.byte;
  }
  peek(length) {
    const state = this.#save();
    const result = this.read(length);
    this.#restore(state);
    return result;
  }
  readBytes(length) {
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) {
      result[i] = this.read(8);
    }
    return result;
  }
  peekBytes(length) {
    const state = this.#save();
    const result = this.readBytes(length);
    this.#restore(state);
    return result;
  }
};

// node_modules/@yume-chan/scrcpy/esm/codec/h264.js
var AndroidAvcProfile = {
  Baseline: 1 << 0,
  Main: 1 << 1,
  Extended: 1 << 2,
  High: 1 << 3,
  High10: 1 << 4,
  High422: 1 << 5,
  High444: 1 << 6,
  ConstrainedBaseline: 1 << 16,
  ConstrainedHigh: 1 << 19
};
var AndroidAvcLevel = {
  Level1: 1 << 0,
  Level1b: 1 << 1,
  Level11: 1 << 2,
  Level12: 1 << 3,
  Level13: 1 << 4,
  Level2: 1 << 5,
  Level21: 1 << 6,
  Level22: 1 << 7,
  Level3: 1 << 8,
  Level31: 1 << 9,
  Level32: 1 << 10,
  Level4: 1 << 11,
  Level41: 1 << 12,
  Level42: 1 << 13,
  Level5: 1 << 14,
  Level51: 1 << 15,
  Level52: 1 << 16,
  Level6: 1 << 17,
  Level61: 1 << 18,
  Level62: 1 << 19
};
function h264ParseSequenceParameterSet(nalu) {
  const reader = new NaluSodbBitReader(nalu);
  if (reader.next() !== 0) {
    throw new Error("Invalid data");
  }
  const nal_ref_idc = reader.read(2);
  const nal_unit_type = reader.read(5);
  if (nal_unit_type !== 7) {
    throw new Error("Invalid data");
  }
  if (nal_ref_idc === 0) {
    throw new Error("Invalid data");
  }
  const profile_idc = reader.read(8);
  const constraint_set = reader.peek(8);
  const constraint_set0_flag = !!reader.next();
  const constraint_set1_flag = !!reader.next();
  const constraint_set2_flag = !!reader.next();
  const constraint_set3_flag = !!reader.next();
  const constraint_set4_flag = !!reader.next();
  const constraint_set5_flag = !!reader.next();
  if (reader.read(2) !== 0) {
    throw new Error("Invalid data");
  }
  const level_idc = reader.read(8);
  const seq_parameter_set_id = reader.decodeExponentialGolombNumber();
  if (profile_idc === 100 || profile_idc === 110 || profile_idc === 122 || profile_idc === 244 || profile_idc === 44 || profile_idc === 83 || profile_idc === 86 || profile_idc === 118 || profile_idc === 128 || profile_idc === 138 || profile_idc === 139 || profile_idc === 134) {
    const chroma_format_idc = reader.decodeExponentialGolombNumber();
    if (chroma_format_idc === 3) {
      reader.next();
    }
    reader.decodeExponentialGolombNumber();
    reader.decodeExponentialGolombNumber();
    reader.next();
    const seq_scaling_matrix_present_flag = !!reader.next();
    if (seq_scaling_matrix_present_flag) {
      const seq_scaling_list_present_flag = [];
      for (let i = 0; i < (chroma_format_idc !== 3 ? 8 : 12); i += 1) {
        seq_scaling_list_present_flag[i] = !!reader.next();
        if (seq_scaling_list_present_flag[i])
          if (i < 6) {
          } else {
          }
      }
    }
  }
  reader.decodeExponentialGolombNumber();
  const pic_order_cnt_type = reader.decodeExponentialGolombNumber();
  if (pic_order_cnt_type === 0) {
    reader.decodeExponentialGolombNumber();
  } else if (pic_order_cnt_type === 1) {
    reader.next();
    reader.decodeExponentialGolombNumber();
    reader.decodeExponentialGolombNumber();
    const num_ref_frames_in_pic_order_cnt_cycle = reader.decodeExponentialGolombNumber();
    const offset_for_ref_frame = [];
    for (let i = 0; i < num_ref_frames_in_pic_order_cnt_cycle; i += 1) {
      offset_for_ref_frame[i] = reader.decodeExponentialGolombNumber();
    }
  }
  reader.decodeExponentialGolombNumber();
  reader.next();
  const pic_width_in_mbs_minus1 = reader.decodeExponentialGolombNumber();
  const pic_height_in_map_units_minus1 = reader.decodeExponentialGolombNumber();
  const frame_mbs_only_flag = reader.next();
  if (!frame_mbs_only_flag) {
    reader.next();
  }
  reader.next();
  const frame_cropping_flag = !!reader.next();
  let frame_crop_left_offset;
  let frame_crop_right_offset;
  let frame_crop_top_offset;
  let frame_crop_bottom_offset;
  if (frame_cropping_flag) {
    frame_crop_left_offset = reader.decodeExponentialGolombNumber();
    frame_crop_right_offset = reader.decodeExponentialGolombNumber();
    frame_crop_top_offset = reader.decodeExponentialGolombNumber();
    frame_crop_bottom_offset = reader.decodeExponentialGolombNumber();
  } else {
    frame_crop_left_offset = 0;
    frame_crop_right_offset = 0;
    frame_crop_top_offset = 0;
    frame_crop_bottom_offset = 0;
  }
  const vui_parameters_present_flag = !!reader.next();
  if (vui_parameters_present_flag) {
  }
  return {
    profile_idc,
    constraint_set,
    constraint_set0_flag,
    constraint_set1_flag,
    constraint_set2_flag,
    constraint_set3_flag,
    constraint_set4_flag,
    constraint_set5_flag,
    level_idc,
    seq_parameter_set_id,
    pic_width_in_mbs_minus1,
    pic_height_in_map_units_minus1,
    frame_mbs_only_flag,
    frame_cropping_flag,
    frame_crop_left_offset,
    frame_crop_right_offset,
    frame_crop_top_offset,
    frame_crop_bottom_offset
  };
}
function h264SearchConfiguration(buffer7) {
  let sequenceParameterSet;
  let pictureParameterSet;
  for (const nalu of annexBSplitNalu(buffer7)) {
    const naluType = nalu[0] & 31;
    switch (naluType) {
      case 7:
        sequenceParameterSet = nalu;
        if (pictureParameterSet) {
          return {
            sequenceParameterSet,
            pictureParameterSet
          };
        }
        break;
      case 8:
        pictureParameterSet = nalu;
        if (sequenceParameterSet) {
          return {
            sequenceParameterSet,
            pictureParameterSet
          };
        }
        break;
      default:
        break;
    }
  }
  throw new Error("Invalid data");
}
function h264ParseConfiguration(data) {
  const { sequenceParameterSet, pictureParameterSet } = h264SearchConfiguration(data);
  const { profile_idc: profileIndex, constraint_set: constraintSet, level_idc: levelIndex, pic_width_in_mbs_minus1, pic_height_in_map_units_minus1, frame_mbs_only_flag, frame_crop_left_offset, frame_crop_right_offset, frame_crop_top_offset, frame_crop_bottom_offset } = h264ParseSequenceParameterSet(sequenceParameterSet);
  const encodedWidth = (pic_width_in_mbs_minus1 + 1) * 16;
  const encodedHeight = (pic_height_in_map_units_minus1 + 1) * (2 - frame_mbs_only_flag) * 16;
  const cropLeft = frame_crop_left_offset * 2;
  const cropRight = frame_crop_right_offset * 2;
  const cropTop = frame_crop_top_offset * 2;
  const cropBottom = frame_crop_bottom_offset * 2;
  const croppedWidth = encodedWidth - cropLeft - cropRight;
  const croppedHeight = encodedHeight - cropTop - cropBottom;
  return {
    pictureParameterSet,
    sequenceParameterSet,
    profileIndex,
    constraintSet,
    levelIndex,
    encodedWidth,
    encodedHeight,
    cropLeft,
    cropRight,
    cropTop,
    cropBottom,
    croppedWidth,
    croppedHeight
  };
}

// node_modules/@yume-chan/scrcpy/esm/codec/h265.js
var AndroidHevcProfile = {
  Main: 1 << 0,
  Main10: 1 << 1,
  MainStill: 1 << 2,
  Main10Hdr10: 1 << 12,
  Main10Hdr10Plus: 1 << 13
};
var AndroidHevcLevel = {
  MainTierLevel1: 1 << 0,
  HighTierLevel1: 1 << 1,
  MainTierLevel2: 1 << 2,
  HighTierLevel2: 1 << 3,
  MainTierLevel21: 1 << 4,
  HighTierLevel21: 1 << 5,
  MainTierLevel3: 1 << 6,
  HighTierLevel3: 1 << 7,
  MainTierLevel31: 1 << 8,
  HighTierLevel31: 1 << 9,
  MainTierLevel4: 1 << 10,
  HighTierLevel4: 1 << 11,
  MainTierLevel41: 1 << 12,
  HighTierLevel41: 1 << 13,
  MainTierLevel5: 1 << 14,
  HighTierLevel5: 1 << 15,
  MainTierLevel51: 1 << 16,
  HighTierLevel51: 1 << 17,
  MainTierLevel52: 1 << 18,
  HighTierLevel52: 1 << 19,
  MainTierLevel6: 1 << 20,
  HighTierLevel6: 1 << 21,
  MainTierLevel61: 1 << 22,
  HighTierLevel61: 1 << 23,
  MainTierLevel62: 1 << 24,
  HighTierLevel62: 1 << 25
};
function getSubWidthC(chroma_format_idc) {
  switch (chroma_format_idc) {
    case 0:
    case 3:
      return 1;
    case 1:
    case 2:
      return 2;
    default:
      throw new Error("Invalid chroma_format_idc");
  }
}
function getSubHeightC(chroma_format_idc) {
  switch (chroma_format_idc) {
    case 0:
    case 2:
    case 3:
      return 1;
    case 1:
      return 2;
    default:
      throw new Error("Invalid chroma_format_idc");
  }
}
function h265ParseNaluHeader(nalu) {
  const reader = new NaluSodbBitReader(nalu);
  if (reader.next() !== 0) {
    throw new Error("Invalid NALU header");
  }
  const nal_unit_type = reader.read(6);
  const nuh_layer_id = reader.read(6);
  const nuh_temporal_id_plus1 = reader.read(3);
  return {
    nal_unit_type,
    nuh_layer_id,
    nuh_temporal_id_plus1
  };
}
function h265ParseVideoParameterSet(nalu) {
  const reader = new NaluSodbBitReader(nalu);
  const vps_video_parameter_set_id = reader.read(4);
  const vps_base_layer_internal_flag = !!reader.next();
  const vps_base_layer_available_flag = !!reader.next();
  const vps_max_layers_minus1 = reader.read(6);
  const vps_max_sub_layers_minus1 = reader.read(3);
  const vps_temporal_id_nesting_flag = !!reader.next();
  reader.skip(16);
  const profileTierLevel = h265ParseProfileTierLevel(reader, true, vps_max_sub_layers_minus1);
  const vps_sub_layer_ordering_info_present_flag = !!reader.next();
  const vps_max_dec_pic_buffering_minus1 = [];
  const vps_max_num_reorder_pics = [];
  const vps_max_latency_increase_plus1 = [];
  for (let i = vps_sub_layer_ordering_info_present_flag ? 0 : vps_max_sub_layers_minus1; i <= vps_max_sub_layers_minus1; i += 1) {
    vps_max_dec_pic_buffering_minus1[i] = reader.decodeExponentialGolombNumber();
    vps_max_num_reorder_pics[i] = reader.decodeExponentialGolombNumber();
    vps_max_latency_increase_plus1[i] = reader.decodeExponentialGolombNumber();
  }
  const vps_max_layer_id = reader.read(6);
  const vps_num_layer_sets_minus1 = reader.decodeExponentialGolombNumber();
  const layer_id_included_flag = [];
  for (let i = 1; i <= vps_num_layer_sets_minus1; i += 1) {
    layer_id_included_flag[i] = [];
    for (let j = 0; j <= vps_max_layer_id; j += 1) {
      layer_id_included_flag[i][j] = !!reader.next();
    }
  }
  const vps_timing_info_present_flag = !!reader.next();
  let vps_num_units_in_tick;
  let vps_time_scale;
  let vps_poc_proportional_to_timing_flag;
  let vps_num_ticks_poc_diff_one_minus1;
  let vps_num_hrd_parameters;
  let hrd_layer_set_idx;
  let cprms_present_flag;
  let hrdParameters;
  if (vps_timing_info_present_flag) {
    vps_num_units_in_tick = reader.read(32);
    vps_time_scale = reader.read(32);
    vps_poc_proportional_to_timing_flag = !!reader.next();
    if (vps_poc_proportional_to_timing_flag) {
      vps_num_ticks_poc_diff_one_minus1 = reader.decodeExponentialGolombNumber();
    }
    vps_num_hrd_parameters = reader.decodeExponentialGolombNumber();
    hrd_layer_set_idx = [];
    cprms_present_flag = [true];
    hrdParameters = [];
    for (let i = 0; i < vps_num_hrd_parameters; i += 1) {
      hrd_layer_set_idx[i] = reader.decodeExponentialGolombNumber();
      if (i > 0) {
        cprms_present_flag[i] = !!reader.next();
      }
      hrdParameters[i] = h265ParseHrdParameters(reader, cprms_present_flag[i], vps_max_sub_layers_minus1);
    }
  }
  const vps_extension_flag = !!reader.next();
  return {
    vps_video_parameter_set_id,
    vps_base_layer_internal_flag,
    vps_base_layer_available_flag,
    vps_max_layers_minus1,
    vps_max_sub_layers_minus1,
    vps_temporal_id_nesting_flag,
    profileTierLevel,
    vps_sub_layer_ordering_info_present_flag,
    vps_max_dec_pic_buffering_minus1,
    vps_max_num_reorder_pics,
    vps_max_latency_increase_plus1,
    vps_max_layer_id,
    vps_num_layer_sets_minus1,
    layer_id_included_flag,
    vps_timing_info_present_flag,
    vps_num_units_in_tick,
    vps_time_scale,
    vps_poc_proportional_to_timing_flag,
    vps_num_ticks_poc_diff_one_minus1,
    vps_num_hrd_parameters,
    hrd_layer_set_idx,
    cprms_present_flag,
    hrdParameters,
    vps_extension_flag
  };
}
function h265ParseSequenceParameterSet(nalu) {
  const reader = new NaluSodbBitReader(nalu);
  const sps_video_parameter_set_id = reader.read(4);
  const sps_max_sub_layers_minus1 = reader.read(3);
  const sps_temporal_id_nesting_flag = !!reader.next();
  const profileTierLevel = h265ParseProfileTierLevel(reader, true, sps_max_sub_layers_minus1);
  const sps_seq_parameter_set_id = reader.decodeExponentialGolombNumber();
  const chroma_format_idc = reader.decodeExponentialGolombNumber();
  let separate_colour_plane_flag;
  if (chroma_format_idc === 3) {
    separate_colour_plane_flag = !!reader.next();
  }
  const pic_width_in_luma_samples = reader.decodeExponentialGolombNumber();
  const pic_height_in_luma_samples = reader.decodeExponentialGolombNumber();
  const conformance_window_flag = !!reader.next();
  let conf_win_left_offset;
  let conf_win_right_offset;
  let conf_win_top_offset;
  let conf_win_bottom_offset;
  if (conformance_window_flag) {
    conf_win_left_offset = reader.decodeExponentialGolombNumber();
    conf_win_right_offset = reader.decodeExponentialGolombNumber();
    conf_win_top_offset = reader.decodeExponentialGolombNumber();
    conf_win_bottom_offset = reader.decodeExponentialGolombNumber();
  }
  const bit_depth_luma_minus8 = reader.decodeExponentialGolombNumber();
  const bit_depth_chroma_minus8 = reader.decodeExponentialGolombNumber();
  const log2_max_pic_order_cnt_lsb_minus4 = reader.decodeExponentialGolombNumber();
  const sps_max_dec_pic_buffering_minus1 = [];
  const sps_max_num_reorder_pics = [];
  const sps_max_latency_increase_plus1 = [];
  const sps_sub_layer_ordering_info_present_flag = !!reader.next();
  for (let i = sps_sub_layer_ordering_info_present_flag ? 0 : sps_max_sub_layers_minus1; i <= sps_max_sub_layers_minus1; i += 1) {
    sps_max_dec_pic_buffering_minus1[i] = reader.decodeExponentialGolombNumber();
    sps_max_num_reorder_pics[i] = reader.decodeExponentialGolombNumber();
    sps_max_latency_increase_plus1[i] = reader.decodeExponentialGolombNumber();
  }
  const log2_min_luma_coding_block_size_minus3 = reader.decodeExponentialGolombNumber();
  const log2_diff_max_min_luma_coding_block_size = reader.decodeExponentialGolombNumber();
  const log2_min_luma_transform_block_size_minus2 = reader.decodeExponentialGolombNumber();
  const log2_diff_max_min_luma_transform_block_size = reader.decodeExponentialGolombNumber();
  const max_transform_hierarchy_depth_inter = reader.decodeExponentialGolombNumber();
  const max_transform_hierarchy_depth_intra = reader.decodeExponentialGolombNumber();
  const scaling_list_enabled_flag = !!reader.next();
  let sps_scaling_list_data_present_flag;
  let scalingListData;
  if (scaling_list_enabled_flag) {
    sps_scaling_list_data_present_flag = !!reader.next();
    if (sps_scaling_list_data_present_flag) {
      scalingListData = h265ParseScalingListData(reader);
    }
  }
  const amp_enabled_flag = !!reader.next();
  const sample_adaptive_offset_enabled_flag = !!reader.next();
  const pcm_enabled_flag = !!reader.next();
  let pcm_sample_bit_depth_luma_minus1;
  let pcm_sample_bit_depth_chroma_minus1;
  let log2_min_pcm_luma_coding_block_size_minus3;
  let log2_diff_max_min_pcm_luma_coding_block_size;
  let pcm_loop_filter_disabled_flag;
  if (pcm_enabled_flag) {
    pcm_sample_bit_depth_luma_minus1 = reader.read(4);
    pcm_sample_bit_depth_chroma_minus1 = reader.read(4);
    log2_min_pcm_luma_coding_block_size_minus3 = reader.decodeExponentialGolombNumber();
    log2_diff_max_min_pcm_luma_coding_block_size = reader.decodeExponentialGolombNumber();
    pcm_loop_filter_disabled_flag = !!reader.next();
  }
  const num_short_term_ref_pic_sets = reader.decodeExponentialGolombNumber();
  const shortTermRefPicSets = [];
  for (let i = 0; i < num_short_term_ref_pic_sets; i += 1) {
    shortTermRefPicSets[i] = h265ParseShortTermReferencePictureSet(reader, i, num_short_term_ref_pic_sets, shortTermRefPicSets);
  }
  const long_term_ref_pics_present_flag = !!reader.next();
  let num_long_term_ref_pics_sps;
  let lt_ref_pic_poc_lsb_sps;
  let used_by_curr_pic_lt_sps_flag;
  if (long_term_ref_pics_present_flag) {
    num_long_term_ref_pics_sps = reader.decodeExponentialGolombNumber();
    lt_ref_pic_poc_lsb_sps = [];
    used_by_curr_pic_lt_sps_flag = [];
    for (let i = 0; i < num_long_term_ref_pics_sps; i += 1) {
      lt_ref_pic_poc_lsb_sps[i] = reader.read(log2_max_pic_order_cnt_lsb_minus4 + 4);
      used_by_curr_pic_lt_sps_flag[i] = !!reader.next();
    }
  }
  const sps_temporal_mvp_enabled_flag = !!reader.next();
  const strong_intra_smoothing_enabled_flag = !!reader.next();
  const vui_parameters_present_flag = !!reader.next();
  let vuiParameters;
  if (vui_parameters_present_flag) {
    vuiParameters = h265ParseVuiParameters(reader, sps_max_sub_layers_minus1);
  }
  const sps_extension_present_flag = !!reader.next();
  let sps_range_extension_flag;
  let sps_multilayer_extension_flag;
  let sps_3d_extension_flag;
  let sps_scc_extension_flag;
  let sps_extension_4bits;
  if (sps_extension_present_flag) {
    sps_range_extension_flag = !!reader.next();
    sps_multilayer_extension_flag = !!reader.next();
    sps_3d_extension_flag = !!reader.next();
    sps_scc_extension_flag = !!reader.next();
    sps_extension_4bits = reader.read(4);
  }
  if (sps_range_extension_flag) {
    throw new Error("Not implemented");
  }
  let spsMultilayerExtension;
  if (sps_multilayer_extension_flag) {
    spsMultilayerExtension = h265ParseSpsMultilayerExtension(reader);
  }
  let sps3dExtension;
  if (sps_3d_extension_flag) {
    sps3dExtension = h265ParseSps3dExtension(reader);
  }
  if (sps_scc_extension_flag) {
    throw new Error("Not implemented");
  }
  let sps_extension_data_flag;
  if (sps_extension_4bits) {
    sps_extension_data_flag = [];
    let i = 0;
    while (!reader.ended) {
      sps_extension_data_flag[i] = !!reader.next();
      i += 1;
    }
  }
  return {
    sps_video_parameter_set_id,
    sps_max_sub_layers_minus1,
    sps_temporal_id_nesting_flag,
    profileTierLevel,
    sps_seq_parameter_set_id,
    chroma_format_idc,
    separate_colour_plane_flag,
    pic_width_in_luma_samples,
    pic_height_in_luma_samples,
    conformance_window_flag,
    conf_win_left_offset,
    conf_win_right_offset,
    conf_win_top_offset,
    conf_win_bottom_offset,
    bit_depth_luma_minus8,
    bit_depth_chroma_minus8,
    log2_max_pic_order_cnt_lsb_minus4,
    sps_sub_layer_ordering_info_present_flag,
    sps_max_dec_pic_buffering_minus1,
    sps_max_num_reorder_pics,
    sps_max_latency_increase_plus1,
    log2_min_luma_coding_block_size_minus3,
    log2_diff_max_min_luma_coding_block_size,
    log2_min_luma_transform_block_size_minus2,
    log2_diff_max_min_luma_transform_block_size,
    max_transform_hierarchy_depth_inter,
    max_transform_hierarchy_depth_intra,
    scaling_list_enabled_flag,
    sps_scaling_list_data_present_flag,
    scalingListData,
    amp_enabled_flag,
    sample_adaptive_offset_enabled_flag,
    pcm_enabled_flag,
    pcm_sample_bit_depth_luma_minus1,
    pcm_sample_bit_depth_chroma_minus1,
    log2_min_pcm_luma_coding_block_size_minus3,
    log2_diff_max_min_pcm_luma_coding_block_size,
    pcm_loop_filter_disabled_flag,
    num_short_term_ref_pic_sets,
    shortTermRefPicSets,
    long_term_ref_pics_present_flag,
    num_long_term_ref_pics_sps,
    lt_ref_pic_poc_lsb_sps,
    used_by_curr_pic_lt_sps_flag,
    sps_temporal_mvp_enabled_flag,
    strong_intra_smoothing_enabled_flag,
    vui_parameters_present_flag,
    vuiParameters,
    sps_extension_present_flag,
    sps_range_extension_flag,
    sps_multilayer_extension_flag,
    sps_3d_extension_flag,
    sps_scc_extension_flag,
    sps_extension_4bits,
    spsMultilayerExtension,
    sps3dExtension,
    sps_extension_data_flag
  };
}
function h265ParseProfileTier(reader) {
  const profile_space = reader.read(2);
  const tier_flag = !!reader.next();
  const profile_idc = reader.read(5);
  const profileCompatibilitySet = reader.peekBytes(4);
  const profile_compatibility_flag = [];
  for (let j = 0; j < 32; j += 1) {
    profile_compatibility_flag[j] = !!reader.next();
  }
  const constraintSet = reader.peekBytes(6);
  const progressive_source_flag = !!reader.next();
  const interlaced_source_flag = !!reader.next();
  const non_packed_constraint_flag = !!reader.next();
  const frame_only_constraint_flag = !!reader.next();
  let max_12bit_constraint_flag;
  let max_10bit_constraint_flag;
  let max_8bit_constraint_flag;
  let max_422chroma_constraint_flag;
  let max_420chroma_constraint_flag;
  let max_monochrome_constraint_flag;
  let intra_constraint_flag;
  let one_picture_only_constraint_flag;
  let lower_bit_rate_constraint_flag;
  let max_14bit_constraint_flag;
  if (profile_idc === 4 || profile_compatibility_flag[4] || profile_idc === 5 || profile_compatibility_flag[5] || profile_idc === 6 || profile_compatibility_flag[6] || profile_idc === 7 || profile_compatibility_flag[7] || profile_idc === 8 || profile_compatibility_flag[8] || profile_idc === 9 || profile_compatibility_flag[9] || profile_idc === 10 || profile_compatibility_flag[10] || profile_idc === 11 || profile_compatibility_flag[11]) {
    max_12bit_constraint_flag = !!reader.next();
    max_10bit_constraint_flag = !!reader.next();
    max_8bit_constraint_flag = !!reader.next();
    max_422chroma_constraint_flag = !!reader.next();
    max_420chroma_constraint_flag = !!reader.next();
    max_monochrome_constraint_flag = !!reader.next();
    intra_constraint_flag = !!reader.next();
    one_picture_only_constraint_flag = !!reader.next();
    lower_bit_rate_constraint_flag = !!reader.next();
    if (profile_idc === 5 || profile_compatibility_flag[5] || profile_idc === 9 || profile_compatibility_flag[9] || profile_idc === 10 || profile_compatibility_flag[10] || profile_idc === 11 || profile_compatibility_flag[11]) {
      max_14bit_constraint_flag = !!reader.next();
      reader.skip(33);
    } else {
      reader.skip(34);
    }
  } else if (profile_idc === 2 || profile_compatibility_flag[2]) {
    reader.skip(7);
    one_picture_only_constraint_flag = !!reader.next();
    reader.skip(35);
  } else {
    reader.skip(43);
  }
  let inbld_flag;
  if (profile_idc === 1 || profile_compatibility_flag[1] || profile_idc === 2 || profile_compatibility_flag[2] || profile_idc === 3 || profile_compatibility_flag[3] || profile_idc === 4 || profile_compatibility_flag[4] || profile_idc === 5 || profile_compatibility_flag[5] || profile_idc === 9 || profile_compatibility_flag[9] || profile_idc === 11 || profile_compatibility_flag[11]) {
    inbld_flag = !!reader.next();
  } else {
    reader.skip(1);
  }
  return {
    profile_space,
    tier_flag,
    profile_idc,
    profileCompatibilitySet,
    profile_compatibility_flag,
    constraintSet,
    progressive_source_flag,
    interlaced_source_flag,
    non_packed_constraint_flag,
    frame_only_constraint_flag,
    max_12bit_constraint_flag,
    max_10bit_constraint_flag,
    max_8bit_constraint_flag,
    max_422chroma_constraint_flag,
    max_420chroma_constraint_flag,
    max_monochrome_constraint_flag,
    intra_constraint_flag,
    one_picture_only_constraint_flag,
    lower_bit_rate_constraint_flag,
    max_14bit_constraint_flag,
    inbld_flag
  };
}
function h265ParseProfileTierLevel(reader, profilePresentFlag, maxNumSubLayersMinus1) {
  let generalProfileTier;
  if (profilePresentFlag) {
    generalProfileTier = h265ParseProfileTier(reader);
  }
  const general_level_idc = reader.read(8);
  const sub_layer_profile_present_flag = [];
  const sub_layer_level_present_flag = [];
  for (let i = 0; i < maxNumSubLayersMinus1; i += 1) {
    sub_layer_profile_present_flag[i] = !!reader.next();
    sub_layer_level_present_flag[i] = !!reader.next();
  }
  if (maxNumSubLayersMinus1 > 0) {
    for (let i = maxNumSubLayersMinus1; i < 8; i += 1) {
      reader.read(2);
    }
  }
  const subLayerProfileTier = [];
  const sub_layer_level_idc = [];
  for (let i = 0; i < maxNumSubLayersMinus1; i += 1) {
    if (sub_layer_profile_present_flag[i]) {
      subLayerProfileTier[i] = h265ParseProfileTier(reader);
    }
    if (sub_layer_level_present_flag[i]) {
      sub_layer_level_idc[i] = reader.read(8);
    }
  }
  return {
    generalProfileTier,
    general_level_idc,
    sub_layer_profile_present_flag,
    sub_layer_level_present_flag,
    subLayerProfileTier,
    sub_layer_level_idc
  };
}
function h265ParseScalingListData(reader) {
  const scaling_list = [];
  for (let sizeId = 0; sizeId < 4; sizeId += 1) {
    scaling_list[sizeId] = [];
    for (let matrixId = 0; matrixId < 6; matrixId += sizeId === 3 ? 3 : 1) {
      const scaling_list_pred_mode_flag = !!reader.next();
      if (!scaling_list_pred_mode_flag) {
        reader.decodeExponentialGolombNumber();
      } else {
        let nextCoef = 8;
        const coefNum = Math.min(64, 1 << 4 + (sizeId << 1));
        if (sizeId > 1) {
          const scaling_list_dc_coef_minus8 = reader.decodeExponentialGolombNumber();
          nextCoef = scaling_list_dc_coef_minus8 + 8;
        }
        scaling_list[sizeId][matrixId] = [];
        for (let i = 0; i < coefNum; i += 1) {
          const scaling_list_delta_coef = reader.decodeExponentialGolombNumber();
          nextCoef = (nextCoef + scaling_list_delta_coef + 256) % 256;
          scaling_list[sizeId][matrixId][i] = nextCoef;
        }
      }
    }
  }
  return scaling_list;
}
function h265ParseShortTermReferencePictureSet(reader, stRpsIdx, num_short_term_ref_pic_sets, sets) {
  let inter_ref_pic_set_prediction_flag = false;
  if (stRpsIdx !== 0) {
    inter_ref_pic_set_prediction_flag = !!reader.next();
  }
  let delta_idx_minus1 = 0;
  let delta_rps_sign = false;
  let abs_delta_rps_minus1 = 0;
  const used_by_curr_pic_flag = [];
  const use_delta_flag = [];
  let num_negative_pics = 0;
  let num_positive_pics = 0;
  const delta_poc_s0_minus1 = [];
  const used_by_curr_pic_s0_flag = [];
  const delta_poc_s1_minus1 = [];
  const used_by_curr_pic_s1_flag = [];
  if (inter_ref_pic_set_prediction_flag) {
    if (stRpsIdx === num_short_term_ref_pic_sets) {
      delta_idx_minus1 = reader.decodeExponentialGolombNumber();
    }
    delta_rps_sign = !!reader.next();
    abs_delta_rps_minus1 = reader.decodeExponentialGolombNumber();
    const RefRpsIdx = stRpsIdx - (delta_idx_minus1 + 1);
    const RefRps = sets[RefRpsIdx];
    const NumDeltaPocs_RefRpsIdx = RefRps.num_negative_pics + RefRps.num_positive_pics;
    for (let j = 0; j <= NumDeltaPocs_RefRpsIdx; j += 1) {
      used_by_curr_pic_flag[j] = !!reader.next();
      if (!used_by_curr_pic_flag[j]) {
        use_delta_flag[j] = !!reader.next();
      } else {
        use_delta_flag[j] = true;
      }
    }
    const DeltaRps = (1 - 2 * Number(delta_rps_sign)) * (abs_delta_rps_minus1 + 1);
    const RefPocS0 = [];
    const RefPocS1 = [];
    const pocS0 = [];
    const pocS1 = [];
    let dPoc = 0;
    for (let i2 = 0; i2 < RefRps.num_negative_pics; i2 += 1) {
      dPoc -= RefRps.delta_poc_s0_minus1[i2] + 1;
      RefPocS0[i2] = dPoc;
    }
    dPoc = 0;
    for (let i2 = 0; i2 < RefRps.num_positive_pics; i2 += 1) {
      dPoc += RefRps.delta_poc_s1_minus1[i2] + 1;
      RefPocS1[i2] = dPoc;
    }
    let i = 0;
    if (RefRps.num_positive_pics > 0) {
      for (let j = RefRps.num_positive_pics - 1; j >= 0; j -= 1) {
        dPoc = RefPocS1[j] + DeltaRps;
        if (dPoc < 0 && use_delta_flag[RefRps.num_negative_pics + j]) {
          pocS0[i] = dPoc;
          used_by_curr_pic_s0_flag[i] = used_by_curr_pic_flag[RefRps.num_negative_pics + j];
          i += 1;
        }
      }
    }
    if (DeltaRps < 0 && use_delta_flag[NumDeltaPocs_RefRpsIdx]) {
      pocS0[i] = DeltaRps;
      used_by_curr_pic_s0_flag[i] = used_by_curr_pic_flag[NumDeltaPocs_RefRpsIdx];
      i += 1;
    }
    for (let j = 0; j < RefRps.num_negative_pics; j += 1) {
      dPoc = RefPocS0[j] + DeltaRps;
      if (dPoc < 0 && use_delta_flag[j]) {
        pocS0[i] = dPoc;
        used_by_curr_pic_s0_flag[i] = used_by_curr_pic_flag[j];
        i += 1;
      }
    }
    num_negative_pics = i;
    let prev = 0;
    for (i = 0; i < num_negative_pics; i += 1) {
      const current = pocS0[i];
      delta_poc_s0_minus1[i] = -(current - prev - 1);
      prev = current;
    }
    i = 0;
    if (RefRps.num_negative_pics > 0) {
      for (let j = RefRps.num_negative_pics - 1; j >= 0; j -= 1) {
        dPoc = RefPocS0[j] + DeltaRps;
        if (dPoc > 0 && use_delta_flag[j]) {
          pocS1[i] = dPoc;
          used_by_curr_pic_s1_flag[i] = used_by_curr_pic_flag[j];
          i += 1;
        }
      }
    }
    if (DeltaRps > 0 && use_delta_flag[NumDeltaPocs_RefRpsIdx]) {
      pocS1[i] = DeltaRps;
      used_by_curr_pic_s1_flag[i] = used_by_curr_pic_flag[NumDeltaPocs_RefRpsIdx];
      i += 1;
    }
    for (let j = 0; j < RefRps.num_positive_pics; j += 1) {
      dPoc = RefPocS1[j] + DeltaRps;
      if (dPoc > 0 && use_delta_flag[RefRps.num_negative_pics + j]) {
        pocS1[i] = dPoc;
        used_by_curr_pic_s1_flag[i] = used_by_curr_pic_flag[RefRps.num_negative_pics + j];
        i += 1;
      }
    }
    num_positive_pics = i;
    prev = 0;
    for (i = 0; i < num_positive_pics; i += 1) {
      const current = pocS1[i];
      delta_poc_s1_minus1[i] = current - prev - 1;
      prev = current;
    }
  } else {
    num_negative_pics = reader.decodeExponentialGolombNumber();
    num_positive_pics = reader.decodeExponentialGolombNumber();
    for (let i = 0; i < num_negative_pics; i += 1) {
      delta_poc_s0_minus1[i] = reader.decodeExponentialGolombNumber();
      used_by_curr_pic_s0_flag[i] = !!reader.next();
    }
    for (let i = 0; i < num_positive_pics; i += 1) {
      delta_poc_s1_minus1[i] = reader.decodeExponentialGolombNumber();
      used_by_curr_pic_s1_flag[i] = !!reader.next();
    }
  }
  return {
    stRpsIdx,
    num_short_term_ref_pic_sets,
    inter_ref_pic_set_prediction_flag,
    delta_idx_minus1,
    delta_rps_sign,
    abs_delta_rps_minus1,
    used_by_curr_pic_flag,
    use_delta_flag,
    num_negative_pics,
    num_positive_pics,
    delta_poc_s0_minus1,
    used_by_curr_pic_s0_flag,
    delta_poc_s1_minus1,
    used_by_curr_pic_s1_flag
  };
}
var H265AspectRatioIndicator = {
  Unspecified: 0,
  Square: 1,
  _12_11: 2,
  _10_11: 3,
  _16_11: 4,
  _40_33: 5,
  _24_11: 6,
  _20_11: 7,
  _32_11: 8,
  _80_33: 9,
  _18_11: 10,
  _15_11: 11,
  _64_33: 12,
  _160_99: 13,
  _4_3: 15,
  _3_2: 16,
  _2_1: 17,
  Extended: 255
};
function h265ParseVuiParameters(reader, sps_max_sub_layers_minus1) {
  const aspect_ratio_info_present_flag = !!reader.next();
  let aspect_ratio_idc;
  let sar_width;
  let sar_height;
  if (aspect_ratio_info_present_flag) {
    aspect_ratio_idc = reader.read(8);
    if (aspect_ratio_idc === H265AspectRatioIndicator.Extended) {
      sar_width = reader.read(16);
      sar_height = reader.read(16);
    }
  }
  const overscan_info_present_flag = !!reader.next();
  let overscan_appropriate_flag;
  if (overscan_info_present_flag) {
    overscan_appropriate_flag = !!reader.next();
  }
  const video_signal_type_present_flag = !!reader.next();
  let video_format;
  let video_full_range_flag;
  let colour_description_present_flag;
  let colour_primaries;
  let transfer_characteristics;
  let matrix_coeffs;
  if (video_signal_type_present_flag) {
    video_format = reader.read(3);
    video_full_range_flag = !!reader.next();
    colour_description_present_flag = !!reader.next();
    if (colour_description_present_flag) {
      colour_primaries = reader.read(8);
      transfer_characteristics = reader.read(8);
      matrix_coeffs = reader.read(8);
    }
  }
  const chroma_loc_info_present_flag = !!reader.next();
  let chroma_sample_loc_type_top_field;
  let chroma_sample_loc_type_bottom_field;
  if (chroma_loc_info_present_flag) {
    chroma_sample_loc_type_top_field = reader.decodeExponentialGolombNumber();
    chroma_sample_loc_type_bottom_field = reader.decodeExponentialGolombNumber();
  }
  const neutral_chroma_indication_flag = !!reader.next();
  const field_seq_flag = !!reader.next();
  const frame_field_info_present_flag = !!reader.next();
  const default_display_window_flag = !!reader.next();
  let def_disp_win_left_offset;
  let def_disp_win_right_offset;
  let def_disp_win_top_offset;
  let def_disp_win_bottom_offset;
  if (default_display_window_flag) {
    def_disp_win_left_offset = reader.decodeExponentialGolombNumber();
    def_disp_win_right_offset = reader.decodeExponentialGolombNumber();
    def_disp_win_top_offset = reader.decodeExponentialGolombNumber();
    def_disp_win_bottom_offset = reader.decodeExponentialGolombNumber();
  }
  const vui_timing_info_present_flag = !!reader.next();
  let vui_num_units_in_tick;
  let vui_time_scale;
  let vui_poc_proportional_to_timing_flag;
  let vui_num_ticks_poc_diff_one_minus1;
  let vui_hrd_parameters_present_flag;
  let vui_hrd_parameters;
  if (vui_timing_info_present_flag) {
    vui_num_units_in_tick = reader.read(32);
    vui_time_scale = reader.read(32);
    vui_poc_proportional_to_timing_flag = !!reader.next();
    if (vui_poc_proportional_to_timing_flag) {
      vui_num_ticks_poc_diff_one_minus1 = reader.decodeExponentialGolombNumber();
    }
    vui_hrd_parameters_present_flag = !!reader.next();
    if (vui_hrd_parameters_present_flag) {
      vui_hrd_parameters = h265ParseHrdParameters(reader, true, sps_max_sub_layers_minus1);
    }
  }
  const bitstream_restriction_flag = !!reader.next();
  let tiles_fixed_structure_flag;
  let motion_vectors_over_pic_boundaries_flag;
  let restricted_ref_pic_lists_flag;
  let min_spatial_segmentation_idc;
  let max_bytes_per_pic_denom;
  let max_bits_per_min_cu_denom;
  let log2_max_mv_length_horizontal;
  let log2_max_mv_length_vertical;
  if (bitstream_restriction_flag) {
    tiles_fixed_structure_flag = !!reader.next();
    motion_vectors_over_pic_boundaries_flag = !!reader.next();
    restricted_ref_pic_lists_flag = !!reader.next();
    min_spatial_segmentation_idc = reader.decodeExponentialGolombNumber();
    max_bytes_per_pic_denom = reader.decodeExponentialGolombNumber();
    max_bits_per_min_cu_denom = reader.decodeExponentialGolombNumber();
    log2_max_mv_length_horizontal = reader.decodeExponentialGolombNumber();
    log2_max_mv_length_vertical = reader.decodeExponentialGolombNumber();
  }
  return {
    aspect_ratio_info_present_flag,
    aspect_ratio_idc,
    sar_width,
    sar_height,
    overscan_info_present_flag,
    overscan_appropriate_flag,
    video_signal_type_present_flag,
    video_format,
    video_full_range_flag,
    colour_description_present_flag,
    colour_primaries,
    transfer_characteristics,
    matrix_coeffs,
    chroma_loc_info_present_flag,
    chroma_sample_loc_type_top_field,
    chroma_sample_loc_type_bottom_field,
    neutral_chroma_indication_flag,
    field_seq_flag,
    frame_field_info_present_flag,
    default_display_window_flag,
    def_disp_win_left_offset,
    def_disp_win_right_offset,
    def_disp_win_top_offset,
    def_disp_win_bottom_offset,
    vui_timing_info_present_flag,
    vui_num_units_in_tick,
    vui_time_scale,
    vui_poc_proportional_to_timing_flag,
    vui_num_ticks_poc_diff_one_minus1,
    vui_hrd_parameters_present_flag,
    vui_hrd_parameters,
    bitstream_restriction_flag,
    tiles_fixed_structure_flag,
    motion_vectors_over_pic_boundaries_flag,
    restricted_ref_pic_lists_flag,
    min_spatial_segmentation_idc,
    max_bytes_per_pic_denom,
    max_bits_per_min_cu_denom,
    log2_max_mv_length_horizontal,
    log2_max_mv_length_vertical
  };
}
function h265ParseHrdParameters(reader, commonInfPresentFlag, maxNumSubLayersMinus1) {
  let nal_hrd_parameters_present_flag;
  let vcl_hrd_parameters_present_flag;
  let sub_pic_hrd_params_present_flag;
  let tick_divisor_minus2;
  let du_cpb_removal_delay_increment_length_minus1;
  let sub_pic_cpb_params_in_pic_timing_sei_flag;
  let dpb_output_delay_du_length_minus1;
  let bit_rate_scale;
  let cpb_size_scale;
  let cpb_size_du_scale;
  let initial_cpb_removal_delay_length_minus1;
  let au_cpb_removal_delay_length_minus1;
  let dpb_output_delay_length_minus1;
  if (commonInfPresentFlag) {
    nal_hrd_parameters_present_flag = !!reader.next();
    vcl_hrd_parameters_present_flag = !!reader.next();
    if (nal_hrd_parameters_present_flag || vcl_hrd_parameters_present_flag) {
      sub_pic_hrd_params_present_flag = !!reader.next();
      if (sub_pic_hrd_params_present_flag) {
        tick_divisor_minus2 = reader.read(8);
        du_cpb_removal_delay_increment_length_minus1 = reader.read(5);
        sub_pic_cpb_params_in_pic_timing_sei_flag = !!reader.next();
        dpb_output_delay_du_length_minus1 = reader.read(5);
      }
      bit_rate_scale = reader.read(4);
      cpb_size_scale = reader.read(4);
      if (sub_pic_hrd_params_present_flag) {
        cpb_size_du_scale = reader.read(4);
      }
      initial_cpb_removal_delay_length_minus1 = reader.read(5);
      au_cpb_removal_delay_length_minus1 = reader.read(5);
      dpb_output_delay_length_minus1 = reader.read(5);
    }
  }
  const fixed_pic_rate_general_flag = [];
  const fixed_pic_rate_within_cvs_flag = [];
  const elemental_duration_in_tc_minus1 = [];
  const low_delay_hrd_flag = [];
  const cpb_cnt_minus1 = [];
  const nalHrdParameters = [];
  const vclHrdParameters = [];
  for (let i = 0; i <= maxNumSubLayersMinus1; i += 1) {
    fixed_pic_rate_general_flag[i] = !!reader.next();
    if (!fixed_pic_rate_general_flag[i]) {
      fixed_pic_rate_within_cvs_flag[i] = !!reader.next();
    }
    if (fixed_pic_rate_within_cvs_flag[i]) {
      elemental_duration_in_tc_minus1[i] = reader.decodeExponentialGolombNumber();
    } else {
      low_delay_hrd_flag[i] = !!reader.next();
    }
    if (!low_delay_hrd_flag[i]) {
      cpb_cnt_minus1[i] = reader.decodeExponentialGolombNumber();
    }
    if (nal_hrd_parameters_present_flag) {
      nalHrdParameters[i] = h265ParseSubLayerHrdParameters(reader, i, getCpbCnt(cpb_cnt_minus1[i]));
    }
    if (vcl_hrd_parameters_present_flag) {
      vclHrdParameters[i] = h265ParseSubLayerHrdParameters(reader, i, getCpbCnt(cpb_cnt_minus1[i]));
    }
  }
  return {
    nal_hrd_parameters_present_flag,
    vcl_hrd_parameters_present_flag,
    sub_pic_hrd_params_present_flag,
    tick_divisor_minus2,
    du_cpb_removal_delay_increment_length_minus1,
    sub_pic_cpb_params_in_pic_timing_sei_flag,
    dpb_output_delay_du_length_minus1,
    bit_rate_scale,
    cpb_size_scale,
    cpb_size_du_scale,
    initial_cpb_removal_delay_length_minus1,
    au_cpb_removal_delay_length_minus1,
    dpb_output_delay_length_minus1,
    fixed_pic_rate_general_flag,
    fixed_pic_rate_within_cvs_flag,
    elemental_duration_in_tc_minus1,
    low_delay_hrd_flag,
    cpb_cnt_minus1,
    nalHrdParameters,
    vclHrdParameters
  };
}
function h265ParseSubLayerHrdParameters(reader, subLayerId, CpbCnt) {
  const bit_rate_value_minus1 = [];
  const cpb_size_value_minus1 = [];
  const cpb_size_du_value_minus1 = [];
  const bit_rate_du_value_minus1 = [];
  const cbr_flag = [];
  for (let i = 0; i < CpbCnt; i += 1) {
    bit_rate_value_minus1[i] = reader.decodeExponentialGolombNumber();
    cpb_size_value_minus1[i] = reader.decodeExponentialGolombNumber();
    if (subLayerId > 0) {
      cbr_flag[i] = !!reader.next();
    }
  }
  return {
    bit_rate_value_minus1,
    cpb_size_value_minus1,
    cpb_size_du_value_minus1,
    bit_rate_du_value_minus1,
    cbr_flag
  };
}
function getCpbCnt(cpb_cnt_minus_1) {
  return cpb_cnt_minus_1 + 1;
}
function h265SearchConfiguration(buffer7) {
  let videoParameterSet;
  let sequenceParameterSet;
  let pictureParameterSet;
  let count = 0;
  for (const nalu of annexBSplitNalu(buffer7)) {
    const header = h265ParseNaluHeader(nalu);
    const raw = {
      ...header,
      data: nalu,
      rbsp: nalu.subarray(2)
    };
    switch (header.nal_unit_type) {
      case 32:
        videoParameterSet = raw;
        break;
      case 33:
        sequenceParameterSet = raw;
        break;
      case 34:
        pictureParameterSet = raw;
        break;
      default:
        continue;
    }
    count += 1;
    if (count === 3) {
      return {
        videoParameterSet,
        sequenceParameterSet,
        pictureParameterSet
      };
    }
  }
  throw new Error("Invalid data");
}
function h265ParseSpsMultilayerExtension(reader) {
  const inter_view_mv_vert_constraint_flag = !!reader.next();
  return {
    inter_view_mv_vert_constraint_flag
  };
}
function h265ParseSps3dExtension(reader) {
  const iv_di_mc_enabled_flag = [];
  const iv_mv_scal_enabled_flag = [];
  iv_di_mc_enabled_flag[0] = !!reader.next();
  iv_mv_scal_enabled_flag[0] = !!reader.next();
  const log2_ivmc_sub_pb_size_minus3 = reader.decodeExponentialGolombNumber();
  const iv_res_pred_enabled_flag = !!reader.next();
  const depth_ref_enabled_flag = !!reader.next();
  const vsp_mc_enabled_flag = !!reader.next();
  const dbbp_enabled_flag = !!reader.next();
  iv_di_mc_enabled_flag[1] = !!reader.next();
  iv_mv_scal_enabled_flag[1] = !!reader.next();
  const tex_mc_enabled_flag = !!reader.next();
  const log2_texmc_sub_pb_size_minus3 = reader.decodeExponentialGolombNumber();
  const intra_contour_enabled_flag = !!reader.next();
  const intra_dc_only_wedge_enabled_flag = !!reader.next();
  const cqt_cu_part_pred_enabled_flag = !!reader.next();
  const inter_dc_only_enabled_flag = !!reader.next();
  const skip_intra_enabled_flag = !!reader.next();
  return {
    iv_di_mc_enabled_flag,
    iv_mv_scal_enabled_flag,
    log2_ivmc_sub_pb_size_minus3,
    iv_res_pred_enabled_flag,
    depth_ref_enabled_flag,
    vsp_mc_enabled_flag,
    dbbp_enabled_flag,
    tex_mc_enabled_flag,
    log2_texmc_sub_pb_size_minus3,
    intra_contour_enabled_flag,
    intra_dc_only_wedge_enabled_flag,
    cqt_cu_part_pred_enabled_flag,
    inter_dc_only_enabled_flag,
    skip_intra_enabled_flag
  };
}
function h265ParseConfiguration(data) {
  const { videoParameterSet, sequenceParameterSet, pictureParameterSet } = h265SearchConfiguration(data);
  const { profileTierLevel: { generalProfileTier: { profile_space: generalProfileSpace, tier_flag: generalTierFlag, profile_idc: generalProfileIndex, profileCompatibilitySet: generalProfileCompatibilitySet, constraintSet: generalConstraintSet }, general_level_idc: generalLevelIndex } } = h265ParseVideoParameterSet(videoParameterSet.rbsp);
  const { chroma_format_idc, pic_width_in_luma_samples: encodedWidth, pic_height_in_luma_samples: encodedHeight, conf_win_left_offset: cropLeft = 0, conf_win_right_offset: cropRight = 0, conf_win_top_offset: cropTop = 0, conf_win_bottom_offset: cropBottom = 0 } = h265ParseSequenceParameterSet(sequenceParameterSet.rbsp);
  const SubWidthC = getSubWidthC(chroma_format_idc);
  const SubHeightC = getSubHeightC(chroma_format_idc);
  const croppedWidth = encodedWidth - SubWidthC * (cropLeft + cropRight);
  const croppedHeight = encodedHeight - SubHeightC * (cropTop + cropBottom);
  return {
    videoParameterSet,
    sequenceParameterSet,
    pictureParameterSet,
    generalProfileSpace,
    generalProfileIndex,
    generalProfileCompatibilitySet,
    generalTierFlag,
    generalLevelIndex,
    generalConstraintSet,
    encodedWidth,
    encodedHeight,
    cropLeft,
    cropRight,
    cropTop,
    cropBottom,
    croppedWidth,
    croppedHeight
  };
}

// node_modules/@yume-chan/adb-scrcpy/esm/connection.js
import { AdbReverseNotSupportedError, NOOP } from "@yume-chan/adb";
import { delay } from "@yume-chan/async";
import { BufferedReadableStream as BufferedReadableStream4, PushReadableStream as PushReadableStream4 } from "@yume-chan/stream-extra";
var SCRCPY_SOCKET_NAME_PREFIX = "scrcpy";
var AdbScrcpyConnection = class {
  adb;
  options;
  socketName;
  constructor(adb, options) {
    this.adb = adb;
    this.options = options;
    this.socketName = this.getSocketName();
  }
  initialize() {
  }
  getSocketName() {
    let socketName = "localabstract:" + SCRCPY_SOCKET_NAME_PREFIX;
    if (this.options.scid !== void 0) {
      socketName += "_" + this.options.scid.padStart(8, "0");
    }
    return socketName;
  }
  dispose() {
  }
};
var AdbScrcpyForwardConnection = class extends AdbScrcpyConnection {
  #disposed = false;
  #connect() {
    return this.adb.createSocket(this.socketName);
  }
  async #connectAndRetry(sendDummyByte) {
    for (let i = 0; !this.#disposed && i < 100; i += 1) {
      try {
        const stream = await this.#connect();
        if (sendDummyByte) {
          const buffered = new BufferedReadableStream4(stream.readable);
          await buffered.readExactly(1);
          return {
            readable: buffered.release(),
            writable: stream.writable
          };
        }
        return stream;
      } catch {
        await delay(100);
      }
    }
    throw new Error(`Can't connect to server after 100 retries`);
  }
  async getStreams() {
    let { sendDummyByte } = this.options;
    const streams = {};
    if (this.options.video) {
      const stream = await this.#connectAndRetry(sendDummyByte);
      streams.video = stream.readable;
      sendDummyByte = false;
    }
    if (this.options.audio) {
      const stream = await this.#connectAndRetry(sendDummyByte);
      streams.audio = stream.readable;
      sendDummyByte = false;
    }
    if (this.options.control) {
      const stream = await this.#connectAndRetry(sendDummyByte);
      streams.control = stream;
      sendDummyByte = false;
    }
    return streams;
  }
  dispose() {
    this.#disposed = true;
  }
};
var AdbScrcpyReverseConnection = class extends AdbScrcpyConnection {
  #streams;
  #address;
  async initialize() {
    await this.adb.reverse.remove(this.socketName).catch((e) => {
      if (e instanceof AdbReverseNotSupportedError) {
        throw e;
      }
    });
    let queueController;
    const queue = new PushReadableStream4((controller) => {
      queueController = controller;
    });
    this.#streams = queue.getReader();
    this.#address = await this.adb.reverse.add(this.socketName, async (socket) => {
      await queueController.enqueue(socket);
    });
  }
  async #accept() {
    return (await this.#streams.read()).value;
  }
  async getStreams() {
    const streams = {};
    if (this.options.video) {
      const stream = await this.#accept();
      streams.video = stream.readable;
    }
    if (this.options.audio) {
      const stream = await this.#accept();
      streams.audio = stream.readable;
    }
    if (this.options.control) {
      const stream = await this.#accept();
      streams.control = stream;
    }
    return streams;
  }
  dispose() {
    this.adb.reverse.remove(this.#address).catch(NOOP);
  }
};

// node_modules/@yume-chan/adb-scrcpy/esm/client.js
import { AdbReverseNotSupportedError as AdbReverseNotSupportedError2 } from "@yume-chan/adb";
import { AbortController, BufferedReadableStream as BufferedReadableStream5, PushReadableStream as PushReadableStream5, SplitStringStream, TextDecoderStream, tryCancel, WritableStream as WritableStream2 } from "@yume-chan/stream-extra";
import { ExactReadableEndedError } from "@yume-chan/struct";

// node_modules/@yume-chan/adb-scrcpy/esm/video.js
import { StickyEventEmitter } from "@yume-chan/event";
import { InspectStream } from "@yume-chan/stream-extra";
var AdbScrcpyVideoStream = class {
  #options;
  #metadata;
  get metadata() {
    return this.#metadata;
  }
  #stream;
  get stream() {
    return this.#stream;
  }
  #sizeChanged = new StickyEventEmitter();
  get sizeChanged() {
    return this.#sizeChanged.event;
  }
  #width = 0;
  get width() {
    return this.#width;
  }
  #height = 0;
  get height() {
    return this.#height;
  }
  constructor(options, metadata, stream) {
    this.#options = options;
    this.#metadata = metadata;
    this.#stream = stream.pipeThrough(this.#options.createMediaStreamTransformer()).pipeThrough(new InspectStream((packet) => {
      if (packet.type === "configuration") {
        switch (metadata.codec) {
          case ScrcpyVideoCodecId.H264:
            this.#configureH264(packet.data);
            break;
          case ScrcpyVideoCodecId.H265:
            this.#configureH265(packet.data);
            break;
          case ScrcpyVideoCodecId.AV1:
            break;
        }
      } else if (metadata.codec === ScrcpyVideoCodecId.AV1) {
        this.#configureAv1(packet.data);
      }
    }));
  }
  #configureH264(data) {
    const { croppedWidth, croppedHeight } = h264ParseConfiguration(data);
    this.#width = croppedWidth;
    this.#height = croppedHeight;
    this.#sizeChanged.fire({ width: croppedWidth, height: croppedHeight });
  }
  #configureH265(data) {
    const { croppedWidth, croppedHeight } = h265ParseConfiguration(data);
    this.#width = croppedWidth;
    this.#height = croppedHeight;
    this.#sizeChanged.fire({ width: croppedWidth, height: croppedHeight });
  }
  #configureAv1(data) {
    const parser = new Av1(data);
    const sequenceHeader = parser.searchSequenceHeaderObu();
    if (!sequenceHeader) {
      return;
    }
    const { max_frame_width_minus_1, max_frame_height_minus_1 } = sequenceHeader;
    const width = max_frame_width_minus_1 + 1;
    const height = max_frame_height_minus_1 + 1;
    this.#width = width;
    this.#height = height;
    this.#sizeChanged.fire({ width, height });
  }
};

// node_modules/@yume-chan/adb-scrcpy/esm/client.js
function arrayToStream(array) {
  return new PushReadableStream5(async (controller) => {
    for (const item of array) {
      await controller.enqueue(item);
    }
  });
}
function concatStreams(...streams) {
  return new PushReadableStream5(async (controller) => {
    for (const stream of streams) {
      const reader = stream.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        await controller.enqueue(value);
      }
    }
  });
}
var AdbScrcpyExitedError = class extends Error {
  output;
  constructor(output) {
    super("scrcpy server exited prematurely");
    this.output = output;
  }
};
var AdbScrcpyClient = class _AdbScrcpyClient {
  static async pushServer(adb, file, filename = DefaultServerPath) {
    const sync = await adb.sync();
    try {
      await sync.write({
        filename,
        file
      });
    } finally {
      await sync.dispose();
    }
  }
  static async start(adb, path, options) {
    let connection;
    let process;
    try {
      try {
        connection = options.createConnection(adb);
        await connection.initialize();
      } catch (e) {
        if (e instanceof AdbReverseNotSupportedError2) {
          options.value.tunnelForward = true;
          connection = options.createConnection(adb);
          await connection.initialize();
        } else {
          connection = void 0;
          throw e;
        }
      }
      const args = [
        `CLASSPATH=${path}`,
        // Set environment variable
        "app_process",
        "/",
        // Parent dir (unused but required)
        "com.genymobile.scrcpy.Server",
        options.version,
        ...options.serialize()
      ];
      if (options.spawner) {
        process = await options.spawner.spawn(args);
      } else {
        process = await adb.subprocess.noneProtocol.spawn(args);
      }
      const output = process.output.pipeThrough(new TextDecoderStream()).pipeThrough(new SplitStringStream("\n"));
      const lines = [];
      const abortController = new AbortController();
      const pipe = output.pipeTo(new WritableStream2({
        write(chunk) {
          lines.push(chunk);
        }
      }), {
        signal: abortController.signal,
        preventCancel: true
      }).catch((e) => {
        if (abortController.signal.aborted) {
          return;
        }
        throw e;
      });
      const streams = await Promise.race([
        process.exited.then(() => {
          throw new AdbScrcpyExitedError(lines);
        }),
        connection.getStreams()
      ]);
      abortController.abort();
      await pipe;
      return new _AdbScrcpyClient({
        options,
        process,
        output: concatStreams(arrayToStream(lines), output),
        videoStream: streams.video,
        audioStream: streams.audio,
        controlStream: streams.control
      });
    } catch (e) {
      await process?.kill();
      throw e;
    } finally {
      connection?.dispose();
    }
  }
  /**
   * This method will modify the given `options`,
   * so don't reuse it elsewhere.
   */
  static getEncoders(adb, path, options) {
    options.setListEncoders();
    return options.getEncoders(adb, path);
  }
  /**
   * This method will modify the given `options`,
   * so don't reuse it elsewhere.
   */
  static getDisplays(adb, path, options) {
    options.setListDisplays();
    return options.getDisplays(adb, path);
  }
  #options;
  #process;
  #output;
  get output() {
    return this.#output;
  }
  get exited() {
    return this.#process.exited;
  }
  #videoStream;
  /**
   * Gets a `Promise` that resolves to the parsed video stream.
   *
   * On server version 2.1 and above, it will be `undefined` if
   * video is disabled by `options.video: false`.
   *
   * Note: if it's not `undefined`, it must be consumed to prevent
   * the connection from being blocked.
   */
  get videoStream() {
    return this.#videoStream;
  }
  #audioStream;
  /**
   * Gets a `Promise` that resolves to the parsed audio stream.
   *
   * On server versions before 2.0, it will always be `undefined`.
   * On server version 2.0 and above, it will be `undefined` if
   * audio is disabled by `options.audio: false`.
   *
   * Note: if it's not `undefined`, it must be consumed to prevent
   * the connection from being blocked.
   */
  get audioStream() {
    return this.#audioStream;
  }
  #controller;
  /**
   * Gets the control message writer.
   *
   * On server version 1.22 and above, it will be `undefined` if
   * control is disabled by `options.control: false`.
   */
  get controller() {
    return this.#controller;
  }
  get clipboard() {
    return this.#options.clipboard;
  }
  constructor({ options, process, output, videoStream, audioStream, controlStream }) {
    this.#options = options;
    this.#process = process;
    this.#output = output;
    this.#videoStream = videoStream ? this.#createVideoStream(videoStream) : void 0;
    this.#audioStream = audioStream ? this.#createAudioStream(audioStream) : void 0;
    if (controlStream) {
      this.#controller = new ScrcpyControlMessageWriter(controlStream.writable.getWriter(), options);
      this.#parseDeviceMessages(controlStream.readable).catch(() => {
      });
    }
  }
  async #parseDeviceMessages(controlStream) {
    const buffered = new BufferedReadableStream5(controlStream);
    try {
      while (true) {
        let id;
        try {
          const result = await buffered.readExactly(1);
          id = result[0];
        } catch (e) {
          if (e instanceof ExactReadableEndedError) {
            this.#options.deviceMessageParsers.close();
            break;
          }
          throw e;
        }
        await this.#options.deviceMessageParsers.parse(id, buffered);
      }
    } catch (e) {
      this.#options.deviceMessageParsers.error(e);
      await tryCancel(buffered);
    }
  }
  async #createVideoStream(initialStream) {
    const { metadata, stream } = await this.#options.parseVideoStreamMetadata(initialStream);
    return new AdbScrcpyVideoStream(this.#options, metadata, stream);
  }
  async #createAudioStream(initialStream) {
    if (!this.#options.parseAudioStreamMetadata) {
      throw new Error("parsing audio stream is not supported in this version");
    }
    const metadata = await this.#options.parseAudioStreamMetadata(initialStream);
    switch (metadata.type) {
      case "disabled":
      case "errored":
        return metadata;
      case "success":
        return {
          ...metadata,
          stream: metadata.stream.pipeThrough(this.#options.createMediaStreamTransformer())
        };
      default:
        throw new Error(`Unexpected audio metadata type ${metadata["type"]}`);
    }
  }
  async close() {
    await this.#process.kill();
  }
};

// node_modules/@yume-chan/adb-scrcpy/esm/1_15/impl/get-displays.js
async function getDisplays(adb, path, options) {
  try {
    const client = await AdbScrcpyClient.start(adb, path, options);
    await client.close();
    throw new Error("Unexpected server output");
  } catch (e) {
    if (e instanceof AdbScrcpyExitedError) {
      if (e.output[0]?.startsWith("[server] ERROR:")) {
        throw e;
      }
      const displays = [];
      for (const line of e.output) {
        const display = options.parseDisplay(line);
        if (display) {
          displays.push(display);
        }
      }
      return displays;
    }
    throw e;
  }
}

// node_modules/@yume-chan/adb-scrcpy/esm/2_0/impl/get-encoders.js
async function getEncoders(adb, path, options) {
  try {
    const client = await AdbScrcpyClient.start(adb, path, options);
    await client.close();
    throw new Error("Unexpected server output");
  } catch (e) {
    if (e instanceof AdbScrcpyExitedError) {
      if (e.output[0]?.startsWith("[server] ERROR:")) {
        throw e;
      }
      const encoders = [];
      for (const line of e.output) {
        const encoder = options.parseEncoder(line);
        if (encoder) {
          encoders.push(encoder);
        }
      }
      return encoders;
    }
    throw e;
  }
}

// node_modules/@yume-chan/adb-scrcpy/esm/2_1/impl/create-connection.js
function createConnection(adb, options) {
  const connectionOptions = {
    scid: toScrcpyOptionValue(options.scid, void 0),
    video: options.video,
    audio: options.audio,
    control: options.control,
    sendDummyByte: options.sendDummyByte
  };
  if (options.tunnelForward) {
    return new AdbScrcpyForwardConnection(adb, connectionOptions);
  } else {
    return new AdbScrcpyReverseConnection(adb, connectionOptions);
  }
}

// node_modules/@yume-chan/adb-scrcpy/esm/3_3_3.js
var AdbScrcpyOptions3_3_3 = class extends ScrcpyOptions3_3_1 {
  version;
  spawner;
  constructor(init, clientOptions) {
    super(init);
    this.version = clientOptions?.version ?? "3.3.3";
    this.spawner = clientOptions?.spawner;
  }
  getEncoders(adb, path) {
    return getEncoders(adb, path, this);
  }
  getDisplays(adb, path) {
    return getDisplays(adb, path, this);
  }
  createConnection(adb) {
    return createConnection(adb, this.value);
  }
};

// src/relive/session.js
import { ReadableStream as TangoReadableStream } from "@yume-chan/stream-extra";

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/codec/utils.js
function hexDigits(value) {
  return value.toString(16).toUpperCase();
}
function hexTwoDigits(value) {
  return value.toString(16).toUpperCase().padStart(2, "0");
}
function decimalTwoDigits(value) {
  return value.toString(10).padStart(2, "0");
}

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/codec/av1.js
var Av1Codec = class {
  #decoder;
  #updateSize;
  #options;
  #config;
  #configured = false;
  constructor(decoder, updateSize, options) {
    this.#decoder = decoder;
    this.#updateSize = updateSize;
    this.#options = options;
  }
  #parseConfig(data) {
    const parser = new Av1(data);
    const sequenceHeader = parser.searchSequenceHeaderObu();
    if (!sequenceHeader) {
      return;
    }
    const { seq_profile: seqProfile, seq_level_idx: [seqLevelIdx = 0], max_frame_width_minus_1, max_frame_height_minus_1, color_config: { BitDepth, mono_chrome: monoChrome, subsampling_x: subsamplingX, subsampling_y: subsamplingY, chroma_sample_position: chromaSamplePosition, color_description_present_flag } } = sequenceHeader;
    let colorPrimaries;
    let transferCharacteristics;
    let matrixCoefficients;
    let colorRange;
    if (color_description_present_flag) {
      ({
        color_primaries: colorPrimaries,
        transfer_characteristics: transferCharacteristics,
        matrix_coefficients: matrixCoefficients,
        color_range: colorRange
      } = sequenceHeader.color_config);
    } else {
      colorPrimaries = Av1.ColorPrimaries.Bt709;
      transferCharacteristics = Av1.TransferCharacteristics.Bt709;
      matrixCoefficients = Av1.MatrixCoefficients.Bt709;
      colorRange = false;
    }
    const width = max_frame_width_minus_1 + 1;
    const height = max_frame_height_minus_1 + 1;
    this.#updateSize(width, height);
    const codec = [
      "av01",
      seqProfile.toString(16),
      decimalTwoDigits(seqLevelIdx) + (sequenceHeader.seq_tier[0] ? "H" : "M"),
      decimalTwoDigits(BitDepth),
      monoChrome ? "1" : "0",
      (subsamplingX ? "1" : "0") + (subsamplingY ? "1" : "0") + chromaSamplePosition.toString(),
      decimalTwoDigits(colorPrimaries),
      decimalTwoDigits(transferCharacteristics),
      decimalTwoDigits(matrixCoefficients),
      colorRange ? "1" : "0"
    ].join(".");
    this.#config = {
      codec,
      hardwareAcceleration: this.#options?.hardwareAcceleration ?? "no-preference",
      optimizeForLatency: true
    };
    this.#configured = false;
  }
  decode(packet) {
    if (packet.type === "configuration") {
      return;
    }
    this.#parseConfig(packet.data);
    if (!this.#config) {
      throw new Error("Decoder not configured");
    }
    if (packet.keyframe) {
      if (this.#decoder.decodeQueueSize) {
        this.#decoder.reset();
        this.#decoder.configure(this.#config);
        this.#configured = true;
      } else if (!this.#configured) {
        this.#decoder.configure(this.#config);
        this.#configured = true;
      }
    }
    this.#decoder.decode(new EncodedVideoChunk({
      // AV1 requires Scrcpy 2.0 where `keyframe` flag must be set
      type: packet.keyframe ? "key" : "delta",
      timestamp: 0,
      data: packet.data
    }));
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/codec/h26x.js
var H26xDecoder = class {
  #decoder;
  #config;
  #configured = false;
  constructor(decoder) {
    this.#decoder = decoder;
  }
  #configureAndDecodeFirstKeyframe(config, packet) {
    this.#decoder.configure(config);
    this.#configured = true;
    const { raw } = config;
    const data = new Uint8Array(raw.length + packet.data.length);
    data.set(raw, 0);
    data.set(packet.data, raw.length);
    this.#decoder.decode(new EncodedVideoChunk({
      type: "key",
      timestamp: 0,
      data
    }));
  }
  decode(packet) {
    if (packet.type === "configuration") {
      this.#config = {
        ...this.configure(packet.data),
        raw: packet.data
      };
      this.#configured = false;
      return;
    }
    if (!this.#config) {
      throw new Error("Decoder not configured");
    }
    if (packet.keyframe) {
      if (this.#decoder.decodeQueueSize) {
        this.#decoder.reset();
        this.#configureAndDecodeFirstKeyframe(this.#config, packet);
        return;
      }
      if (!this.#configured) {
        this.#configureAndDecodeFirstKeyframe(this.#config, packet);
        return;
      }
    }
    if (!this.#configured) {
      if (packet.keyframe === void 0) {
        this.#configureAndDecodeFirstKeyframe(this.#config, packet);
        return;
      }
      throw new Error("Expect a keyframe but got a delta frame");
    }
    this.#decoder.decode(new EncodedVideoChunk({
      // Treat `undefined` as `key`, otherwise won't decode.
      type: packet.keyframe === false ? "delta" : "key",
      timestamp: 0,
      data: packet.data
    }));
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/codec/h264.js
var H264Decoder = class extends H26xDecoder {
  #updateSize;
  #options;
  constructor(decoder, updateSize, options) {
    super(decoder);
    this.#updateSize = updateSize;
    this.#options = options;
  }
  configure(data) {
    const { profileIndex, constraintSet, levelIndex, croppedWidth, croppedHeight } = h264ParseConfiguration(data);
    this.#updateSize(croppedWidth, croppedHeight);
    const codec = "avc1." + hexTwoDigits(profileIndex) + hexTwoDigits(constraintSet) + hexTwoDigits(levelIndex);
    return {
      codec,
      hardwareAcceleration: this.#options?.hardwareAcceleration ?? "no-preference",
      optimizeForLatency: true
    };
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/codec/h265.js
import { getUint32LittleEndian } from "@yume-chan/no-data-view";
var H265Decoder = class extends H26xDecoder {
  #updateSize;
  #options;
  constructor(decoder, updateSize, options) {
    super(decoder);
    this.#updateSize = updateSize;
    this.#options = options;
  }
  configure(data) {
    const { generalProfileSpace, generalProfileIndex, generalProfileCompatibilitySet, generalTierFlag, generalLevelIndex, generalConstraintSet, croppedWidth, croppedHeight } = h265ParseConfiguration(data);
    this.#updateSize(croppedWidth, croppedHeight);
    const codec = [
      "hev1",
      ["", "A", "B", "C"][generalProfileSpace] + generalProfileIndex.toString(),
      hexDigits(getUint32LittleEndian(generalProfileCompatibilitySet, 0)),
      (generalTierFlag ? "H" : "L") + generalLevelIndex.toString(),
      ...Array.from(generalConstraintSet, hexDigits)
    ].join(".");
    return {
      codec,
      // Microsoft Edge requires explicit size to work
      codedWidth: croppedWidth,
      codedHeight: croppedHeight,
      hardwareAcceleration: this.#options?.hardwareAcceleration ?? "no-preference",
      optimizeForLatency: true
    };
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/decoder.js
import { StickyEventEmitter as StickyEventEmitter2 } from "@yume-chan/event";
import { WritableStream as WritableStream3 } from "@yume-chan/stream-extra";

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/pool.js
var Pool = class {
  #controller;
  #readable = new ReadableStream({
    start: (controller) => {
      this.#controller = controller;
    },
    pull: (controller) => {
      controller.enqueue(this.#initializer());
    }
  }, { highWaterMark: 0 });
  #reader = this.#readable.getReader();
  #initializer;
  #size = 0;
  #capacity;
  constructor(initializer, capacity) {
    this.#initializer = initializer;
    this.#capacity = capacity;
  }
  async borrow() {
    const result = await this.#reader.read();
    return result.value;
  }
  return(value) {
    if (this.#size < this.#capacity) {
      this.#controller.enqueue(value);
      this.#size += 1;
    }
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/snapshot.js
var VideoFrameCapturer = class {
  #canvas;
  #context;
  constructor() {
    if (typeof OffscreenCanvas !== "undefined") {
      this.#canvas = new OffscreenCanvas(1, 1);
    } else {
      this.#canvas = document.createElement("canvas");
      this.#canvas.width = 1;
      this.#canvas.height = 1;
    }
    this.#context = this.#canvas.getContext("bitmaprenderer", {
      alpha: false
    });
  }
  async capture(frame) {
    this.#canvas.width = frame.displayWidth;
    this.#canvas.height = frame.displayHeight;
    const bitmap = await createImageBitmap(frame);
    this.#context.transferFromImageBitmap(bitmap);
    if (this.#canvas instanceof OffscreenCanvas) {
      return await this.#canvas.convertToBlob({
        type: "image/png"
      });
    } else {
      return new Promise((resolve, reject) => {
        this.#canvas.toBlob((blob) => {
          if (!blob) {
            reject(new Error("Failed to convert canvas to blob"));
          } else {
            resolve(blob);
          }
        }, "image/png");
      });
    }
  }
};

// node_modules/@yume-chan/scrcpy-decoder-webcodecs/esm/video/decoder.js
var VideoFrameCapturerPool = /* @__PURE__ */ new Pool(() => new VideoFrameCapturer(), 4);
var WebCodecsVideoDecoder = class {
  static get isSupported() {
    return typeof globalThis.VideoDecoder !== "undefined";
  }
  static capabilities = {
    h264: {},
    h265: {},
    av1: {}
  };
  #codec;
  get codec() {
    return this.#codec;
  }
  #renderer;
  get renderer() {
    return this.#renderer;
  }
  #options;
  #codecDecoder;
  #writable;
  get writable() {
    return this.#writable;
  }
  #error;
  #controller;
  #framesDraw = 0;
  #framesPresented = 0;
  get framesRendered() {
    return this.#framesPresented;
  }
  #framesSkipped = 0;
  get framesSkipped() {
    return this.#framesSkipped;
  }
  #sizeChanged = new StickyEventEmitter2();
  get sizeChanged() {
    return this.#sizeChanged.event;
  }
  #width = 0;
  get width() {
    return this.#width;
  }
  #height = 0;
  get height() {
    return this.#height;
  }
  #decoder;
  #drawing = false;
  #nextFrame;
  #captureFrame;
  #animationFrameId = 0;
  /**
   * Create a new WebCodecs video decoder.
   */
  constructor({ codec, renderer, ...options }) {
    this.#codec = codec;
    this.#renderer = renderer;
    this.#options = options;
    this.#decoder = new VideoDecoder({
      output: (frame) => {
        this.#captureFrame?.close();
        this.#captureFrame = frame.clone();
        if (this.#drawing) {
          if (this.#nextFrame) {
            this.#nextFrame.close();
            this.#framesSkipped += 1;
          }
          this.#nextFrame = frame;
          return;
        }
        void this.#draw(frame);
      },
      error: (error) => {
        this.#setError(error);
      }
    });
    switch (this.#codec) {
      case ScrcpyVideoCodecId.H264:
        this.#codecDecoder = new H264Decoder(this.#decoder, this.#updateSize, this.#options);
        break;
      case ScrcpyVideoCodecId.H265:
        this.#codecDecoder = new H265Decoder(this.#decoder, this.#updateSize, this.#options);
        break;
      case ScrcpyVideoCodecId.AV1:
        this.#codecDecoder = new Av1Codec(this.#decoder, this.#updateSize, this.#options);
        break;
      default:
        throw new Error(`Unsupported codec: ${this.#codec}`);
    }
    this.#writable = new WritableStream3({
      start: (controller) => {
        if (this.#error) {
          controller.error(this.#error);
        } else {
          this.#controller = controller;
        }
      },
      write: (packet) => {
        this.#codecDecoder.decode(packet);
      }
    });
    this.#handleAnimationFrame();
  }
  #setError(error) {
    if (this.#controller) {
      try {
        this.#controller.error(error);
      } catch {
      }
    } else {
      this.#error = error;
    }
  }
  async #draw(frame) {
    try {
      this.#drawing = true;
      this.#updateSize(frame.displayWidth, frame.displayHeight);
      await this.#renderer.draw(frame);
      this.#framesDraw += 1;
      frame.close();
      if (this.#nextFrame) {
        const frame2 = this.#nextFrame;
        this.#nextFrame = void 0;
        await this.#draw(frame2);
      }
      this.#drawing = false;
    } catch (error) {
      this.#setError(error);
    }
  }
  #updateSize = (width, height) => {
    this.#renderer.setSize(width, height);
    this.#width = width;
    this.#height = height;
    this.#sizeChanged.fire({ width, height });
  };
  #handleAnimationFrame = () => {
    if (this.#framesDraw > 0) {
      this.#framesPresented += 1;
      this.#framesSkipped += this.#framesDraw - 1;
      this.#framesDraw = 0;
    }
    this.#animationFrameId = requestAnimationFrame(this.#handleAnimationFrame);
  };
  async snapshot() {
    const frame = this.#captureFrame;
    if (!frame) {
      return void 0;
    }
    const capturer = await VideoFrameCapturerPool.borrow();
    const result = await capturer.capture(frame);
    VideoFrameCapturerPool.return(capturer);
    return result;
  }
  dispose() {
    cancelAnimationFrame(this.#animationFrameId);
    if (this.#decoder.state !== "closed") {
      this.#decoder.close();
    }
    this.#nextFrame?.close();
    this.#captureFrame?.close();
  }
};

// src/relive/input.js
var AndroidKey = {
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
  ARROW_RIGHT: 22
};
var KEY_MAP = {
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
  PageDown: AndroidKey.PAGE_DOWN
};
var ACTION_DOWN = 0;
var ACTION_UP = 1;
var ACTION_MOVE = 2;
var ACTION_CANCEL = 3;
var BUTTON_PRIMARY = 1;
var eventSeq = 0;
var ACTION_NAME = { 0: "DOWN", 1: "UP", 2: "MOVE", 3: "CANCEL" };
function bindInput({ canvas, getSize, getController, log = () => {
}, hoverDot = true }) {
  const disposed = { value: false };
  let pointerDown = false;
  const send = (fn) => {
    const controller = getController?.();
    if (!controller) return null;
    try {
      const result = fn(controller);
      if (result && typeof result.catch === "function") {
        result.catch((error) => log("\u63A7\u5236\u6D88\u606F\u53D1\u9001\u5931\u8D25\uFF1A" + (error?.message || error)));
      }
      return result;
    } catch (error) {
      log("\u63A7\u5236\u6D88\u606F\u5F02\u5E38\uFF1A" + (error?.message || error));
      return null;
    }
  };
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
      screenHeight: size.height
    };
  };
  const touch = (action, clientX, clientY, extra = {}) => {
    const point = toDevice(clientX, clientY);
    if (!point) {
      const rect = canvas.getBoundingClientRect();
      log(`[\u8F93\u5165\u8BCA\u65AD] touch \u88AB\u62D2\uFF1Arect=${rect.width}\xD7${rect.height} size=${JSON.stringify(getSize())}`);
      return;
    }
    const controller = getController?.();
    if (!controller) {
      log(`[\u8F93\u5165\u8BCA\u65AD] touch \u88AB\u4E22\u5F03\uFF1A\u63A7\u5236\u901A\u9053\u8FD8\u6CA1\u5C31\u7EEA\uFF08action=${action}\uFF09`, "err");
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
      ...extra
    };
    const name = ACTION_NAME[action] || String(action);
    eventSeq += 1;
    const important = eventSeq <= 2;
    if (important || action !== ACTION_MOVE) {
      const payload = { ...message, pointerId: String(message.pointerId) };
      log(`[\u8F93\u5165] #${eventSeq} ${name} \u2192 ${JSON.stringify(payload)}`, important ? "" : "dim");
    }
    try {
      const result = controller.injectTouch({ action, ...message });
      if (result && typeof result.catch === "function") {
        result.catch((error) => log(`[\u8F93\u5165] ${name} \u53D1\u9001\u5931\u8D25\uFF1A${error?.message || error}`, "err"));
      }
    } catch (error) {
      log(`[\u8F93\u5165] ${name} \u629B\u5F02\u5E38\uFF1A${error?.message || error}`, "err");
    }
  };
  const tap = (clientX, clientY) => {
    touch(ACTION_DOWN, clientX, clientY);
    setTimeout(() => touch(ACTION_UP, clientX, clientY), 30);
  };
  const cancelTouch = (reason) => {
    const size = getSize();
    const width = size?.width || 0;
    const height = size?.height || 0;
    if (!width || !height) return;
    pointerDown = false;
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
        buttons: 0
      });
      if (result && typeof result.catch === "function") {
        result.catch((error) => log("[\u8F93\u5165] CANCEL \u53D1\u9001\u5931\u8D25\uFF1A" + (error?.message || error), "err"));
      }
    } catch (error) {
      log("[\u8F93\u5165] CANCEL \u629B\u5F02\u5E38\uFF1A" + (error?.message || error), "err");
    }
    if (reason) log(`[\u8F93\u5165] \u5DF2\u8865\u53D1 CANCEL \u6536\u5C3E\uFF08${reason}\uFF09`, "dim");
  };
  const key = (keyCode) => {
    send((c) => c.injectKeyCode({ action: ACTION_DOWN, keyCode, repeat: 0, metaState: 0 }));
    send((c) => c.injectKeyCode({ action: ACTION_UP, keyCode, repeat: 0, metaState: 0 }));
  };
  const onPointerDown = (event) => {
    canvas.focus?.();
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
    if (pointerDown) {
      log("[\u8F93\u5165] \u68C0\u6D4B\u5230\u4E0A\u4E00\u6761\u624B\u52BF\u672A\u7ED3\u675F\uFF0C\u5148\u8865\u53D1 CANCEL", "dim");
      touch(ACTION_CANCEL, event.clientX, event.clientY);
    }
    pointerDown = true;
    try {
      canvas.setPointerCapture?.(event.pointerId);
    } catch (error) {
      log("[\u8F93\u5165] setPointerCapture \u5931\u8D25\uFF1A" + (error?.message || error), "dim");
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
  const onLostCapture = () => {
    if (pointerDown) cancelTouch("\u6307\u9488\u6355\u83B7\u4E22\u5931");
  };
  const onWindowBlur = () => {
    if (pointerDown) cancelTouch("\u7A97\u53E3\u5931\u53BB\u7126\u70B9");
  };
  const onVisibility = () => {
    if (document.hidden && pointerDown) cancelTouch("\u9875\u9762\u5207\u5230\u540E\u53F0");
  };
  const onContextMenu = (event) => event.preventDefault();
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
      log(`[\u8F93\u5165\u8BCA\u65AD] \u9996\u6B21\u6EDA\u8F6E\uFF1AscrollY=${-amount.toFixed(3)}\uFF08\u5E93\u5185\u90E8\u8FD8\u4F1A \xF716\uFF09`);
    }
    send(
      (controller) => controller.injectScroll({
        // 与 injectTouch 同理：字段名必须是 pointerX/pointerY/videoWidth/videoHeight
        pointerX: point.x,
        pointerY: point.y,
        videoWidth: point.screenWidth,
        videoHeight: point.screenHeight,
        scrollX: event.shiftKey ? -amount : 0,
        scrollY: event.shiftKey ? 0 : -amount,
        buttons: 0
      })
    );
  };
  const onKeyDown = (event) => {
    if (event.isComposing) return;
    if (event.ctrlKey || event.metaKey) return;
    const mapped = KEY_MAP[event.key];
    if (mapped !== void 0) {
      event.preventDefault();
      send((c) => c.injectKeyCode({ action: ACTION_DOWN, keyCode: mapped, repeat: 0, metaState: 0 }));
      send((c) => c.injectKeyCode({ action: ACTION_UP, keyCode: mapped, repeat: 0, metaState: 0 }));
      return;
    }
    if (event.key.length === 1) {
      if (event.key.charCodeAt(0) < 128) {
        event.preventDefault();
        send((c) => c.injectText(event.key));
      } else {
        log("\u4E2D\u6587\u7B49\u975E ASCII \u5B57\u7B26\u65E0\u6CD5\u76F4\u63A5\u6CE8\u5165\uFF0C\u8BF7\u5728\u5E73\u677F\u4E0A\u7528\u8F93\u5165\u6CD5");
      }
    }
  };
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
  const resetTimer = setTimeout(() => {
    log("[\u8F93\u5165] \u53D1\u9001 CANCEL \u6E05\u7406\u53EF\u80FD\u6B8B\u7559\u7684\u89E6\u6478\u72B6\u6001", "dim");
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
      if (pointerDown) cancelTouch();
      dot?.remove();
      dot = null;
    }
  };
}

// src/relive/audio.js
function parseAacConfig(data) {
  if (!data || data.length < 2) return null;
  const b0 = data[0];
  const b1 = data[1];
  const samplingFreqIndex = (b0 & 7) << 1 | b1 >> 7 & 1;
  const channelConfig = b1 >> 3 & 15;
  const freqTable = [
    96e3,
    88200,
    64e3,
    48e3,
    44100,
    32e3,
    24e3,
    22050,
    16e3,
    12e3,
    11025,
    8e3,
    7350
  ];
  const sampleRate = freqTable[samplingFreqIndex] || 48e3;
  return { channels: channelConfig || 2, sampleRate };
}
var AudioPlayer = class {
  constructor({ onState = () => {
  }, log = () => {
  } } = {}) {
    this.onState = onState;
    this.log = log;
    this.ctx = null;
    this.gain = null;
    this.decoder = null;
    this.reader = null;
    this.muted = false;
    this.volume = 1;
    this._webCodec = "opus";
    this._nextTime = 0;
    this._closed = false;
    this._configured = false;
    this._everResumed = false;
    this._gotConfig = false;
    this._pktCount = 0;
  }
  /** 在用户手势内调用，唤醒被浏览器自动播放策略暂停的 AudioContext */
  async resume() {
    if (!this.ctx) return false;
    if (this.ctx.state !== "running") {
      try {
        await this.ctx.resume();
      } catch (e) {
        this.log("\u97F3\u9891\u5524\u9192\u5931\u8D25\uFF1A" + (e?.message || e), "err");
        return false;
      }
    }
    const running = this.ctx.state === "running";
    this.log("\u97F3\u9891\u4E0A\u4E0B\u6587\u72B6\u6001\uFF1A" + this.ctx.state, running ? "ok" : "warn");
    this.onState({ available: true, muted: this.muted, volume: this.volume, running });
    return running;
  }
  async start(codec, stream) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) {
      this.log("\u5F53\u524D\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 Web Audio\uFF0C\u65E0\u6CD5\u64AD\u653E\u8BBE\u5907\u58F0\u97F3", "err");
      this.onState({ available: false, error: "\u5F53\u524D\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 Web Audio" });
      return;
    }
    if (typeof AudioDecoder === "undefined") {
      this.log("\u5F53\u524D\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 WebCodecs \u97F3\u9891\u89E3\u7801\uFF08AudioDecoder \u4E0D\u5B58\u5728\uFF09", "err");
      this.onState({ available: false, error: "\u5F53\u524D\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 WebCodecs \u97F3\u9891\u89E3\u7801" });
      return;
    }
    this._webCodec = codec?.webCodecId === "mp4a.66" ? "mp4a.40.2" : codec?.webCodecId || "opus";
    try {
      this.ctx = new Ctx({ sampleRate: 48e3 });
    } catch {
      try {
        this.ctx = new Ctx();
      } catch (e) {
        this.log("\u65E0\u6CD5\u521B\u5EFA\u97F3\u9891\u4E0A\u4E0B\u6587\uFF1A" + (e?.message || e), "err");
        this.onState({ available: false, error: "\u65E0\u6CD5\u521B\u5EFA\u97F3\u9891\u4E0A\u4E0B\u6587" });
        return;
      }
    }
    this.gain = this.ctx.createGain();
    this.gain.gain.value = this.muted ? 0 : this.volume;
    this.gain.connect(this.ctx.destination);
    try {
      this.decoder = new AudioDecoder({
        output: (data) => this._play(data),
        error: (e) => this.log("\u97F3\u9891\u89E3\u7801\u5668\u9519\u8BEF\uFF1A" + (e?.message || e), "err")
      });
    } catch (e) {
      this.log("\u521B\u5EFA AudioDecoder \u5931\u8D25\uFF1A" + (e?.message || e), "err");
      this.onState({ available: false, error: "\u521B\u5EFA AudioDecoder \u5931\u8D25\uFF1A" + (e?.message || e) });
      return;
    }
    this.log("\u97F3\u9891\u542F\u52A8\uFF1A\u89E3\u7801\u5668=" + this._webCodec + "\uFF0CAudioContext \u521D\u59CB\u72B6\u6001=" + this.ctx.state, "ok");
    this.reader = stream.getReader();
    this._pump();
    this._gestureResume = () => {
      this.resume();
      if (this._gestureResume) {
        window.removeEventListener("pointerdown", this._gestureResume);
        window.removeEventListener("keydown", this._gestureResume);
        this._gestureResume = null;
      }
    };
    window.addEventListener("pointerdown", this._gestureResume);
    window.addEventListener("keydown", this._gestureResume);
    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx.state === "running" });
  }
  async _pump() {
    try {
      while (!this._closed) {
        const { value: pkt, done } = await this.reader.read();
        if (done) break;
        if (!pkt) continue;
        if (pkt.type === "configuration") {
          this._gotConfig = true;
          this.log("\u97F3\u9891\u6536\u5230\u914D\u7F6E\u5305\uFF0C\u957F\u5EA6=" + (pkt.data ? pkt.data.length : 0), "dim");
          this._configure(pkt.data);
        } else if (pkt.type === "data") {
          this._pktCount += 1;
          if (this._pktCount <= 3) this.log("\u97F3\u9891\u6570\u636E\u5305#" + this._pktCount + " pts=" + pkt.pts, "dim");
          if (!this._configured) {
            if (this._webCodec === "opus" && pkt.data && pkt.data.length >= 19) {
              this.log("\u97F3\u9891\u65E0\u72EC\u7ACB\u914D\u7F6E\u5305\uFF0C\u7528\u9996\u5E27\u6570\u636E\u4F5C\u4E3A Opus \u914D\u7F6E", "dim");
              this._configure(pkt.data);
            }
            if (!this._configured) continue;
          }
          try {
            const chunk = new EncodedAudioChunk({
              type: "delta",
              timestamp: Number(pkt.pts ?? 0),
              data: pkt.data
            });
            this.decoder.decode(chunk);
          } catch (e) {
            this.log("\u97F3\u9891\u89E3\u7801\u629B\u5F02\u5E38\uFF1A" + (e?.message || e), "err");
          }
        } else {
          this.log("\u97F3\u9891\u672A\u77E5\u5305\u7C7B\u578B\uFF1A" + JSON.stringify(pkt.type), "warn");
        }
      }
    } catch (e) {
      this.log("\u97F3\u9891\u6D41\u8BFB\u53D6\u7ED3\u675F/\u51FA\u9519\uFF1A" + (e?.message || e), "warn");
    }
  }
  _configure(configData) {
    let channels = 2;
    let sampleRate = 48e3;
    if (this._webCodec === "opus" && configData && configData.length >= 10) {
      channels = configData[9] || 2;
    } else if (this._webCodec === "mp4a.40.2") {
      const parsed = parseAacConfig(configData);
      if (parsed) {
        channels = parsed.channels;
        sampleRate = parsed.sampleRate;
      }
    }
    try {
      this.decoder.configure({
        codec: this._webCodec,
        sampleRate,
        numberOfChannels: channels,
        description: configData ? new Uint8Array(configData) : void 0
      });
      this._configured = true;
      this.log("\u97F3\u9891\u89E3\u7801\u5668\u914D\u7F6E\u5B8C\u6210\uFF1A\u58F0\u9053=" + channels + " \u91C7\u6837\u7387=" + sampleRate, "ok");
    } catch (e) {
      this.log("\u97F3\u9891\u89E3\u7801\u5668\u914D\u7F6E\u5931\u8D25\uFF1A" + (e?.message || e), "err");
      this.onState({ available: false, error: "\u97F3\u9891\u89E3\u7801\u5668\u521D\u59CB\u5316\u5931\u8D25\uFF1A" + (e?.message || e) });
      return;
    }
    if (this.ctx && Math.abs(this.ctx.sampleRate - sampleRate) > 1) {
      try {
        const newCtx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate });
        this.gain.disconnect();
        this.gain = newCtx.createGain();
        this.gain.gain.value = this.muted ? 0 : this.volume;
        this.gain.connect(newCtx.destination);
        const old = this.ctx;
        this.ctx = newCtx;
        old.close().catch(() => {
        });
        this.log("\u5DF2\u6309\u91C7\u6837\u7387 " + sampleRate + " \u91CD\u5EFA\u97F3\u9891\u4E0A\u4E0B\u6587", "dim");
      } catch {
      }
    }
  }
  _play(audioData) {
    try {
      if (!this.ctx) return;
      if (this.ctx.state === "suspended") {
        this.ctx.resume().catch(() => {
        });
      }
      const { numberOfChannels, numberOfFrames, sampleRate } = audioData;
      if (!numberOfFrames || !numberOfChannels) {
        audioData.close();
        return;
      }
      if (this._pktCount <= 3) this.log("\u97F3\u9891\u5DF2\u89E3\u7801\u4E00\u5E27\uFF0Cctx \u72B6\u6001=" + this.ctx.state, "dim");
      const ab = this.ctx.createBuffer(numberOfChannels, numberOfFrames, sampleRate);
      const fmt = audioData.format || "f32";
      const planar = String(fmt).endsWith("planar");
      if (planar) {
        for (let c = 0; c < numberOfChannels; c += 1) {
          const ch = new Float32Array(numberOfFrames);
          audioData.copyTo(ch, { planeIndex: c, format: fmt });
          ab.copyToChannel(ch, c);
        }
      } else {
        const inter = new Float32Array(numberOfFrames * numberOfChannels);
        audioData.copyTo(inter, { format: fmt });
        for (let c = 0; c < numberOfChannels; c += 1) {
          const ch = new Float32Array(numberOfFrames);
          for (let i = 0; i < numberOfFrames; i += 1) ch[i] = inter[i * numberOfChannels + c];
          ab.copyToChannel(ch, c);
        }
      }
      audioData.close();
      const dur = numberOfFrames / sampleRate;
      if (this._nextTime < this.ctx.currentTime) this._nextTime = this.ctx.currentTime + 0.03;
      else if (this._nextTime > this.ctx.currentTime + 0.5) this._nextTime = this.ctx.currentTime + 0.03;
      const src = this.ctx.createBufferSource();
      src.buffer = ab;
      src.connect(this.gain);
      src.start(this._nextTime);
      this._nextTime += dur;
    } catch (e) {
      this.log("\u97F3\u9891\u64AD\u653E\u51FA\u9519\uFF1A" + (e?.message || e), "err");
      try {
        audioData.close();
      } catch {
      }
    }
  }
  setMuted(m) {
    this.muted = !!m;
    if (this.gain) this.gain.gain.value = this.muted ? 0 : this.volume;
    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx?.state === "running" });
  }
  setVolume(v) {
    this.volume = Math.max(0, Math.min(1, v));
    if (this.gain && !this.muted) this.gain.gain.value = this.volume;
    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx?.state === "running" });
  }
  stop() {
    this._closed = true;
    if (this._gestureResume) {
      window.removeEventListener("pointerdown", this._gestureResume);
      window.removeEventListener("keydown", this._gestureResume);
      this._gestureResume = null;
    }
    try {
      this.reader?.cancel();
    } catch {
    }
    try {
      this.decoder?.close();
    } catch {
    }
    try {
      this.ctx?.close();
    } catch {
    }
    this.onState({ available: false, muted: this.muted, volume: this.volume });
  }
};

// src/relive/session.js
var SERVER_PATH = "/data/local/tmp/scrcpy-server-v3.3.3.jar";
var SERVER_URL = "js/vendor/scrcpy-server-v3.3.3.jar";
var CanvasRenderer = class {
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
        console.warn("[scrcpy] drawImage \u5931\u8D25", error);
      }
    } finally {
      try {
        frame.close();
      } catch {
      }
    }
  }
};
var sessions = /* @__PURE__ */ new Map();
var pushedDrivers = /* @__PURE__ */ new WeakSet();
var cleanedDrivers = /* @__PURE__ */ new WeakSet();
var sessionSeq = 0;
var activeAudio = null;
var audioStateCb = null;
function emitAudioState(s) {
  if (audioStateCb) audioStateCb(s);
}
function setAudioStateCb(cb) {
  audioStateCb = cb;
}
function setAudioMuted(m) {
  if (activeAudio) activeAudio.setMuted(m);
}
function setAudioVolume(v) {
  if (activeAudio) activeAudio.setVolume(v);
}
function resumeAudio() {
  if (activeAudio) return activeAudio.resume();
  return Promise.resolve(false);
}
function toggleAudioMuted() {
  if (!activeAudio) return true;
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
function getAudioState() {
  return activeAudio ? { available: true, muted: activeAudio.muted, volume: activeAudio.volume } : { available: false, muted: false, volume: 1 };
}
function isSupported() {
  return typeof VideoDecoder !== "undefined";
}
function nextScid() {
  sessionSeq += 1;
  const value = Date.now() % 268435455 ^ sessionSeq * 2654435761;
  return (value & 2147483647).toString(16).padStart(8, "0");
}
var serverBytesCache = null;
async function loadServerBytes() {
  if (serverBytesCache) return serverBytesCache;
  const response = await fetch(SERVER_URL);
  if (!response.ok) throw new Error(`\u65E0\u6CD5\u52A0\u8F7D scrcpy-server\uFF08HTTP ${response.status}\uFF09`);
  const buffer7 = await response.arrayBuffer();
  if (buffer7.byteLength < 1e3) throw new Error("scrcpy-server \u6587\u4EF6\u5F02\u5E38\uFF0C\u53EF\u80FD\u4E0B\u8F7D\u5931\u8D25");
  serverBytesCache = new Uint8Array(buffer7);
  return serverBytesCache;
}
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
async function pushServer(adb, log) {
  const bytes = await loadServerBytes();
  const want = bytes.length;
  const kb = (want / 1024).toFixed(0);
  const have = await remoteServerSize(adb);
  if (have === want) {
    pushedDrivers.add(adb);
    log(`scrcpy-server \u5DF2\u5C31\u7EEA\uFF08\u8BBE\u5907\u4E0A\u5DF2\u6709 ${kb} KB\uFF09`, "dim");
    return;
  }
  if (have === -1) {
    log(
      pushedDrivers.has(adb) ? `\u8BBE\u5907\u4E0A\u7684 scrcpy-server \u4E0D\u89C1\u4E86\uFF08\u88AB\u7CFB\u7EDF\u6E05\u7406\u6389\u4E86\uFF1F\uFF09\uFF0C\u91CD\u65B0\u63A8\u9001\uFF08${kb} KB\uFF09\u2026` : `\u9996\u6B21\u8FDE\u63A5\uFF0C\u63A8\u9001 scrcpy-server\uFF08${kb} KB\uFF09\u2026`
    );
  } else if (have === null) {
    log(`\u8BFB\u4E0D\u5230\u8BBE\u5907\u4E0A\u7684 scrcpy-server \u5927\u5C0F\uFF0C\u76F4\u63A5\u91CD\u63A8\uFF08${kb} KB\uFF09\u2026`, "dim");
  } else {
    log(`\u8BBE\u5907\u4E0A\u7684 scrcpy-server \u5927\u5C0F\u4E0D\u7B26\uFF08\u8BBE\u5907 ${have} / \u672C\u5730 ${want} \u5B57\u8282\uFF09\uFF0C\u91CD\u65B0\u63A8\u9001\u2026`);
  }
  const push = async () => {
    const stream = new TangoReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      }
    });
    await AdbScrcpyClient.pushServer(adb, stream, SERVER_PATH);
  };
  await push();
  let after = await remoteServerSize(adb);
  if (after !== want) {
    log(`\u63A8\u9001\u540E\u6821\u9A8C\u4E0D\u7B26\uFF08\u8BBE\u5907 ${after} / \u672C\u5730 ${want} \u5B57\u8282\uFF09\uFF0C\u518D\u63A8\u4E00\u6B21\u2026`, "dim");
    await push();
    after = await remoteServerSize(adb);
  }
  if (after === want) {
    pushedDrivers.add(adb);
    log("scrcpy-server \u5DF2\u5C31\u7EEA", "dim");
  } else {
    log(`scrcpy-server \u63A8\u9001\u540E\u4ECD\u4E0D\u5BF9\uFF08\u8BBE\u5907 ${after} / \u672C\u5730 ${want} \u5B57\u8282\uFF09\uFF0C\u542F\u52A8\u5927\u6982\u7387\u5931\u8D25`, "err");
  }
}
async function resolveLauncherActivity(adb, pkg) {
  const text = await adb.subprocess.noneProtocol.spawnWaitText([
    "cmd",
    "package",
    "resolve-activity",
    "--brief",
    "-c",
    "android.intent.category.LAUNCHER",
    pkg
  ]);
  const lines = String(text).split("\n").map((s) => s.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i].includes("/")) return lines[i];
  }
  return null;
}
async function launchAppOnDisplay(adb, pkg, displayId, log) {
  const component = await resolveLauncherActivity(adb, pkg);
  if (!component) {
    log(`\u627E\u4E0D\u5230 ${pkg} \u7684\u542F\u52A8\u5165\u53E3`, "err");
    return false;
  }
  const text = await adb.subprocess.noneProtocol.spawnWaitText([
    "am",
    "start",
    "--display",
    String(displayId),
    "-n",
    component
  ]);
  const normalized = String(text).replace(/\s+/g, " ").trim();
  if (/Error|Exception|does not exist/i.test(normalized)) {
    log(`am start \u56DE\u62A5\u5F02\u5E38\uFF1A${normalized}`, "err");
    return false;
  }
  log(`\u5DF2\u5728 display ${displayId} \u4E0A\u542F\u52A8 ${component}`, "ok");
  return true;
}
var replayDone = false;
async function forceCleanup(adb, log) {
  cleanedDrivers.delete(adb);
  await pkillServer(adb, log);
}
function buildInit({ mode, width, height, dpi, maxSize, maxFps, bitRate, scid, audio = false, log = () => {
} }) {
  const isWindow = mode === "window";
  const base = {
    video: true,
    audio: !!audio,
    control: true,
    maxFps,
    videoBitRate: bitRate,
    tunnelForward: true
    // 浏览器没有本地 TCP 端口做反向隧道
  };
  if (!isWindow) base.maxSize = maxSize;
  if (scid) base.scid = scid;
  if (isWindow) {
    const w = Math.round(Number(width)) || 0;
    const h = Math.round(Number(height)) || 0;
    const d = Math.round(Number(dpi)) || 0;
    const size = `${w}x${h}`;
    base.newDisplay = d > 0 ? `${size}/${d}` : size;
    base.videoEncoder = "c2.android.avc.encoder";
    base.maxFps = Math.min(maxFps, 20);
    base.videoBitRate = Math.min(bitRate, 4e6);
    log(
      `[\u8BCA\u65AD] \u5C3A\u5BF8\u5165\u53C2 width=${JSON.stringify(width)}(${typeof width}) height=${JSON.stringify(height)}(${typeof height}) dpi=${JSON.stringify(dpi)}(${typeof dpi}) \u2192 new_display=${base.newDisplay}`,
      "dim"
    );
  }
  log(
    `[\u8BCA\u65AD] \u542F\u52A8\u53C2\u6570 scid=${base.scid ?? "(\u9ED8\u8BA4 socket)"} maxSize=${base.maxSize ?? "-"} maxFps=${base.maxFps} bitRate=${base.videoBitRate} \u7F16\u7801\u5668=${base.videoEncoder ?? "\u786C\u4EF6\u9ED8\u8BA4"}`,
    "dim"
  );
  return base;
}
function buildOptions(args) {
  return new AdbScrcpyOptions3_3_3(buildInit(args), args.spawner ? { spawner: args.spawner } : void 0);
}
function codecName(codec) {
  const map = { 1748121140: "h264", 1748121141: "h265", 1635135537: "av1" };
  const num = Number(codec);
  if (map[num]) return map[num];
  const hex = Number.isFinite(num) ? "0x" + num.toString(16) : "\u975E\u6570\u5B57";
  return `${String(codec)}\uFF08${hex}\uFF0C\u672A\u8BC6\u522B\uFF09`;
}
var sleep2 = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
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
    bitRate = 8e6,
    useScid = true,
    log = () => {
    },
    onIssue = null
  } = opts;
  const adb = driver.adb;
  const sessionId = id || `s${++sessionSeq}`;
  const isWindow = mode === "window";
  await pushServer(adb, log);
  let audioEnabled = false;
  let sdk = 0;
  try {
    sdk = await getAndroidSdk(adb);
    audioEnabled = sdk >= 31;
  } catch {
  }
  log(
    audioEnabled ? `\u68C0\u6D4B\u5230 Android SDK ${sdk}\uFF0C\u5DF2\u542F\u7528\u97F3\u9891\u540C\u6B65` : `Android SDK ${sdk} < 31\uFF0C\u6682\u4E0D\u542F\u7528\u97F3\u9891\uFF08\u8001\u8BBE\u5907\u5F00\u97F3\u9891\u4F1A Aborted\uFF09`,
    "dim"
  );
  const scid = useScid ? nextScid() : void 0;
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
    log
  });
  log(isWindow ? `\u521B\u5EFA\u865A\u62DF\u663E\u793A ${width}\xD7${height}\u2026` : "\u542F\u52A8 scrcpy \u670D\u52A1\u2026");
  let client;
  try {
    client = await AdbScrcpyClient.start(adb, SERVER_PATH, options);
  } catch (error) {
    log("[\u8BCA\u65AD] \u5B9E\u9645\u547D\u4EE4\uFF1A" + (capture.args || []).join(" "), "dim");
    const fromClient = Array.isArray(error?.output) ? error.output.map((line) => String(line).trim()).filter(Boolean) : [];
    const captured = await capture.flush();
    const fromCapture = String(captured).split("\n").map((line) => line.trim()).filter(Boolean);
    const merged = [.../* @__PURE__ */ new Set([...fromClient, ...fromCapture])];
    if (merged.length) {
      log(`\u670D\u52A1\u7AEF\u8F93\u51FA\uFF08\u5171 ${merged.length} \u884C\uFF0Cclient ${fromClient.length} / \u590D\u5236\u6D41 ${fromCapture.length}\uFF09\uFF1A`, "err");
      merged.slice(-40).forEach((line) => log("  " + line, "err"));
    } else {
      log("\u670D\u52A1\u7AEF\u4E00\u884C\u8F93\u51FA\u90FD\u6CA1\u6709\u5C31\u9000\u51FA\u4E86\uFF08\u8FDE Device \u884C\u90FD\u6CA1\u6253\u5370\uFF09", "err");
    }
    const wrapped = new Error(`scrcpy \u670D\u52A1\u7AEF\u542F\u52A8\u5931\u8D25\uFF1A${error?.message || error}`);
    wrapped.retryable = true;
    wrapped.scid = scid;
    wrapped.args = capture.args;
    wrapped.isWindow = isWindow;
    throw wrapped;
  }
  let displayId = null;
  client.output.pipeTo(
    new WritableStream({
      write(text) {
        const line = String(text).trim();
        if (!line) return;
        const matched = line.match(/\(id=(\d+)\)/);
        if (matched && isWindow) {
          displayId = Number(matched[1]);
          log(`[\u8BCA\u65AD] \u865A\u62DF\u663E\u793A\u7F16\u53F7 displayId=${displayId}`, "dim");
        }
        log(line, line.includes("DEBUG:") ? "dim" : "");
        if (INJECT_DENIED.test(line)) reportInjectIssue(log, onIssue, "scrcpy \u670D\u52A1\u7AEF", line);
      }
    })
  ).catch(() => {
  });
  let videoStream;
  try {
    videoStream = await client.videoStream;
  } catch (error) {
    try {
      await client.close();
    } catch {
    }
    throw new Error(`\u89C6\u9891\u6D41\u5EFA\u7ACB\u5931\u8D25\uFF1A${error?.message || error}`);
  }
  if (!videoStream) {
    try {
      await client.close();
    } catch {
    }
    throw new Error("\u8BBE\u5907\u6CA1\u6709\u8FD4\u56DE\u89C6\u9891\u6D41");
  }
  const renderer = new CanvasRenderer(canvas);
  const rawCodec = videoStream.metadata?.codec;
  log(`[\u8BCA\u65AD] \u89C6\u9891\u6D41\u5DF2\u5C31\u7EEA\uFF0Ccodec=${String(rawCodec)}\uFF08${typeof rawCodec}\uFF09\uFF0C\u5F00\u59CB\u6D88\u8D39\u6570\u636E\u2026`, "dim");
  const decoder = new WebCodecsVideoDecoder({ codec: rawCodec, renderer });
  videoStream.stream.pipeTo(decoder.writable).catch((error) => {
    log("\u89E3\u7801\u4E2D\u65AD\uFF1A" + (error?.message || error), "err");
  });
  let vw = Number(videoStream.width) || 0;
  let vh = Number(videoStream.height) || 0;
  log(`[\u8BCA\u65AD] \u6D88\u8D39\u5F00\u59CB\u65F6 videoStream \u5C3A\u5BF8=${JSON.stringify(videoStream.width)}\xD7${JSON.stringify(videoStream.height)}`, "dim");
  if (!vw || !vh) {
    const sizeResult = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), 5e3);
      const done = (size) => {
        clearTimeout(timer);
        resolve(size);
      };
      try {
        videoStream.sizeChanged((size) => {
          log(`[\u8BCA\u65AD] sizeChanged \u4E8B\u4EF6\uFF1A${size?.width}\xD7${size?.height}`, "dim");
          done(size);
        });
      } catch (error) {
        log("[\u8BCA\u65AD] \u8BA2\u9605 sizeChanged \u5931\u8D25\uFF1A" + (error?.message || error), "err");
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
  if (renderer.width && renderer.height) {
    vw = renderer.width;
    vh = renderer.height;
  }
  if (!vw || !vh) {
    log(
      `[\u8BCA\u65AD] 5 \u79D2\u5185\u6CA1\u6709\u62FF\u5230\u6709\u6548\u5C3A\u5BF8 \u2192 videoStream=${JSON.stringify(videoStream.width)}\xD7${JSON.stringify(videoStream.height)}\uFF0Crenderer=${renderer.width}\xD7${renderer.height}\uFF0C\u5DF2\u6E32\u67D3 ${decoder?.framesRendered ?? 0} \u5E27\uFF0Ccodec=${String(rawCodec)}`,
      "err"
    );
    try {
      await client.close();
    } catch {
    }
    const error = new Error("\u89C6\u9891\u6D41 5 \u79D2\u5185\u6CA1\u6709\u8F93\u51FA\u6709\u6548\u753B\u9762\uFF08\u8BE6\u89C1\u4E0A\u65B9\u8BCA\u65AD\u884C\uFF09");
    error.retryable = true;
    throw error;
  }
  renderer.setSize(vw, vh);
  if (canvas) {
    log(`[\u8BCA\u65AD] \u753B\u5E03 element ${canvas.width}\xD7${canvas.height}\uFF0CvideoStream metadata=${JSON.stringify(rawCodec)}`, "dim");
  }
  log(`\u89C6\u9891\u6D41\u5DF2\u5EFA\u7ACB\uFF1A${vw}\xD7${vh}\uFF0C\u7F16\u7801 ${codecName(rawCodec)}`);
  setTimeout(() => {
    log(
      `[\u8BCA\u65AD] 1 \u79D2\u540E\uFF1A\u753B\u5E03 ${renderer.width}\xD7${renderer.height}\uFF0C\u5DF2\u6E32\u67D3 ${decoder?.framesRendered ?? 0} \u5E27\uFF0C\u8DF3\u8FC7 ${decoder?.framesSkipped ?? 0} \u5E27`,
      "dim"
    );
  }, 1e3);
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
      if (!client.controller) throw new Error("\u63A7\u5236\u901A\u9053\u672A\u5C31\u7EEA");
      await client.controller.startApp(pkg);
      this.app = pkg;
    },
    key(code) {
      this.input?.key(code);
    },
    async stop() {
      try {
        this.input?.dispose();
      } catch {
      }
      this.input = null;
      if (this.audio) {
        if (activeAudio === this.audio) activeAudio = null;
        try {
          this.audio.stop();
        } catch {
        }
        this.audio = null;
      }
      try {
        this.decoder?.dispose?.();
      } catch {
      }
      this.decoder = null;
      this.renderer = null;
      this.videoStream = null;
      try {
        await client.close();
      } catch {
      }
      try {
        await killServerByScid(adb, this.scid, log);
      } catch {
      }
      try {
        adb.reverse.remove(`localabstract:scrcpy_${String(this.scid).padStart(8, "0")}`).catch(() => {
        });
      } catch {
      }
      sessions.delete(this.id);
    },
    stats() {
      const elapsed = this._startedAt ? (performance.now() - this._startedAt) / 1e3 : 0;
      return {
        fps: elapsed > 0 ? +(this.decoder?.framesRendered ?? 0) / elapsed : 0,
        rendered: this.decoder?.framesRendered ?? 0,
        skipped: this.decoder?.framesSkipped ?? 0,
        width: this.renderer?.width ?? 0,
        height: this.renderer?.height ?? 0
      };
    }
  };
  sessions.set(sessionId, session);
  if (audioEnabled) {
    try {
      const audio = await client.audioStream;
      if (audio && audio.type === "success") {
        const player = new AudioPlayer({ onState: (s) => emitAudioState(s), log: (m, lv) => log("[\u97F3\u9891] " + m, lv || "dim") });
        player.start(audio.codec, audio.stream).catch((e) => log("\u97F3\u9891\u542F\u52A8\u5931\u8D25\uFF1A" + (e?.message || e), "err"));
        session.audio = player;
        activeAudio = player;
        emitAudioState({ available: true, muted: player.muted, volume: player.volume });
        log("\u97F3\u9891\u6D41\u5DF2\u5F00\u542F", "ok");
      } else if (audio) {
        log("\u8BBE\u5907\u672A\u63D0\u4F9B\u97F3\u9891\u6D41\uFF08" + audio.type + "\uFF09", "dim");
      }
    } catch (e) {
      log("\u97F3\u9891\u4E0D\u53EF\u7528\uFF1A" + (e?.message || e), "err");
    }
  }
  session.input = bindInput({
    canvas,
    log,
    // 用渲染器的真实帧尺寸做坐标基准，SPS 解析失败也不影响点击
    getSize: () => ({ width: renderer.width || vw, height: renderer.height || vh }),
    getController: () => client.controller
  });
  if (isWindow && app) {
    await new Promise((resolve) => setTimeout(resolve, 400));
    let launched = false;
    if (displayId != null) {
      try {
        launched = await launchAppOnDisplay(adb, app, displayId, log);
      } catch (error) {
        log(`\u5728\u865A\u62DF\u663E\u793A\u91CC\u542F\u52A8 ${app} \u5931\u8D25\uFF1A${error?.message || error}`, "err");
      }
    } else {
      log("[\u8BCA\u65AD] \u6CA1\u6293\u5230 displayId\uFF0C\u9000\u56DE\u63A7\u5236\u901A\u9053\u542F\u52A8\uFF08\u53EF\u80FD\u843D\u5728\u4E3B\u5C4F\uFF09", "err");
    }
    if (!launched) {
      try {
        await client.controller.startApp(app);
        log(`\u5DF2\u7528\u63A7\u5236\u901A\u9053\u542F\u52A8 ${app}\uFF08\u82E5\u753B\u9762\u4ECD\u9ED1\uFF0C\u8BF4\u660E\u5B83\u843D\u5728\u4E3B\u5C4F\u4E0A\u4E86\uFF09`, "dim");
      } catch (error) {
        log(`\u542F\u52A8 ${app} \u5931\u8D25\uFF1A${error?.message || error}\uFF08\u753B\u9762\u91CC\u662F\u7A7A\u684C\u9762\uFF0C\u53EF\u624B\u52A8\u70B9\u56FE\u6807\uFF09`, "err");
      }
    }
  }
  return {
    id: sessionId,
    width: vw,
    height: vh,
    codec: codecName(rawCodec),
    session
  };
}
async function startSession(opts) {
  const { driver, log = () => {
  }, onIssue = null } = opts;
  if (!driver?.adb) throw new Error("\u8BBE\u5907\u672A\u8FDE\u63A5");
  if (!isSupported()) throw new Error("\u5F53\u524D\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 WebCodecs\uFF0C\u8BF7\u4F7F\u7528 Chrome / Edge 94 \u4EE5\u4E0A\u7248\u672C");
  const adb = driver.adb;
  resetInjectIssue();
  await sendWakeup(adb, log, onIssue);
  log(`[\u8BCA\u65AD] \u5F53\u524D\u6D3B\u52A8\u4F1A\u8BDD ${sessions.size} \u4E2A`, "dim");
  if (sessions.size === 0) {
    const stale = await countScrcpyProcs(adb, null);
    if (stale > 0) log(`[\u8BCA\u65AD] \u542F\u52A8\u524D\u53D1\u73B0 ${stale} \u4E2A\u65E7 scrcpy \u8FDB\u7A0B\uFF0C\u5148\u6E05\u6389\u518D\u542F\u52A8`, "dim");
    await forceCleanup(adb, log);
    await waitForServerGone(adb, log, 6e3);
    if (stale > 0) {
      log("[\u8BCA\u65AD] \u7B49\u786C\u4EF6\u7F16\u7801\u5668\u91CA\u653E\u2026", "dim");
      await sleep2(600);
    }
  }
  const alone = sessions.size === 0;
  const attempt = async (extra) => {
    if (alone) await clearScrcpyReverse(adb, log);
    return startOnce(extra);
  };
  try {
    return await attempt({ ...opts, useScid: true });
  } catch (first) {
    if (!first?.retryable) throw first;
    log("\u542F\u52A8\u5F02\u5E38\uFF1A" + (first?.message || first), "err");
    if (!replayDone) {
      replayDone = true;
      await replayServerCommand(adb, first.args, log);
    }
    await sleep2(250);
    await dumpCrashLog(adb, log);
    await killServerByScid(adb, first.scid, log);
    await sendWakeup(adb, log, onIssue);
    await waitForServerGone(adb, log, 4e3);
    await sleep2(500);
    log("\u6E05\u7406\u672C\u6B21\u5931\u8D25\u8FDB\u7A0B\u540E\u91CD\u8BD5\u2026", "dim");
  }
  await sleep2(700);
  try {
    return await attempt({ ...opts, useScid: true });
  } catch (second) {
    if (!second?.retryable) throw second;
    log("\u4ECD\u7136\u5931\u8D25\uFF1A" + (second?.message || second), "dim");
    await killServerByScid(adb, second.scid, log);
    await waitForServerGone(adb, log, 3e3);
    await sleep2(500);
    log("\u6539\u7528\u9ED8\u8BA4 socket \u540D\u518D\u8BD5\u4E00\u6B21\u2026", "dim");
  }
  await sleep2(500);
  return attempt({ ...opts, useScid: false });
}
async function start({ driver, canvas, maxSize = 1280, maxFps = 30, bitRate = 8e6, log = () => {
}, onIssue = null }) {
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
  await Promise.all(list.map((s) => s.stop().catch(() => {
  })));
}
function getSession(id) {
  return sessions.get(id) || null;
}
function stats(id) {
  if (id) return sessions.get(id)?.stats() ?? null;
  const first = [...sessions.values()][0];
  return first ? first.stats() : { fps: 0, rendered: 0, skipped: 0, width: 0, height: 0 };
}
async function listApps(driver) {
  if (!driver?.adb) throw new Error("\u8BBE\u5907\u672A\u8FDE\u63A5");
  const text = await driver.adb.subprocess.noneProtocol.spawnWaitText(["pm", "list", "packages", "-3"]);
  return String(text).split("\n").map((line) => line.trim().replace(/^package:/, "")).filter((pkg) => pkg && pkg.includes(".")).sort().map((pkg) => {
    const parts = pkg.split(".");
    return { pkg, short: parts[parts.length - 1], label: parts[parts.length - 1] };
  });
}
async function snapshot(id) {
  const session = id ? sessions.get(id) : [...sessions.values()][0];
  return session?.decoder?.snapshot?.() ?? null;
}
async function systemKey(id, name) {
  const session = id ? sessions.get(id) : [...sessions.values()][0];
  if (!session) return;
  if (name === "release") {
    session.input?.cancelTouch?.("\u624B\u52A8");
    return;
  }
  const map = {
    back: AndroidKey.BACK,
    home: AndroidKey.HOME,
    recents: AndroidKey.APP_SWITCH,
    power: AndroidKey.POWER,
    volup: AndroidKey.VOLUME_UP,
    voldown: AndroidKey.VOLUME_DOWN
  };
  const code = map[name];
  if (code !== void 0) session.input?.key(code);
}
async function cleanup(driver) {
  if (!driver?.adb) return;
  await pkillServer(driver.adb, () => {
  });
  cleanedDrivers.delete(driver.adb);
}
async function setShowTouches(driver, on) {
  if (!driver?.adb) return false;
  try {
    await driver.adb.subprocess.noneProtocol.spawnWaitText([
      "settings",
      "put",
      "system",
      "show_touches",
      on ? "1" : "0"
    ]);
    return true;
  } catch {
    return false;
  }
}
var BUILD = "1.1.0";
var ReLive = {
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
  getAudioState
};
var session_default = ReLive;

// src/files/index.js
var TYPE_DIR = 4;
var TYPE_LINK = 10;
function normalizePath(input) {
  const parts = String(input || "/").split("/").filter((part) => part && part !== ".");
  const stack = [];
  for (const part of parts) {
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  return "/" + stack.join("/");
}
function joinPath(base, name) {
  return normalizePath(base.replace(/\/+$/, "") + "/" + name);
}
function parentPath(path) {
  const clean = normalizePath(path);
  if (clean === "/") return "/";
  const at = clean.lastIndexOf("/");
  return at <= 0 ? "/" : clean.slice(0, at);
}
function shQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}
function formatSize(bytes) {
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
function formatTime(mtime) {
  const seconds = Number(mtime);
  if (!seconds) return "";
  const date = new Date(seconds * 1e3);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  const now = /* @__PURE__ */ new Date();
  const sameYear = date.getFullYear() === now.getFullYear();
  const md = `${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  const hm = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  return sameYear ? `${md} ${hm}` : `${date.getFullYear()}-${md}`;
}
function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    const aDir = a.type === TYPE_DIR;
    const bDir = b.type === TYPE_DIR;
    if (aDir !== bDir) return aDir ? -1 : 1;
    return String(a.name).localeCompare(String(b.name), "zh-Hans-CN", { numeric: true });
  });
}
var IMAGE_RE = /\.(png|jpe?g|gif|webp|bmp|avif|svg)$/i;
var VIDEO_RE = /\.(mp4|m4v|webm|mkv|mov|3gp|ts|avi)$/i;
var AUDIO_RE = /\.(mp3|m4a|aac|wav|flac|ogg|opus|amr|wma)$/i;
var PDF_RE = /\.pdf$/i;
var TEXT_RE = /\.(txt|log|md|markdown|json|xml|csv|tsv|ini|conf|cfg|properties|js|mjs|ts|css|html|htm|java|kt|c|h|cpp|hpp|py|sh|bat|yml|yaml|srt|ass|lrc)$/i;
var MIME = {
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
  pdf: "application/pdf"
};
function mimeOf(name) {
  const ext = String(name).split(".").pop().toLowerCase();
  return MIME[ext] || "application/octet-stream";
}
function kindOf(name) {
  const text = String(name);
  if (IMAGE_RE.test(text)) return "image";
  if (VIDEO_RE.test(text)) return "video";
  if (AUDIO_RE.test(text)) return "audio";
  if (PDF_RE.test(text)) return "pdf";
  if (TEXT_RE.test(text)) return "text";
  return "other";
}
function iconFor(entry) {
  const badge = (label, cls) => `<span class="fp-ico ${cls}">${label}</span>`;
  if (entry.type === TYPE_DIR) return badge("\u5939", "i-dir");
  if (entry.type === TYPE_LINK) return badge("\u94FE", "i-link");
  const kind = kindOf(entry.name);
  if (kind === "image") return badge("\u56FE", "i-image");
  if (kind === "video") return badge("\u89C6", "i-video");
  if (kind === "audio") return badge("\u97F3", "i-audio");
  if (kind === "pdf") return badge("PDF", "i-pdf");
  if (kind === "text") return badge("\u6587", "i-text");
  const name = String(entry.name).toLowerCase();
  if (/\.(epub|mobi|azw3)$/.test(name)) return badge("\u4E66", "i-book");
  if (/\.(apk|xapk|apks)$/.test(name)) return badge("\u5305", "i-apk");
  if (/\.(zip|rar|7z|tar|gz)$/.test(name)) return badge("\u538B", "i-zip");
  return badge("\u4EF6", "i-other");
}
async function listDir(driver, path) {
  return driver.withSync(async (sync) => {
    const entries = await sync.readdir(path);
    return entries.filter((entry) => entry.name !== "." && entry.name !== "..").map((entry) => ({
      name: entry.name,
      type: entry.type,
      size: Number(entry.size),
      mtime: Number(entry.mtime)
    }));
  });
}
async function shell(driver, command) {
  const result = await driver.exec(command);
  if (result.exitCode !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    throw new Error(detail || `\u547D\u4EE4\u5931\u8D25\uFF08\u9000\u51FA\u7801 ${result.exitCode}\uFF09`);
  }
  return result.stdout;
}
var SHORTCUTS = [
  { label: "\u5185\u90E8\u5B58\u50A8", path: "/sdcard" },
  { label: "\u4E0B\u8F7D", path: "/sdcard/Download" },
  { label: "\u6587\u6863", path: "/sdcard/Documents" },
  { label: "\u56FE\u7247", path: "/sdcard/DCIM" },
  { label: "\u6839\u76EE\u5F55", path: "/" }
];
function mountFilePanel({ container, getDriver, log = () => {
}, onClose = () => {
} }) {
  const state = {
    path: "/sdcard",
    entries: [],
    selected: null,
    busy: false,
    filter: ""
  };
  container.innerHTML = `
    <div class="fp-bar">
      <button class="fp-btn" data-act="up" title="\u4E0A\u4E00\u7EA7">\u2191</button>
      <button class="fp-btn" data-act="home" title="\u56DE\u5230\u5185\u90E8\u5B58\u50A8">\u2302</button>
      <div class="fp-path" id="fpPath" title="\u70B9\u51FB\u53EF\u624B\u8F93\u8DEF\u5F84">/sdcard</div>
      <input class="fp-filter" id="fpFilter" placeholder="\u7B5B\u9009\u5F53\u524D\u76EE\u5F55\u2026">
      <button class="fp-btn" data-act="mkdir">\u65B0\u5EFA\u6587\u4EF6\u5939</button>
      <button class="fp-btn primary" data-act="upload">\u4E0A\u4F20</button>
      <button class="fp-btn" data-act="refresh">\u5237\u65B0</button>
      <button class="fp-btn" data-act="close" title="\u5173\u95ED">\u2715</button>
    </div>
    <div class="fp-chips">
      ${SHORTCUTS.map((item) => `<button class="fp-chip" data-path="${item.path}">${item.label}</button>`).join("")}
    </div>
    <div class="fp-head-row">
      <span class="fp-col-name">\u540D\u79F0</span>
      <span class="fp-col-size">\u5927\u5C0F</span>
      <span class="fp-col-time">\u4FEE\u6539\u65F6\u95F4</span>
      <span class="fp-col-ops"></span>
    </div>
    <div class="fp-list" id="fpList"></div>
    <div class="fp-status" id="fpStatus">\u8FDE\u63A5\u8BBE\u5907\u540E\u5373\u53EF\u6D4F\u89C8</div>
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
  const BIG_FILE = 300 * 1024 * 1024;
  const TEXT_LIMIT = 8 * 1024 * 1024;
  const pv = document.createElement("div");
  pv.className = "pv";
  pv.innerHTML = `
    <div class="pv-bar">
      <span class="pv-name" id="pvName"></span>
      <span class="pv-meta" id="pvMeta"></span>
      <span class="pv-nav" id="pvNav">
        <button class="fp-btn" data-pv="prev" title="\u4E0A\u4E00\u4E2A\uFF08\u2190\uFF09">\u2039</button>
        <span class="pv-idx" id="pvIdx"></span>
        <button class="fp-btn" data-pv="next" title="\u4E0B\u4E00\u4E2A\uFF08\u2192\uFF09">\u203A</button>
      </span>
      <button class="fp-btn" data-pv="full" id="pvFull" title="\u5168\u5C4F\u67E5\u770B\uFF08F \u6216\u53CC\u51FB\u753B\u9762\uFF09">\u26F6 \u5168\u5C4F</button>
      <button class="fp-btn" data-pv="download" title="\u5B58\u5230\u7535\u8111">\u4E0B\u8F7D</button>
      <button class="fp-btn" data-pv="close" title="\u5173\u95ED\uFF08Esc\uFF09">\u2715</button>
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
  const viewer = { open: false, items: [], index: 0, url: null, token: 0, max: false };
  const setPvStatus = (text, kind = "") => {
    pvStatus.textContent = text || "";
    pvStatus.className = "pv-status" + (kind ? " " + kind : "");
  };
  let pvHome = null;
  let pvSlot = null;
  async function setFullscreen(on) {
    viewer.max = on;
    pv.classList.toggle("max", on);
    pvFull.textContent = on ? "\u8FD8\u539F" : "\u5168\u5C4F";
    pvFull.title = on ? "\u8FD8\u539F\u5230\u6587\u4EF6\u9762\u677F\uFF08F / Esc\uFF09" : "\u5168\u5C4F\u67E5\u770B\uFF08F \u6216\u53CC\u51FB\u753B\u9762\uFF09";
    if (on) {
      if (!pvHome) {
        pvHome = pv.parentNode;
        pvSlot = document.createComment("pv-slot");
        pvHome.insertBefore(pvSlot, pv);
        document.body.appendChild(pv);
      }
      try {
        await pv.requestFullscreen?.();
      } catch {
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
        } catch {
        }
      }
    }
  }
  const toggleFullscreen = () => setFullscreen(!viewer.max);
  document.addEventListener("fullscreenchange", () => {
    if (document.fullscreenElement !== pv && viewer.max && viewer.open) setFullscreen(false);
  });
  function releaseMedia() {
    if (viewer.url) {
      URL.revokeObjectURL(viewer.url);
      viewer.url = null;
    }
    pvBody.querySelectorAll("video,audio").forEach((el) => {
      try {
        el.pause();
        el.removeAttribute("src");
        el.load?.();
      } catch {
      }
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
  async function renderText(blob) {
    const slice = blob.size > TEXT_LIMIT ? blob.slice(0, TEXT_LIMIT) : blob;
    const buffer7 = await slice.arrayBuffer();
    const utf8 = new TextDecoder("utf-8").decode(buffer7);
    const bad = (text2) => (text2.match(/\uFFFD/g) || []).length;
    let text = utf8;
    let encoding = "UTF-8";
    if (bad(utf8) > 3) {
      try {
        const gbk = new TextDecoder("gbk").decode(buffer7);
        if (bad(gbk) < bad(utf8)) {
          text = gbk;
          encoding = "GBK";
        }
      } catch {
      }
    }
    const pre = document.createElement("pre");
    pre.textContent = text;
    pvBody.appendChild(pre);
    setPvStatus(
      blob.size > TEXT_LIMIT ? `${encoding} \xB7 \u53EA\u663E\u793A\u524D ${formatSize(TEXT_LIMIT)}\uFF08\u6587\u4EF6\u5171 ${formatSize(blob.size)}\uFF09` : `${encoding} \xB7 ${formatSize(blob.size)}`
    );
  }
  async function showItem(entry) {
    const driver = getDriver();
    if (!driver || !entry) return;
    const kind = kindOf(entry.name);
    const token = ++viewer.token;
    pvName.textContent = entry.name;
    pvMeta.textContent = `${formatSize(entry.size)} \xB7 ${formatTime(entry.mtime) || "\u2014"}`;
    releaseMedia();
    setPvStatus("\u8BFB\u53D6\u4E2D\u2026 0%");
    let blob;
    try {
      blob = await driver.read(joinPath(state.path, entry.name), {
        onProgress: (done, total) => {
          if (token !== viewer.token) return;
          const percent = total ? Math.round(done / total * 100) : 0;
          setPvStatus(`\u8BFB\u53D6\u4E2D\u2026 ${percent}%\uFF08${formatSize(done)}${total ? " / " + formatSize(total) : ""}\uFF09`);
        }
      });
    } catch (error) {
      if (token === viewer.token) setPvStatus("\u8BFB\u53D6\u5931\u8D25\uFF1A" + (error?.message || error), "err");
      return;
    }
    if (token !== viewer.token) return;
    if (kind === "text") {
      await renderText(blob);
      log(`[\u6587\u4EF6] \u9884\u89C8 ${entry.name}`, "dim");
      return;
    }
    const url = URL.createObjectURL(new Blob([blob], { type: mimeOf(entry.name) }));
    viewer.url = url;
    if (kind === "pdf") {
      const frame = document.createElement("iframe");
      frame.className = "pv-frame";
      frame.src = url;
      pvBody.appendChild(frame);
      setPvStatus(`PDF \xB7 ${formatSize(blob.size)}\uFF08\u6D4F\u89C8\u5668\u5185\u7F6E\u9605\u8BFB\u5668\uFF0C\u7FFB\u9875\u5728\u6846\u5185\u64CD\u4F5C\uFF09`);
      log(`[\u6587\u4EF6] \u9884\u89C8 ${entry.name}`, "dim");
      return;
    }
    const media = document.createElement(kind === "image" ? "img" : kind === "video" ? "video" : "audio");
    if (kind === "image") {
      media.alt = entry.name;
      media.addEventListener("load", () => setPvStatus(`${media.naturalWidth}\xD7${media.naturalHeight} \xB7 ${formatSize(blob.size)}`));
      media.addEventListener("error", () => setPvStatus("\u56FE\u7247\u89E3\u7801\u5931\u8D25\uFF08\u53EF\u80FD\u4E0D\u662F\u771F\u6B63\u7684\u56FE\u7247\u6587\u4EF6\uFF09", "err"));
      media.src = url;
    } else {
      media.controls = true;
      media.autoplay = true;
      media.playsInline = true;
      media.addEventListener("loadedmetadata", () => {
        const total = Number.isFinite(media.duration) ? media.duration : 0;
        const mm = String(Math.floor(total / 60)).padStart(2, "0");
        const ss = String(Math.floor(total % 60)).padStart(2, "0");
        setPvStatus(`${total ? `\u65F6\u957F ${mm}:${ss}` : "\u65F6\u957F\u672A\u77E5"} \xB7 ${formatSize(blob.size)}`);
      });
      media.addEventListener("error", () => {
        setPvStatus("\u6D4F\u89C8\u5668\u89E3\u4E0D\u4E86\u8FD9\u4E2A\u683C\u5F0F\uFF0C\u70B9\u53F3\u4E0A\u300C\u4E0B\u8F7D\u300D\u7528\u672C\u5730\u64AD\u653E\u5668\u770B", "err");
      });
      media.src = url;
      media.play?.().catch(() => {
      });
    }
    pvBody.appendChild(media);
    log(`[\u6587\u4EF6] \u9884\u89C8 ${entry.name}`, "dim");
  }
  function openViewer(entry) {
    const kind = kindOf(entry.name);
    if (kind === "other") {
      downloadEntry(entry);
      return;
    }
    if (entry.size > BIG_FILE) {
      const go = window.confirm(
        `\u300C${entry.name}\u300D\u6709 ${formatSize(entry.size)}\uFF0C
\u8981\u5728\u6D4F\u89C8\u5668\u91CC\u6253\u5F00\u5FC5\u987B\u5148\u6574\u4EFD\u8BFB\u5230\u5185\u5B58\uFF0C\u4F1A\u7B49\u8F83\u4E45\u3002

\u786E\u5B9A\u6253\u5F00\u5417\uFF1F\uFF08\u9009\u53D6\u6D88\u53EF\u4EE5\u70B9 \u2193 \u76F4\u63A5\u4E0B\u8F7D\u5230\u7535\u8111\uFF09`
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
    const visible = keyword ? state.entries.filter((entry) => entry.name.toLowerCase().includes(keyword)) : state.entries;
    listEl.textContent = "";
    if (!visible.length) {
      const empty = document.createElement("div");
      empty.className = "fp-empty";
      empty.textContent = keyword ? "\u6CA1\u6709\u5339\u914D\u7684\u9879\u76EE" : "\u8FD9\u4E2A\u76EE\u5F55\u662F\u7A7A\u7684";
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
        <span class="fp-col-size">${entry.type === TYPE_DIR ? "\u2014" : formatSize(entry.size)}</span>
        <span class="fp-col-time">${formatTime(entry.mtime)}</span>
        <span class="fp-col-ops">
          ${entry.type !== TYPE_DIR && kindOf(entry.name) !== "other" ? '<button class="fp-op" data-op="preview" title="\u5728\u7EBF\u6253\u5F00">\u{1F441}</button>' : ""}
          ${entry.type !== TYPE_DIR ? '<button class="fp-op" data-op="download" title="\u4E0B\u8F7D\u5230\u7535\u8111">\u2193</button>' : ""}
          <button class="fp-op" data-op="rename" title="\u91CD\u547D\u540D">\u270E</button>
          <button class="fp-op danger" data-op="delete" title="\u5220\u9664">\u{1F5D1}</button>
        </span>
      `;
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
      setStatus("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
      return;
    }
    const target = normalizePath(path);
    if (viewer.open) closeViewer();
    if (!quiet) setStatus("\u6B63\u5728\u8BFB\u53D6 " + target + " \u2026");
    try {
      const entries = await listDir(driver, target);
      state.path = target;
      state.entries = sortEntries(entries);
      state.selected = null;
      updatePath();
      render();
      const dirs = state.entries.filter((entry) => entry.type === TYPE_DIR).length;
      setStatus(`${state.entries.length} \u9879\uFF08${dirs} \u4E2A\u6587\u4EF6\u5939\uFF09`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus("\u8BFB\u53D6\u5931\u8D25\uFF1A" + message, "err");
      log(`[\u6587\u4EF6] \u8BFB\u53D6 ${target} \u5931\u8D25\uFF1A${message}`, "err");
    }
  }
  async function uploadFiles(files) {
    const driver = getDriver();
    if (!driver || !files?.length) return;
    if (state.busy) {
      setStatus("\u4E0A\u4E00\u4E2A\u64CD\u4F5C\u8FD8\u6CA1\u7ED3\u675F", "err");
      return;
    }
    state.busy = true;
    let okCount = 0;
    try {
      for (let i = 0; i < files.length; i += 1) {
        const file = files[i];
        const target = joinPath(state.path, file.name);
        const label = files.length > 1 ? `(${i + 1}/${files.length}) ` : "";
        setStatus(`${label}\u4E0A\u4F20 ${file.name} \u2026 0%`);
        try {
          await driver.write(file, target, {
            onProgress: (done, total) => {
              const percent = total ? Math.round(done / total * 100) : 0;
              setStatus(`${label}\u4E0A\u4F20 ${file.name} \u2026 ${percent}%\uFF08${formatSize(done)} / ${formatSize(total)}\uFF09`);
            }
          });
          okCount += 1;
          log(`[\u6587\u4EF6] \u5DF2\u4E0A\u4F20 ${file.name}\uFF08${formatSize(file.size)}\uFF09`, "ok");
        } catch (error) {
          const message = error?.message || String(error);
          setStatus(`\u4E0A\u4F20 ${file.name} \u5931\u8D25\uFF1A${message}`, "err");
          log(`[\u6587\u4EF6] \u4E0A\u4F20 ${file.name} \u5931\u8D25\uFF1A${message}`, "err");
        }
      }
    } finally {
      state.busy = false;
    }
    await load(state.path, { quiet: true });
    setStatus(`\u4E0A\u4F20\u5B8C\u6210\uFF1A\u6210\u529F ${okCount} / \u5171 ${files.length} \u4E2A`);
  }
  async function downloadEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const target = joinPath(state.path, entry.name);
    setStatus(`\u4E0B\u8F7D ${entry.name} \u2026 0%`);
    try {
      const blob = await driver.read(target, {
        onProgress: (done, total) => {
          const percent = total ? Math.round(done / total * 100) : 0;
          setStatus(`\u4E0B\u8F7D ${entry.name} \u2026 ${percent}%\uFF08${formatSize(done)}${total ? " / " + formatSize(total) : ""}\uFF09`);
        }
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = entry.name;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 6e4);
      setStatus(`\u5DF2\u4E0B\u8F7D ${entry.name}\uFF08${formatSize(blob.size)}\uFF09`);
      log(`[\u6587\u4EF6] \u5DF2\u4E0B\u8F7D ${entry.name}\uFF08${formatSize(blob.size)}\uFF09`, "ok");
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`\u4E0B\u8F7D ${entry.name} \u5931\u8D25\uFF1A${message}`, "err");
      log(`[\u6587\u4EF6] \u4E0B\u8F7D ${entry.name} \u5931\u8D25\uFF1A${message}`, "err");
    }
  }
  async function removeEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const target = joinPath(state.path, entry.name);
    const what = entry.type === TYPE_DIR ? "\u6587\u4EF6\u5939" : "\u6587\u4EF6";
    const hint = entry.type === TYPE_DIR ? `\u786E\u5B9A\u5220\u9664\u6587\u4EF6\u5939\u300C${entry.name}\u300D\u5417\uFF1F
\u91CC\u9762\u7684\u5185\u5BB9\u4F1A\u4E00\u8D77\u5220\u6389\uFF0C\u4E0D\u80FD\u6062\u590D\u3002` : `\u786E\u5B9A\u5220\u9664\u6587\u4EF6\u300C${entry.name}\u300D\u5417\uFF1F`;
    if (!window.confirm(hint)) return;
    setStatus(`\u6B63\u5728\u5220\u9664 ${entry.name} \u2026`);
    try {
      await shell(driver, `rm -rf -- ${shQuote(target)}`);
      log(`[\u6587\u4EF6] \u5DF2\u5220\u9664${what} ${entry.name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`\u5DF2\u5220\u9664 ${entry.name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`\u5220\u9664\u5931\u8D25\uFF1A${message}`, "err");
      log(`[\u6587\u4EF6] \u5220\u9664 ${entry.name} \u5931\u8D25\uFF1A${message}`, "err");
    }
  }
  async function renameEntry(entry) {
    const driver = getDriver();
    if (!driver) return;
    const next = window.prompt(`\u91CD\u547D\u540D\u300C${entry.name}\u300D\u4E3A\uFF1A`, entry.name);
    if (next === null) return;
    const name = next.trim();
    if (!name || name === entry.name) return;
    if (name.includes("/")) {
      setStatus("\u540D\u5B57\u91CC\u4E0D\u80FD\u6709 /", "err");
      return;
    }
    const from = joinPath(state.path, entry.name);
    const to = joinPath(state.path, name);
    setStatus(`\u6B63\u5728\u91CD\u547D\u540D ${entry.name} \u2026`);
    try {
      await shell(driver, `mv -f -- ${shQuote(from)} ${shQuote(to)}`);
      log(`[\u6587\u4EF6] ${entry.name} \u2192 ${name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`\u5DF2\u91CD\u547D\u540D\u4E3A ${name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`\u91CD\u547D\u540D\u5931\u8D25\uFF1A${message}`, "err");
      log(`[\u6587\u4EF6] \u91CD\u547D\u540D ${entry.name} \u5931\u8D25\uFF1A${message}`, "err");
    }
  }
  async function makeDir() {
    const driver = getDriver();
    if (!driver) return;
    const name = (window.prompt("\u65B0\u5EFA\u6587\u4EF6\u5939\uFF0C\u540D\u5B57\uFF1A", "\u65B0\u5EFA\u6587\u4EF6\u5939") || "").trim();
    if (!name) return;
    if (name.includes("/")) {
      setStatus("\u540D\u5B57\u91CC\u4E0D\u80FD\u6709 /", "err");
      return;
    }
    const target = joinPath(state.path, name);
    try {
      await shell(driver, `mkdir -p -- ${shQuote(target)}`);
      log(`[\u6587\u4EF6] \u5DF2\u65B0\u5EFA\u6587\u4EF6\u5939 ${name}`, "ok");
      await load(state.path, { quiet: true });
      setStatus(`\u5DF2\u65B0\u5EFA ${name}`);
    } catch (error) {
      const message = error?.message || String(error);
      setStatus(`\u65B0\u5EFA\u5931\u8D25\uFF1A${message}`, "err");
      log(`[\u6587\u4EF6] \u65B0\u5EFA ${name} \u5931\u8D25\uFF1A${message}`, "err");
    }
  }
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
  document.addEventListener(
    "keydown",
    (event) => {
      if (!viewer.open) return;
      const tag = event.target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (event.key === "Escape") {
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
  pathEl.addEventListener("click", () => {
    const input = window.prompt("\u8DF3\u8F6C\u5230\u8DEF\u5F84\uFF1A", state.path);
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
    const files = [...event.dataTransfer?.files || []];
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
    }
  };
}

// js/core/core.js
var GJ = (() => {
  const VERSION = "1.0.0";
  const defaults = { startPage: "home", connectionMethod: "usb", autoConnectAuthorized: true, uiScale: 100, theme: "indigo", cpuInterval: 1e3, pushPath: "/sdcard/", allowDowngrade: false, clearInput: false, clearOutput: false, screenshotDownload: true, screenshotDelete: false, autoFill: true, autoDelay: false };
  const google = [["\u5546\u5E97", "com.android.vending"], ["\u952E\u76D8", "com.google.android.inputmethod.latin"], ["\u64AD\u5BA2", "com.google.android.apps.podcasts"], ["\u90AE\u7BB1", "com.google.android.gm"], ["\u670D\u52A1", "com.google.android.gms"], ["\u5907\u4EFD", "com.google.android.backuptransport"], ["\u4E91\u76D8", "com.google.android.apps.docs"], ["\u641C\u7D22", "com.google.android.googlequicksearchbox"], ["\u6846\u67B6", "com.google.android.gsf"], ["\u7535\u5F71", "com.google.android.videos"], ["\u76F8\u518C", "com.google.android.apps.photos"], ["\u5730\u56FE", "com.google.android.apps.maps"], ["\u97F3\u4E50", "com.google.android.music"], ["Pay", "com.google.android.apps.walletnfcrel"], ["One", "com.google.android.apps.subscriptions.red"], ["Duo", "com.google.android.apps.tachyon"], ["Chrome", "com.android.chrome"], ["YouTube", "com.google.android.youtube"], ["YT Music", "com.google.android.apps.youtube.music"]];
  const slots = [["\u65F6\u95F4", "clock"], ["\u5B9A\u4F4D", "location"], ["\u8033\u673A", "headset"], ["\u6295\u5C04", "cast"], ["\u95F9\u949F", "alarm_clock"], ["\u58F0\u97F3", "volume"], ["\u4FE1\u53F7", "mobile"], ["\u98DE\u884C", "airplane"], ["\u84DD\u7259", "bluetooth"], ["\u7535\u6C60", "battery"], ["\u65E0\u7EBF", "wifi"], ["NFC", "nfc"]];
  const pages = { home: "\u4E3B\u9875", apps: "\u8F6F\u4EF6\u7BA1\u7406", display: "\u663E\u793A\u63A7\u5236", system: "\u7CFB\u7EDF\u754C\u9762", battery: "\u7535\u6C60\u7BA1\u7406", tuning: "\u65E0\u7EA7\u8C03\u8282", scripts: "\u63A7\u673A\u811A\u672C", terminal: "ADB \u7EC8\u7AEF", settings: "\u8F6F\u4EF6\u8BBE\u7F6E", about: "\u5173\u4E8E" };
  const abortError = () => new DOMException("\u64CD\u4F5C\u5DF2\u505C\u6B62", "AbortError");
  function checkAbort(signal) {
    if (signal?.aborted) throw signal.reason || abortError();
  }
  function sleep3(ms, signal) {
    return new Promise((resolve, reject) => {
      checkAbort(signal);
      const done = () => {
        signal?.removeEventListener("abort", stop2);
        resolve();
      };
      const timer = setTimeout(done, ms);
      const stop2 = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", stop2);
        reject(signal.reason || abortError());
      };
      signal?.addEventListener("abort", stop2, { once: true });
    });
  }
  function quote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }
  function pkg(value) {
    const result = String(value || "").trim();
    if (!/^[\w]+(?:\.[\w]+)+$/.test(result)) throw new Error("\u8BF7\u8F93\u5165\u6709\u6548\u7684\u8F6F\u4EF6\u5305\u540D\uFF0C\u4F8B\u5982 com.android.settings");
    return result;
  }
  function number(value, min, max, name = "\u6570\u503C") {
    const n = Number(value);
    if (String(value).trim() === "" || !Number.isFinite(n) || n < min || n > max) throw new Error(`${name}\u5E94\u5728 ${min}\u2014${max} \u4E4B\u95F4`);
    return n;
  }
  function integer(value, min, max, name) {
    const n = number(value, min, max, name);
    if (!Number.isInteger(n)) throw new Error(`${name || "\u6570\u503C"}\u5FC5\u987B\u662F\u6574\u6570`);
    return n;
  }
  function safeName(value) {
    return String(value || "file").replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_").slice(0, 160) || "file";
  }
  function basename(value) {
    return String(value).replaceAll("\\", "/").split("/").pop();
  }
  function timestamp(date = /* @__PURE__ */ new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
  }
  function deviceName(properties) {
    const keys = ["ro.vendor.oplus.market.name", "ro.product.marketname", "ro.product.vendor.marketname", "ro.product.odm.marketname", "ro.vivo.market.name", "ro.vendor.vivo.market.name", "ro.config.marketing_name", "ro.vendor.oplus.market.enname", "ro.product.model"];
    for (const key of keys) {
      const value = String(properties[key] ?? "").trim();
      if (value && !/^(?:unknown|null|undefined)$/i.test(value)) return value;
    }
    return "\u672A\u77E5\u673A\u578B";
  }
  function batteryCsvName(model, date = /* @__PURE__ */ new Date()) {
    return safeName(String(model || "\u672A\u77E5\u673A\u578B").trim() || "\u672A\u77E5\u673A\u578B") + "_" + timestamp(date) + ".csv";
  }
  function props(text) {
    return Object.fromEntries([...String(text).matchAll(/^\[([^\]]+)\]:\s*\[(.*)\]\s*$/gm)].map((m) => [m[1], m[2]]));
  }
  function battery(text) {
    const raw = String(text), data = {};
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
      if (m) data[m[1].trim().toLowerCase()] = m[2];
    }
    const numeric = (key) => data[key] === void 0 ? null : Number(data[key]);
    return { raw, level: numeric("level"), voltage: numeric("voltage") === null ? null : numeric("voltage") / 1e3, temperature: numeric("temperature") === null ? null : numeric("temperature") / 10, ac: data["ac powered"] === "true", usb: data["usb powered"] === "true", wireless: data["wireless powered"] === "true", stopped: /updates stopped/i.test(raw), data };
  }
  function display(size, density) {
    const sizes = [...String(size).matchAll(/(Physical|Override) size:\s*(\d+)x(\d+)/gi)];
    const densities = [...String(density).matchAll(/(Physical|Override) density:\s*(\d+)/gi)];
    const s = sizes.at(-1), d = densities.at(-1);
    return { width: s ? +s[2] : null, height: s ? +s[3] : null, dpi: d ? +d[2] : null, dp: s && d ? Math.round(Math.min(+s[2], +s[3]) * 160 / +d[2]) : null, physicalSize: sizes[0] ? `${sizes[0][2]}x${sizes[0][3]}` : null, physicalDpi: densities[0] ? +densities[0][2] : null };
  }
  function focus(text) {
    const lines = String(text).split(/\r?\n/);
    const preferred = lines.filter((x) => /mCurrentFocus|mFocusedApp|mResumedActivity|topResumedActivity/.test(x));
    for (const line of preferred) {
      const m = line.match(/\b([\w]+(?:\.[\w]+)+)\/([\w.$]+)/);
      if (m) return { package: m[1], activity: m[2].startsWith(".") ? m[1] + m[2] : m[2] };
    }
    return { package: "", activity: "" };
  }
  function cpu(text) {
    return String(text).trim().split(/\r?\n/).map((line) => line.match(/^(\d+):(\d+)$/)).filter(Boolean).map((m) => ({ id: +m[1], mhz: Math.round(+m[2] / 1e3) })).sort((a, b) => a.id - b.id);
  }
  function duration(sec) {
    const n = Math.max(0, Math.floor(Number(sec) || 0));
    return `${Math.floor(n / 86400)}\u5929${Math.floor(n % 86400 / 3600)}\u65F6${Math.floor(n % 3600 / 60)}\u5206`;
  }
  function joinBytes(chunks) {
    const result = new Uint8Array(chunks.reduce((sum, c) => sum + c.length, 0));
    let offset = 0;
    for (const c of chunks) {
      result.set(c, offset);
      offset += c.length;
    }
    return result;
  }
  function argumentsOf(input) {
    const tokens = [];
    let token = "", quoteChar = null, started = false;
    for (let i = 0; i < input.length; i++) {
      const c = input[i];
      if (c === "\\" && input[i + 1] === '"') {
        token += '"';
        i++;
        started = true;
      } else if (quoteChar) {
        if (c === quoteChar) quoteChar = null;
        else token += c;
        started = true;
      } else if (c === '"' || c === "'") {
        quoteChar = c;
        started = true;
      } else if (/\s/.test(c)) {
        if (started) {
          tokens.push(token);
          token = "";
          started = false;
        }
      } else {
        token += c;
        started = true;
      }
    }
    if (quoteChar) throw new Error("\u547D\u4EE4\u4E2D\u7684\u5F15\u53F7\u672A\u95ED\u5408");
    if (started) tokens.push(token);
    return tokens;
  }
  function settings(value) {
    const s = { ...defaults };
    if (!value || typeof value !== "object") return s;
    for (const k of Object.keys(s)) {
      if (typeof value[k] === typeof s[k]) s[k] = value[k];
    }
    if (!pages[s.startPage]) s.startPage = "home";
    s.connectionMethod = "usb";
    if (![80, 85, 90, 95, 100, 105, 110, 115, 120].includes(s.uiScale)) s.uiScale = 100;
    if (!["teal", "indigo", "bluegrey", "green", "purple"].includes(s.theme)) s.theme = "indigo";
    s.cpuInterval = Math.round(Math.max(500, Math.min(6e4, s.cpuInterval)));
    if (!s.pushPath.startsWith("/") || /[\u0000\r\n]/.test(s.pushPath)) s.pushPath = "/sdcard/";
    if (!s.pushPath.endsWith("/")) s.pushPath += "/";
    return s;
  }
  function checkedResult(result) {
    const text = String(result || "").trim();
    if (/^(?:Failure\b|Error:|Exception occurred|Security exception|java\.lang\.|Permission denied)/mi.test(text)) throw new Error(text);
    return result;
  }
  const crcTable = Uint32Array.from({ length: 256 }, (_, n) => {
    for (let i = 0; i < 8; i++) n = n & 1 ? 3988292384 ^ n >>> 1 : n >>> 1;
    return n >>> 0;
  });
  function crc32(bytes) {
    let c = 4294967295;
    for (const b of bytes) c = crcTable[(c ^ b) & 255] ^ c >>> 8;
    return (c ^ 4294967295) >>> 0;
  }
  function zipStore(files) {
    const chunks = [], directory = [];
    let offset = 0, centralLength = 0;
    const encoder = new TextEncoder();
    for (const file of files) {
      const name = encoder.encode(file.name), bytes = file.bytes, crc = crc32(bytes);
      const head = new Uint8Array(30 + name.length), h = new DataView(head.buffer);
      h.setUint32(0, 67324752, true);
      h.setUint16(4, 20, true);
      h.setUint16(6, 2048, true);
      h.setUint16(12, 33, true);
      h.setUint32(14, crc, true);
      h.setUint32(18, bytes.length, true);
      h.setUint32(22, bytes.length, true);
      h.setUint16(26, name.length, true);
      head.set(name, 30);
      const central = new Uint8Array(46 + name.length), c = new DataView(central.buffer);
      c.setUint32(0, 33639248, true);
      c.setUint16(4, 20, true);
      c.setUint16(6, 20, true);
      c.setUint16(8, 2048, true);
      c.setUint16(14, 33, true);
      c.setUint32(16, crc, true);
      c.setUint32(20, bytes.length, true);
      c.setUint32(24, bytes.length, true);
      c.setUint16(28, name.length, true);
      c.setUint32(42, offset, true);
      central.set(name, 46);
      chunks.push(head, bytes);
      directory.push(central);
      offset += head.length + bytes.length;
      centralLength += central.length;
    }
    const end = new Uint8Array(22), e = new DataView(end.buffer);
    e.setUint32(0, 101010256, true);
    e.setUint16(8, files.length, true);
    e.setUint16(10, files.length, true);
    e.setUint32(12, centralLength, true);
    e.setUint32(16, offset, true);
    return new Blob([...chunks, ...directory, end], { type: "application/zip" });
  }
  class Service {
    constructor({ output = () => {
    }, progress = () => {
    }, saveFile = async () => {
    }, history = () => {
    }, getSettings = () => defaults } = {}) {
      this.driver = null;
      this.output = output;
      this.progress = progress;
      this.saveFile = saveFile;
      this.history = history;
      this.getSettings = getSettings;
      this.sdk = null;
      this.currentDisplay = null;
      this.tasks = /* @__PURE__ */ new Set();
    }
    require() {
      if (!this.driver?.connected) throw new Error("\u8BF7\u5148\u8FDE\u63A5\u8BBE\u5907");
      return this.driver;
    }
    async shell(command, { log = true, signal, allowFailure = false } = {}) {
      const d = this.require();
      checkAbort(signal);
      if (log) this.output("command", `$ adb shell ${command}`);
      let streamedOut = false, streamedErr = false;
      const result = await d.exec(command, { signal, onStdout: log ? (text) => {
        streamedOut = true;
        this.output("result", text);
      } : void 0, onStderr: log ? (text) => {
        streamedErr = true;
        this.output("stderr", text);
      } : void 0 });
      if (log) {
        if (result.stdout && !streamedOut) this.output("result", result.stdout.trimEnd());
        if (result.stderr && !streamedErr) this.output("stderr", result.stderr.trimEnd());
        if (!result.stdout && !result.stderr) this.output("result", `\uFF08\u65E0\u8F93\u51FA\uFF0C\u9000\u51FA\u7801 ${result.exitCode ?? "\u672A\u77E5"}\uFF09`);
      }
      if (!allowFailure && result.exitCode !== void 0 && result.exitCode !== null && result.exitCode !== 0) {
        const error = new Error((result.stderr || result.stdout || `\u547D\u4EE4\u9000\u51FA\u7801 ${result.exitCode}`).trim());
        error.exitCode = result.exitCode;
        throw error;
      }
      return result;
    }
    async text(command, options) {
      return (await this.shell(command, options)).stdout;
    }
    async mutation(command, options) {
      return checkedResult(await this.text(command, options));
    }
    async getSdk() {
      if (!this.sdk) this.sdk = Number((await this.text("getprop ro.build.version.sdk", { log: false })).trim());
      return this.sdk;
    }
    async getDisplay() {
      const [s, d] = await Promise.all([this.text("wm size", { log: false }), this.text("wm density", { log: false })]);
      this.currentDisplay = display(s, d);
      return this.currentDisplay;
    }
    async getBattery() {
      return battery(await this.text("dumpsys battery", { log: false }));
    }
    async getCpu() {
      return cpu(await this.text('for c in /sys/devices/system/cpu/cpu[0-9]*; do n=${c##*cpu}; f=$(cat "$c/cpufreq/scaling_cur_freq" 2>/dev/null); [ -n "$f" ] && printf "%s:%s\\n" "$n" "$f"; done', { log: false, allowFailure: true }));
    }
    async getDeviceName() {
      return deviceName(props(await this.text("getprop", { log: false })));
    }
    async getInfo() {
      const optional = async (c) => {
        try {
          return await this.text(c, { log: false, allowFailure: true });
        } catch {
          return "";
        }
      };
      const [p, d, b, uptime, arch, kernel, board, blocks] = await Promise.all([this.text("getprop", { log: false }), this.getDisplay(), this.getBattery(), optional("cat /proc/uptime"), optional("uname -m"), optional("uname -r"), optional("cat /sys/devices/soc0/serial_number"), optional("ls /dev/block")]);
      const v = props(p);
      this.sdk = Number(v["ro.build.version.sdk"]) || null;
      return { brand: v["ro.product.brand"] || "\u2014", model: v["ro.product.model"] || "\u2014", device: v["ro.product.odm.name"] || v["ro.product.device"] || "\u2014", android: `Android ${v["ro.build.version.release"] || "?"} (API ${v["ro.build.version.sdk"] || "?"})`, board: board.trim() || "N/A", abi: v["ro.product.cpu.abi"] || "\u2014", storage: /\bsda\b/.test(blocks) ? "UFS" : /\bmmcblk0\b/.test(blocks) ? "eMMC" : "\u672A\u77E5", display: d.width ? `${d.width}\xD7${d.height} (${d.dpi || "?"} dpi)` : "\u2014", uptime: duration(parseFloat(uptime)), battery: formatBattery(b), arch: arch.trim() || "\u2014", fingerprint: v["ro.build.fingerprint"] || "\u2014", kernel: kernel.trim() || "\u2014" };
    }
    async getFocus() {
      let r = focus(await this.text("dumpsys window windows", { log: false, allowFailure: true }));
      if (!r.package) r = focus(await this.text("dumpsys activity activities", { log: false, allowFailure: true }));
      return r;
    }
    async listPackages() {
      const output = await this.text("pm list packages", { log: false });
      return output.split(/\r?\n/).map((x) => x.replace(/^package:/, "").trim()).filter((x) => /^[\w]+(?:\.[\w]+)+$/.test(x)).sort();
    }
    async paths(name) {
      const text = await this.text(`pm path ${quote(pkg(name))}`, { log: false });
      const paths = text.split(/\r?\n/).filter((x) => x.startsWith("package:")).map((x) => x.slice(8).trim());
      if (!paths.length) throw new Error(`${name} \u672A\u5B89\u88C5\u6216\u65E0\u6743\u8BBF\u95EE`);
      return paths;
    }
    async packageAction(action, name, { signal } = {}) {
      name = pkg(name);
      const p = quote(name);
      if (action !== "restore") await this.paths(name);
      let command;
      switch (action) {
        case "enable":
          command = `pm enable --user 0 ${p}`;
          break;
        case "disable":
          command = `pm disable-user --user 0 ${p}`;
          break;
        case "launch":
          command = `monkey -p ${p} -c android.intent.category.LAUNCHER 1`;
          break;
        case "stop":
          command = `am force-stop ${p}`;
          break;
        case "clear":
          command = `pm clear --user 0 ${p}`;
          break;
        case "uninstall":
          command = `pm uninstall ${await this.isSystemPackage(name) ? "-k " : ""}--user 0 ${p}`;
          break;
        case "uninstall-keep":
          command = `pm uninstall -k --user 0 ${p}`;
          break;
        case "restore":
          command = `cmd package install-existing --user 0 ${p}`;
          break;
        case "info":
          return this.text(`dumpsys package ${p}`, { signal });
        default:
          throw new Error("\u672A\u77E5\u8F6F\u4EF6\u64CD\u4F5C");
      }
      const result = await this.mutation(command, { signal });
      this.history({ time: (/* @__PURE__ */ new Date()).toISOString(), action, package: name });
      return result;
    }
    async isSystemPackage(name) {
      const list = await this.text("pm list packages -s", { log: false });
      return list.split(/\r?\n/).some((x) => x.trim() === `package:${pkg(name)}`);
    }
    async uninstallLock(name, value) {
      name = pkg(name);
      const sdk = await this.getSdk(), map = { 25: 145, 26: 151, 27: 151, 28: 152, 29: 151, 30: 156, 31: 136, 32: 136, 33: 133, 34: 134, 35: 138, 36: 139 }, op = map[sdk];
      if (!op) throw new Error("\u5F53\u524D Android \u7248\u672C\u6CA1\u6709\u53EF\u9A8C\u8BC1\u7684\u5378\u8F7D\u9650\u5236\u63A5\u53E3\uFF0C\u5DF2\u505C\u6B62\u64CD\u4F5C");
      if (await this.isSystemPackage(name)) throw new Error("\u6B64\u529F\u80FD\u4EC5\u9002\u7528\u4E8E\u7B2C\u4E09\u65B9\u8F6F\u4EF6");
      await this.paths(name);
      if (value === void 0) {
        const result = await this.text(`service call package ${op + 1} s16 ${quote(name)} i32 0`, { log: false });
        const words = [...result.matchAll(/\b([0-9a-f]{8})\b/gi)].map((x) => parseInt(x[1], 16));
        if (words[0] !== 0 || ![0, 1].includes(words[1])) throw new Error("\u7CFB\u7EDF\u8FD4\u56DE\u7684\u5378\u8F7D\u9650\u5236\u72B6\u6001\u65E0\u6CD5\u8BC6\u522B\uFF0C\u672A\u6267\u884C\u4FEE\u6539");
        return !!words[1];
      }
      await this.mutation(`service call package ${op} s16 ${quote(name)} i32 ${value ? 1 : 0} i32 0`);
      const actual = await this.uninstallLock(name);
      if (actual !== !!value) throw new Error("\u7CFB\u7EDF\u672A\u63A5\u53D7\u5378\u8F7D\u9650\u5236\u4FEE\u6539");
      return actual;
    }
    async key(code, long = false) {
      if (!/^(?:\d+|KEYCODE_[A-Z_]+)$/.test(String(code))) throw new Error("\u65E0\u6548\u7684\u6309\u952E\u7F16\u53F7");
      return this.mutation(`input keyevent ${long ? "--longpress " : ""}${code}`);
    }
    async setResolution(width, height) {
      width = integer(width, 100, 16384, "\u5BBD\u5EA6");
      height = integer(height, 100, 16384, "\u9AD8\u5EA6");
      await this.mutation(`wm size ${width}x${height}`);
      return this.getDisplay();
    }
    async setDensity(value, unit) {
      let n = number(value, 1, 1e4, unit === "dp" ? "\u6700\u5C0F\u5BBD\u5EA6" : "DPI");
      if (unit === "dp") {
        const d = await this.getDisplay();
        if (!d.width || !d.height) throw new Error("\u65E0\u6CD5\u8BFB\u53D6\u5C4F\u5E55\u5206\u8FA8\u7387");
        n = Math.round(Math.min(d.width, d.height) * 160 / n);
      }
      n = integer(Math.round(n), 72, 1600, "\u76EE\u6807 DPI");
      await this.mutation(`wm density ${n}`);
      return this.getDisplay();
    }
    async resetDisplay(kind) {
      await this.mutation(`wm ${kind === "density" ? "density" : "size"} reset`);
      return this.getDisplay();
    }
    async statusIcons(selected, rotation, seconds) {
      const controlled = slots.map((x) => x[1]);
      const previous = (await this.text("settings get secure icon_blacklist", { log: false })).trim();
      const existing = previous === "null" ? [] : previous.split(",").filter(Boolean);
      const kept = existing.filter((x) => !controlled.includes(x));
      const value = [.../* @__PURE__ */ new Set([...kept, ...selected.filter((x) => controlled.includes(x))])].join(",");
      await this.mutation(`settings put secure icon_blacklist ${quote(value)}`);
      await this.mutation(`settings put secure show_rotation_suggestions ${rotation ? 0 : 1}`);
      await this.mutation(`settings put secure clock_seconds ${seconds ? 1 : 0}`);
    }
    async getSystemSettings() {
      const keys = ["icon_blacklist", "show_rotation_suggestions", "clock_seconds", "sysui_qqs_count", "sysui_rounded_content_padding"];
      const values = await Promise.all(keys.map((k) => this.text(`settings get secure ${k}`, { log: false })));
      return Object.fromEntries(keys.map((k, i) => [k, values[i].trim()]));
    }
    async statusSetting(key, value) {
      if (!["sysui_qqs_count", "sysui_rounded_content_padding"].includes(key)) throw new Error("\u65E0\u6548\u8BBE\u7F6E");
      if (value === "default") return this.mutation(`settings delete secure ${key}`);
      const allowed = key === "sysui_qqs_count" ? [3, 4, 5, 6, 7, 8, 9] : [0, 5, 10, 15, 20, 30];
      if (!allowed.includes(Number(value))) throw new Error("\u65E0\u6548\u8BBE\u7F6E\u503C");
      return this.mutation(`settings put secure ${key} ${Number(value)}`);
    }
    async immersive(kind, target) {
      if (!["status", "navigation", "full", "reset"].includes(kind)) throw new Error("\u65E0\u6548\u6C89\u6D78\u6A21\u5F0F");
      if (kind === "reset") return this.mutation("settings put global policy_control immersive.full=null");
      target = String(target).trim() || "*";
      if (!/^[\w.*,-]+$/.test(target)) throw new Error("\u8F6F\u4EF6\u8303\u56F4\u53EA\u5141\u8BB8\u5305\u540D\u3001\u9017\u53F7\u3001* \u548C -");
      return this.mutation(`settings put global policy_control ${quote(`immersive.${kind}=${target}`)}`);
    }
    async wifiFix() {
      for (const [key, value] of [["captive_portal_http_url", "http://connect.rom.miui.com/generate_204"], ["captive_portal_https_url", "https://connect.rom.miui.com/generate_204"], ["time_zone", "Asia/Shanghai"], ["ntp_server", "ntp1.aliyun.com"]]) await this.mutation(`settings put global ${key} ${quote(value)}`);
    }
    async getTuning() {
      const keys = [["system", "font_scale"], ["global", "window_animation_scale"], ["global", "transition_animation_scale"], ["global", "animator_duration_scale"], ["system", "screen_off_timeout"]];
      const result = await Promise.all(keys.map(([scope, key]) => this.text(`settings get ${scope} ${key}`, { log: false })));
      return Object.fromEntries(keys.map(([, k], i) => [k, result[i].trim() === "null" ? null : Number(result[i])]));
    }
    async tune(key, value) {
      if (!["font_scale", "window_animation_scale", "transition_animation_scale", "animator_duration_scale"].includes(key)) throw new Error("\u65E0\u6548\u8C03\u8282\u9879\u76EE");
      const n = number(value, key === "font_scale" ? 0.2 : 0, 4, "\u500D\u7387");
      return this.mutation(`settings put ${key === "font_scale" ? "system" : "global"} ${key} ${Number(n.toFixed(2))}`);
    }
    async timeout(seconds) {
      return this.mutation(`settings put system screen_off_timeout ${Math.round(number(seconds, 1, 2147483, "\u79D2\u6570") * 1e3)}`);
    }
    async batterySet(key, value) {
      if (key === "temp") value = Math.round(number(value, -50, 150, "\u6E29\u5EA6") * 10);
      else if (key === "level") value = integer(value, 0, 100, "\u7535\u91CF");
      else throw new Error("\u65E0\u6548\u7535\u6C60\u53C2\u6570");
      await this.mutation(`dumpsys battery set ${key} ${value}`);
      return this.getBattery();
    }
    async batterySource(source, enabled) {
      if (!["unplugged", "wireless", "usb", "ac"].includes(source)) throw new Error("\u65E0\u6548\u5145\u7535\u7C7B\u578B");
      if (!enabled) await this.mutation("dumpsys battery reset");
      else if (source === "unplugged") await this.mutation("dumpsys battery unplug");
      else {
        for (const type of ["ac", "usb", "wireless"]) await this.mutation(`dumpsys battery set ${type} ${source === type ? 1 : 0}`);
        await this.mutation("dumpsys battery set status 2");
      }
      return this.getBattery();
    }
    async power() {
      const text = await this.text('printf "current:"; cat /sys/class/power_supply/battery/current_now; printf "voltage:"; cat /sys/class/power_supply/battery/voltage_now', { log: false, allowFailure: true });
      const c = text.match(/current:\s*(-?\d+)/), v = text.match(/voltage:\s*(\d+)/);
      if (c && v) return Number(c[1]) * Number(v[1]) / 1e12;
      const fallback = await this.text("dumpsys activity com.jamcz.powerdumper/.MainActivity power", { log: false, allowFailure: true });
      const match = fallback.match(/P=\s*(-?[\d.]+)\s*W/);
      return match ? Number(match[1]) : null;
    }
    async preparePower() {
      if (await this.power() !== null) return true;
      try {
        await this.paths("com.jamcz.powerdumper");
      } catch {
        return false;
      }
      await this.mutation("am force-stop com.jamcz.powerdumper");
      await this.mutation("am start -n com.jamcz.powerdumper/.MainActivity");
      await sleep3(500);
      return true;
    }
    async reboot(mode) {
      const d = this.require();
      if (!["", "bootloader", "fastboot", "edl", "recovery", "poweroff"].includes(mode)) throw new Error("\u65E0\u6548\u91CD\u542F\u6A21\u5F0F");
      this.output("command", mode === "poweroff" ? "$ adb shell reboot -p" : `$ adb reboot${mode ? " " + mode : ""}`);
      await d.reboot(mode);
      this.output("result", "\u91CD\u542F\u6307\u4EE4\u5DF2\u53D1\u9001");
    }
    async push(file, remote, { signal, log = true } = {}) {
      const d = this.require();
      if (!String(remote).startsWith("/") || /[\u0000\r\n]/.test(remote)) throw new Error("\u624B\u673A\u8DEF\u5F84\u5FC5\u987B\u4EE5 / \u5F00\u5934");
      if (log) this.output("command", `$ adb push ${quote(file.name)} ${quote(remote)}`);
      await d.write(file, remote, { signal, onProgress: (done, total) => this.progress(file.name, done, total) });
      if (log) this.output("result", `${file.name}: ${file.size} \u5B57\u8282\u5DF2\u4F20\u8F93`);
    }
    async pull(remote, name, { signal, category = "\u6587\u4EF6", save = true, log = true } = {}) {
      const d = this.require();
      if (log) this.output("command", `$ adb pull ${quote(remote)} ${quote(name || basename(remote))}`);
      const blob = await d.read(remote, { signal, onProgress: (done, total) => this.progress(name || basename(remote), done, total) });
      if (save) await this.saveFile(blob, safeName(name || basename(remote)), category);
      if (log) this.output("result", `${name || basename(remote)}: ${blob.size} \u5B57\u8282\u5DF2\u63A5\u6536`);
      return blob;
    }
    async extract(name, { signal } = {}) {
      name = pkg(name);
      const paths = await this.paths(name);
      const info = await this.text(`dumpsys package ${quote(name)}`, { log: false });
      const version = info.match(/\bversionName=([^\s]+)/)?.[1] || "unknown";
      if (paths.length === 1) return this.pull(paths[0], `${name}_${safeName(version)}.apk`, { signal, category: "ApkExt" });
      const files = [];
      for (const path of paths) {
        checkAbort(signal);
        const blob2 = await this.pull(path, basename(path), { signal, save: false });
        files.push({ name: basename(path), bytes: new Uint8Array(await blob2.arrayBuffer()) });
      }
      const blob = zipStore(files);
      await this.saveFile(blob, `${name}_${safeName(version)}_split.zip`, "ApkExt");
      return blob;
    }
    async screenshot() {
      const remote = `/sdcard/${timestamp()}.png`;
      await this.mutation(`screencap -p ${quote(remote)}`);
      if (!this.getSettings().screenshotDownload) return { remote };
      const blob = await this.pull(remote, basename(remote), { save: false });
      const signature = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
      if (![137, 80, 78, 71, 13, 10, 26, 10].every((b, i) => signature[i] === b)) throw new Error("\u622A\u5C4F\u672A\u8FD4\u56DE\u6709\u6548 PNG \u6587\u4EF6\uFF0C\u5DF2\u4FDD\u7559\u624B\u673A\u5185\u539F\u6587\u4EF6");
      const saved = await this.saveFile(blob, basename(remote), "Screenshots");
      const retained = !!this.getSettings().screenshotDelete && !saved?.confirmed;
      if (this.getSettings().screenshotDelete && saved?.confirmed) await this.mutation(`rm ${quote(remote)}`);
      return { remote, blob, name: basename(remote), retained };
    }
    async install(files, { split = false, signal } = {}) {
      if (!files.length) throw new Error("\u672A\u9009\u62E9 APK");
      const sdk = await this.getSdk(), options = `-r${this.getSettings().allowDowngrade ? " -d" : ""}${sdk >= 34 ? " --bypass-low-target-sdk-block" : ""}`;
      const staging = [], results = [];
      let session = null, committed = false;
      try {
        for (const file of files) {
          checkAbort(signal);
          if (!/\.apk$/i.test(file.name)) throw new Error(`${file.name} \u4E0D\u662F APK \u6587\u4EF6`);
          const path = `/data/local/tmp/gj_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.apk`;
          staging.push(path);
          await this.push(file, path, { signal });
          if (!split) {
            try {
              const output = await this.mutation(`pm install ${options} ${quote(path)}`, { signal });
              if (!/\bSuccess\b/.test(output)) throw new Error(output || "\u7CFB\u7EDF\u672A\u8FD4\u56DE\u5B89\u88C5\u6210\u529F");
              results.push({ name: file.name, success: true, output });
            } catch (error) {
              if (error.name === "AbortError") throw error;
              results.push({ name: file.name, success: false, output: error.message });
            }
          }
        }
        if (split) {
          const total = files.reduce((n, f) => n + f.size, 0);
          const create = await this.mutation(`pm install-create ${options} -S ${total}`, { signal });
          const match = create.match(/\[(\d+)\]/);
          if (!match) throw new Error(create || "\u521B\u5EFA\u5B89\u88C5\u4F1A\u8BDD\u5931\u8D25");
          session = match[1];
          for (let i = 0; i < files.length; i++) {
            const output2 = await this.mutation(`pm install-write -S ${files[i].size} ${session} ${quote(`part${i}.apk`)} ${quote(staging[i])}`, { signal });
            if (!/\bSuccess\b/.test(output2)) throw new Error(output2 || "\u5199\u5165\u62C6\u5206 APK \u5931\u8D25");
          }
          const output = await this.mutation(`pm install-commit ${session}`, { signal });
          if (!/\bSuccess\b/.test(output)) throw new Error(output || "\u63D0\u4EA4\u5B89\u88C5\u5931\u8D25");
          committed = true;
          results.push({ name: "\u62C6\u5206 APK", success: true, output });
        }
        return results;
      } finally {
        if (session && !committed) await this.text(`pm install-abandon ${session}`, { log: false, allowFailure: true }).catch(() => {
        });
        if (staging.length) await this.text(`rm -f ${staging.map(quote).join(" ")}`, { log: false, allowFailure: true }).catch(() => {
        });
      }
    }
    async execute(input, { signal, files = /* @__PURE__ */ new Map() } = {}) {
      input = String(input).trim();
      if (!input) return "";
      const command = input.replace(/^"?[^"\s]*[\\/]adb(?:\.exe)?"?(?=\s)/i, "adb");
      if (/^fastboot(?:\.exe)?\b/i.test(command)) throw new Error("ADB \u8FDE\u63A5\u4E0D\u80FD\u6267\u884C Fastboot \u534F\u8BAE\u547D\u4EE4\uFF1B\u53EF\u901A\u8FC7\u4E3B\u9875\u91CD\u542F\u8FDB\u5165 Fastboot\uFF1B\u5237\u5199\u5206\u533A\u8BF7\u4F7F\u7528\u4E13\u7528\u5DE5\u5177");
      if (!/^adb(?:\.exe)?\b/i.test(command)) return this.text(command, { signal });
      let rest = command.replace(/^adb(?:\.exe)?\s*/i, "").replace(/^(?:-s\s+(?:"[^"]*"|'[^']*'|\S+)\s+|-d\s+|-e\s+)/, "");
      const verb = rest.match(/^\S+/)?.[0];
      rest = rest.slice(verb?.length || 0).trim();
      if (verb === "shell") {
        if (rest.startsWith('"') && rest.endsWith('"')) rest = rest.slice(1, -1);
        return this.text(rest || 'echo "\u8BF7\u5728\u8F93\u5165\u6846\u4E2D\u8F93\u5165\u547D\u4EE4"', { signal });
      }
      const args = argumentsOf(rest);
      switch (verb) {
        case "reboot":
          return this.reboot(args[0] || "");
        case "get-state":
          return "device";
        case "get-serialno":
          return this.require().serial;
        case "version":
          return `Tango ADB 2.6.4 / \u641E\u673A\u5DE5\u5177\u7BB1 WebADB ${VERSION}`;
        case "devices":
          return `List of devices attached
${this.require().serial}	device`;
        case "uninstall":
          return this.mutation(`pm uninstall ${args.includes("-k") ? "-k " : ""}--user 0 ${quote(pkg(args.at(-1)))}`, { signal });
        case "push": {
          const file = files.get(args[0]) || files.get(basename(args[0]));
          if (!file) throw new Error(`\u8BF7\u5148\u5173\u8054\u672C\u5730\u6587\u4EF6\uFF1A${args[0]}`);
          return this.push(file, args[1]?.endsWith("/") ? args[1] + file.name : args[1], { signal });
        }
        case "pull":
          if (!args[0]) throw new Error("\u7528\u6CD5\uFF1Aadb pull \u624B\u673A\u8DEF\u5F84 [\u6587\u4EF6\u540D]");
          return this.pull(args[0], args[1] ? basename(args[1]) : basename(args[0]), { signal });
        case "install":
        case "install-multiple": {
          const selected = args.filter((x) => /\.apk$/i.test(x)).map((x) => {
            const f = files.get(x) || files.get(basename(x));
            if (!f) throw new Error(`\u8BF7\u5148\u5173\u8054\u672C\u5730 APK\uFF1A${x}`);
            return f;
          });
          return this.install(selected, { split: verb === "install-multiple", signal });
        }
        case "tcpip": {
          const port = integer(args[0] || 5555, 1, 65535, "\u7AEF\u53E3");
          return this.require().control(`tcpip:${port}`);
        }
        case "usb":
          return this.require().control("usb:");
        case "disconnect":
          return this.driver.close();
        case "wait-for-device":
          this.require();
          return "";
        case "exec-out":
          if (/^screencap\b/.test(rest)) return this.screenshot();
          return this.text(rest, { signal });
        default:
          throw new Error(`\u5C1A\u672A\u63D0\u4F9B adb ${verb || ""} \u7684\u7F51\u9875\u9002\u914D\uFF1B\u53EF\u76F4\u63A5\u8F93\u5165 Android shell \u547D\u4EE4`);
      }
    }
  }
  function formatBattery(b) {
    return `${b.level ?? "\u2014"}%\u3000${b.voltage === null ? "\u2014" : b.voltage.toFixed(3)} V\u3000${b.temperature ?? "\u2014"}\u2103`;
  }
  return { VERSION, defaults, google, slots, pages, quote, pkg, number, integer, safeName, basename, timestamp, deviceName, batteryCsvName, props, battery, display, focus, cpu, duration, joinBytes, argumentsOf, settings, checkedResult, zipStore, crc32, sleep: sleep3, checkAbort, abortError, Service, formatBattery };
})();

// src/apps/labels.js
var CACHE_KEY = "relive.appMeta.v1";
var LABEL_KEYS = [
  "app_name",
  "application_label",
  "application_name",
  "app_label",
  "launcher_name",
  "app_title",
  "appname"
];
var ICON_KEY_RE = /^(ic_launcher|ic_launcher_round|app_icon|ic_app|launcher_icon|ic_logo|icon_launcher)/i;
function u1610(b, o) {
  return (b[o] | b[o + 1] << 8) >>> 0;
}
function u3211(b, o) {
  return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;
}
function readLen(b, p, utf8) {
  if (utf8) {
    let v2 = b[p++];
    if (v2 & 128) v2 = (v2 & 127) << 8 | b[p++];
    return { value: v2, next: p };
  }
  let v = u1610(b, p);
  p += 2;
  if (v & 32768) {
    v = (v & 32767) << 16 | u1610(b, p);
    p += 2;
  }
  return { value: v, next: p };
}
function readPool(b, start2) {
  const empty = { strings: [], next: start2 + 8 };
  if (u1610(b, start2) !== 1) return empty;
  const headerSize = u1610(b, start2 + 2);
  const size = u3211(b, start2 + 4);
  const count = u3211(b, start2 + 8);
  if (!size || start2 + size > b.length || count > 2e5) return empty;
  const flags = u3211(b, start2 + 16);
  const stringsStart = u3211(b, start2 + 20);
  const utf8 = !!(flags & 256);
  const dataStart = start2 + stringsStart;
  const offsets = start2 + headerSize;
  const dec8 = new TextDecoder("utf-8");
  const dec16 = new TextDecoder("utf-16le");
  const strings = [];
  for (let i = 0; i < count; i++) {
    let p = dataStart + u3211(b, offsets + i * 4);
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
  return { strings, next: start2 + size };
}
function configRank(type) {
  const lang = String(type.lang || "").toLowerCase();
  const country = String(type.country || "").toUpperCase();
  if (lang === "zh" && (country === "CN" || country === "")) return 100;
  if (lang === "zh") return 90;
  if (!lang) return 60;
  return 10;
}
function readTypeChunk(b, start2, size, keyNames, typeNames, out) {
  const headerSize = u1610(b, start2 + 2);
  const id = b[start2 + 8];
  const typeFlags = b[start2 + 9];
  const entryCount = u3211(b, start2 + 12);
  const entriesStart = u3211(b, start2 + 16);
  if (!headerSize || entryCount > 2e5 || start2 + headerSize > start2 + size) return;
  const cfg = start2 + 20;
  const cfgSize = cfg + 4 <= start2 + size ? u3211(b, cfg) : 0;
  let lang = "";
  let country = "";
  if (cfgSize >= 12) {
    const l1 = b[cfg + 8], l2 = b[cfg + 9], c1 = b[cfg + 10], c2 = b[cfg + 11];
    if (l1 >= 97 && l1 <= 122 && l2 >= 97 && l2 <= 122) lang = String.fromCharCode(l1, l2);
    if (c1 >= 65 && c1 <= 90 && c2 >= 65 && c2 <= 90) country = String.fromCharCode(c1, c2);
  }
  const offsetsBase = start2 + headerSize;
  const entriesBase = start2 + entriesStart;
  const pairs = [];
  if (typeFlags & 1) {
    for (let i = 0; i < entryCount; i++) {
      const idx = u1610(b, offsetsBase + i * 4);
      const off = u1610(b, offsetsBase + i * 4 + 2);
      pairs.push([idx, off * 4]);
    }
  } else if (typeFlags & 2) {
    for (let i = 0; i < entryCount; i++) {
      const off = u1610(b, offsetsBase + i * 2);
      if (off !== 65535) pairs.push([i, off * 4]);
    }
  } else {
    for (let i = 0; i < entryCount; i++) {
      const off = u3211(b, offsetsBase + i * 4);
      if (off !== 4294967295) pairs.push([i, off]);
    }
  }
  const entries = [];
  for (const [, off] of pairs) {
    const e = entriesBase + off;
    if (e + 8 > start2 + size) continue;
    const entrySize = u1610(b, e);
    const entryFlags = u1610(b, e + 2);
    const key = keyNames[u3211(b, e + 4)] || "";
    if (entryFlags & 1) continue;
    const v = e + entrySize;
    if (v + 8 > start2 + size) continue;
    entries.push({ key, dataType: b[v + 3], data: u3211(b, v + 4) });
  }
  out.push({ id, typeName: typeNames[id - 1] || "", lang, country, entries });
}
function readPackage(b, start2, size, global, out) {
  const headerSize = u1610(b, start2 + 2);
  const typeStringsOff = u3211(b, start2 + 268);
  const keyStringsOff = u3211(b, start2 + 276);
  let typeNames = [];
  let keyNames = [];
  let p = start2 + headerSize;
  const end = start2 + size;
  while (p + 8 <= end) {
    const type = u1610(b, p);
    const chunkSize = u3211(b, p + 4);
    if (chunkSize < 8 || p + chunkSize > end) break;
    if (p === start2 + typeStringsOff) typeNames = readPool(b, p).strings;
    else if (p === start2 + keyStringsOff) keyNames = readPool(b, p).strings;
    else if (type === 513) readTypeChunk(b, p, chunkSize, keyNames, typeNames, out);
    p += chunkSize;
  }
}
function parseArsc(b) {
  if (u1610(b, 0) !== 2) throw new Error("resources.arsc \u5934\u4E0D\u662F RES_TABLE_TYPE");
  const headerSize = u1610(b, 2);
  const total = Math.min(u3211(b, 4), b.length);
  let global = [];
  const types = [];
  let p = headerSize;
  let firstPool = true;
  while (p + 8 <= total) {
    const type = u1610(b, p);
    const chunkSize = u3211(b, p + 4);
    if (chunkSize < 8 || p + chunkSize > total) break;
    if (type === 1) {
      const pool = readPool(b, p);
      if (firstPool) global = pool.strings;
      firstPool = false;
    } else if (type === 512) {
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
      if (e.dataType !== 3) continue;
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
  labels.sort((a, b2) => b2.score - a.score);
  icons.sort((a, b2) => b2.score - a.score);
  return {
    label: labels[0]?.value || null,
    iconPath: icons[0]?.path || null,
    debug: {
      globalStrings: global.length,
      typeChunks: types.length,
      labelCandidates: labels.slice(0, 3).map((x) => x.value),
      iconCandidates: icons.slice(0, 3).map((x) => x.path)
    }
  };
}
async function inflateRaw(bytes) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("\u6D4F\u89C8\u5668\u4E0D\u652F\u6301 deflate-raw \u89E3\u538B\uFF08\u9700\u8981 Chrome / Edge 103+\uFF09");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function unzipEntry(blob, wanted) {
  const size = blob.size;
  const tailLen = Math.min(size, 262144);
  const tail = new Uint8Array(await blob.slice(size - tailLen).arrayBuffer());
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (u3211(tail, i) === 101010256) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("APK \u91CC\u627E\u4E0D\u5230 ZIP \u7ED3\u5C3E\u8BB0\u5F55");
  const cdSize = u3211(tail, eocd + 12);
  const cdOffset = u3211(tail, eocd + 16);
  const count = u1610(tail, eocd + 10);
  const inTail = cdOffset - (size - tailLen);
  const cd = inTail >= 0 && inTail + cdSize <= tail.length ? tail.subarray(inTail, inTail + cdSize) : new Uint8Array(await blob.slice(cdOffset, cdOffset + cdSize).arrayBuffer());
  const decoder = new TextDecoder();
  let p = 0;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cd.length || u3211(cd, p) !== 33639248) break;
    const method = u1610(cd, p + 10);
    const compSize = u3211(cd, p + 20);
    const nameLen = u1610(cd, p + 28);
    const extraLen = u1610(cd, p + 30);
    const commentLen = u1610(cd, p + 32);
    const local = u3211(cd, p + 42);
    const name = decoder.decode(cd.subarray(p + 46, p + 46 + nameLen));
    if (name === wanted) {
      const head = new Uint8Array(await blob.slice(local, local + 30).arrayBuffer());
      if (u3211(head, 0) !== 67324752) throw new Error("APK \u5C40\u90E8\u6587\u4EF6\u5934\u635F\u574F");
      const start2 = local + 30 + u1610(head, 26) + u1610(head, 28);
      const data = new Uint8Array(await blob.slice(start2, start2 + compSize).arrayBuffer());
      if (method === 0) return data;
      if (method === 8) return inflateRaw(data);
      throw new Error(`APK \u6761\u76EE\u7528\u4E86\u4E0D\u652F\u6301\u7684\u538B\u7F29\u65B9\u5F0F ${method}`);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}
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
  if (bytes.length > 4e5) return null;
  return `data:${mime};base64,${bytesToBase64(bytes)}`;
}
function parseBadging(text) {
  let label = null;
  let zhLabel = null;
  let iconPath = null;
  let iconSize = -1;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    let m = line.match(/^application-label-zh(?:-CN|-TW|-HK)?:\s*'((?:[^'\\]|\\.)*)'/);
    if (m) {
      zhLabel = m[1].replace(/\\'/g, "'");
      continue;
    }
    m = line.match(/^application-label:\s*'((?:[^'\\]|\\.)*)'/);
    if (m) {
      label = m[1].replace(/\\'/g, "'");
      continue;
    }
    m = line.match(/^application-icon-(\d+):\s*'([^']+)'/);
    if (m && +m[1] > iconSize) {
      iconSize = +m[1];
      iconPath = m[2];
    }
  }
  return { label: zhLabel || label, iconPath };
}
async function probeDevice(service, log) {
  const script = "echo __AAPT__; (aapt version 2>&1 || true) | head -2; echo __UNZIP__; (unzip 2>&1 || true) | head -2; echo __B64__; (printf gjwtest | base64 2>&1 || true) | head -2; echo __DUMP__; (dumpsys package com.android.settings 2>/dev/null | grep -iE 'nonLocalizedLabel|labelRes|application-icon' | head -8); echo __END__";
  let raw = "";
  try {
    raw = await service.text(script, { log: false, allowFailure: true });
  } catch (error) {
    log(`[\u8BC6\u522B] \u80FD\u529B\u63A2\u6D4B\u5931\u8D25\uFF1A${error?.message || error}`, "err");
  }
  const section = (from, to) => {
    const start2 = raw.indexOf(`__${from}__`);
    const end = raw.indexOf(`__${to}__`, start2 + 1);
    return start2 < 0 ? "" : raw.slice(start2 + from.length + 4, end < 0 ? raw.length : end).trim();
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
    raw: raw.slice(0, 900)
  };
  log(`[\u8BC6\u522B] \u8BBE\u5907\u80FD\u529B\uFF1Aaapt=${caps.aapt || "\u65E0"} unzip=${caps.unzip || "\u65E0"} base64=${caps.base64 || "\u65E0"}`, "dim");
  log(`[\u8BC6\u522B] \u63A2\u6D4B\u539F\u59CB\u8F93\u51FA\uFF1A${caps.raw.replace(/\r?\n/g, " | ")}`, "dim");
  if (!caps.unzip || !caps.base64) log("[\u8BC6\u522B] \u5C06\u6539\u7528 ADB \u6574\u5305\u8BFB\u53D6\uFF08\u6162\u4E00\u4E9B\uFF0C\u4F46\u4E00\u5B9A\u80FD\u62FF\u5230\u8D44\u6E90\u8868\uFF09", "dim");
  return caps;
}
async function resolveAppMeta({ service, driver, pkg, caps, log = () => {
} }) {
  const paths = await service.paths(pkg);
  const apk = paths.find((p) => /base\.apk$/i.test(p)) || paths[0];
  if (!apk) throw new Error("\u6CA1\u6709\u62FF\u5230 APK \u8DEF\u5F84");
  let blob = null;
  const readEntry = async (entry) => {
    if (caps.unzip && caps.base64) {
      const cmd = `${caps.unzip} -p ${GJ.quote(apk)} ${GJ.quote(entry)} | ${caps.base64}`;
      const out = await service.text(cmd, { log: false, allowFailure: true });
      const bytes = maybeBase64Bytes(out);
      if (bytes) return bytes;
      log(`[\u8BC6\u522B] ${pkg}\uFF1A\u8BBE\u5907\u7AEF\u53D6 ${entry} \u6CA1\u62FF\u5230 base64\uFF08\u524D 80 \u5B57\uFF1A${String(out).slice(0, 80).replace(/\r?\n/g, " ")}\uFF09\uFF0C\u6539\u8D70\u6574\u5305`, "dim");
    }
    if (!blob) {
      const sizeText = await service.text(`stat -c %s ${GJ.quote(apk)} 2>/dev/null`, { log: false, allowFailure: true });
      const size = parseInt(String(sizeText).trim(), 10);
      if (Number.isFinite(size) && size > 80 * 1024 * 1024) {
        throw new Error(`APK \u6709 ${Math.round(size / 1048576)}MB\uFF0C\u6574\u5305\u6A21\u5F0F\u8DF3\u8FC7\uFF08\u8BBE\u5907\u7AEF unzip \u4E0D\u53EF\u7528\u65F6\u624D\u4F1A\u8FD9\u6837\uFF09`);
      }
      blob = await driver.read(apk);
      log(`[\u8BC6\u522B] ${pkg}\uFF1A\u6574\u5305\u8BFB\u53D6 ${blob.size} \u5B57\u8282`, "dim");
    }
    return unzipEntry(blob, entry);
  };
  if (caps.aapt) {
    try {
      const badging = await service.text(`${caps.aapt} dump badging ${GJ.quote(apk)} 2>/dev/null | head -80`, { log: false, allowFailure: true });
      const parsed = parseBadging(badging);
      if (parsed.label) {
        log(`[\u8BC6\u522B] ${pkg}\uFF1Aaapt \u76F4\u63A5\u7ED9\u51FA\u300C${parsed.label}\u300D`, "dim");
        let icon2 = null;
        if (parsed.iconPath) icon2 = iconDataUrl(await readEntry(parsed.iconPath), parsed.iconPath);
        return { label: parsed.label, iconPath: parsed.iconPath, icon: icon2, source: "aapt", debug: {} };
      }
      log(`[\u8BC6\u522B] ${pkg}\uFF1Aaapt \u6CA1\u6709\u7ED9\u51FA label\uFF0C\u6539\u89E3 resources.arsc`, "dim");
    } catch (error) {
      log(`[\u8BC6\u522B] ${pkg}\uFF1Aaapt \u5931\u8D25\uFF08${error?.message || error}\uFF09\uFF0C\u6539\u89E3 resources.arsc`, "dim");
    }
  }
  const arsc = await readEntry("resources.arsc");
  if (!arsc) throw new Error("APK \u91CC\u627E\u4E0D\u5230 resources.arsc");
  const meta = parseArsc(arsc);
  log(
    `[\u8BC6\u522B] ${pkg}\uFF1A\u8D44\u6E90\u8868 ${arsc.length} \u5B57\u8282\uFF0C\u5168\u5C40\u4E32 ${meta.debug.globalStrings}\uFF0C\u7C7B\u578B\u5757 ${meta.debug.typeChunks}\uFF0C\u540D\u79F0\u5019\u9009 ${JSON.stringify(meta.debug.labelCandidates)}\uFF0C\u56FE\u6807\u5019\u9009 ${JSON.stringify(meta.debug.iconCandidates)}`,
    "dim"
  );
  let icon = null;
  if (meta.iconPath) {
    try {
      icon = iconDataUrl(await readEntry(meta.iconPath), meta.iconPath);
    } catch (error) {
      log(`[\u8BC6\u522B] ${pkg}\uFF1A\u56FE\u6807 ${meta.iconPath} \u8BFB\u53D6\u5931\u8D25\uFF08${error?.message || error}\uFF09`, "dim");
    }
  }
  return { ...meta, icon, source: "arsc" };
}
var cache = null;
function metaCache() {
  if (!cache) {
    try {
      cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}") || {};
    } catch {
      cache = {};
    }
  }
  return cache;
}
function getCachedMeta(pkg) {
  return metaCache()[pkg] || null;
}
function saveMeta(pkg, meta) {
  const all = metaCache();
  all[pkg] = {
    label: meta.label || null,
    icon: meta.icon && meta.icon.length < 16e3 ? meta.icon : null,
    at: Date.now()
  };
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(all));
  } catch {
    for (const key of Object.keys(all)) all[key].icon = null;
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(all));
    } catch {
    }
  }
  return all[pkg];
}
function clearMetaCache() {
  cache = {};
  try {
    localStorage.removeItem(CACHE_KEY);
  } catch {
  }
}

// src/apps/index.js
var SECTIONS = [
  ["U", "pm list packages -u"],
  ["P", "pm list packages"],
  ["3", "pm list packages -3"],
  ["S", "pm list packages -s"],
  ["D", "pm list packages -d"],
  ["E", "pm list packages -e"]
];
var TYPE_LABEL = { system: "\u7CFB\u7EDF", third: "\u7B2C\u4E09\u65B9", unknown: "\u672A\u77E5" };
var STATE_LABEL = { enabled: "\u5DF2\u542F\u7528", disabled: "\u5DF2\u7981\u7528", uninstalled: "\u5DF2\u5378\u8F7D", installed: "\u5DF2\u5B89\u88C5" };
var ACTION_LABEL = {
  launch: "\u542F\u52A8",
  stop: "\u5F3A\u884C\u505C\u6B62",
  uninstall: "\u5378\u8F7D",
  restore: "\u6062\u590D",
  disable: "\u7981\u7528",
  enable: "\u542F\u7528",
  clear: "\u6E05\u9664\u6570\u636E"
};
var FILTERS = [
  ["all", "\u5168\u90E8"],
  ["third", "\u7B2C\u4E09\u65B9"],
  ["system", "\u7CFB\u7EDF"],
  ["disabled", "\u5DF2\u7981\u7528"],
  ["uninstalled", "\u5DF2\u5378\u8F7D"],
  ["selected", "\u5DF2\u52FE\u9009"]
];
function parseSections(text) {
  const sections = {};
  let current = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    const mark = line.match(/^__([A-Z0-9]+)__$/);
    if (mark) {
      current = mark[1];
      sections[current] = { names: /* @__PURE__ */ new Set(), noise: [] };
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
function parseDetail(text) {
  const raw = String(text);
  const pick = (re) => raw.match(re)?.[1]?.trim() || "\u2014";
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
    lines: raw.split(/\r?\n/).length
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
  setTimeout(() => URL.revokeObjectURL(url), 6e4);
}
function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}
function mountAppPanel({ container, getDriver, log = () => {
}, onClose = () => {
} }) {
  container.innerHTML = `
    <div class="ap-bar">
      <button class="ap-btn primary" data-act="refresh" title="\u91CD\u65B0\u8BFB\u53D6\u8BBE\u5907\u4E0A\u7684\u5E94\u7528">\u5237\u65B0\u5217\u8868</button>
      <button class="ap-btn" data-act="identify" title="\u4ECE\u5E73\u677F\u4E0A\u7684 APK \u91CC\u8BFB\u51FA\u5E94\u7528\u540D\u79F0\u548C\u684C\u9762\u56FE\u6807\uFF1B\u53EA\u5904\u7406\u5F53\u524D\u7B5B\u9009\u51FA\u6765\u7684\u3001\u8FD8\u6CA1\u8BA4\u8FC7\u7684">\u8BC6\u522B\u5E94\u7528</button>
      <button class="ap-btn" data-act="install" title="\u9009\u62E9\u4E00\u4E2A\u6216\u591A\u4E2A\u72EC\u7ACB APK \u5206\u522B\u5B89\u88C5">\u5B89\u88C5 APK</button>
      <button class="ap-btn" data-act="install-split" title="\u9009\u4E2D\u540C\u4E00\u5957 base.apk + split_config.*.apk \u4E00\u8D77\u5B89\u88C5">\u62C6\u5206\u5B89\u88C5</button>
      <button class="ap-btn" data-act="export" title="\u628A\u5F53\u524D\u5217\u8868\u5BFC\u51FA\u6210 CSV\uFF0CExcel \u53EF\u76F4\u63A5\u6253\u5F00">\u5BFC\u51FA\u6E05\u5355</button>
      <span class="ap-spacer"></span>
      <span class="ap-count" id="apCount">\u2014</span>
      <button class="ap-btn tiny ghost" data-act="clear-meta" title="\u6E05\u6389\u8BB0\u4F4F\u7684\u540D\u79F0\u548C\u56FE\u6807\uFF0C\u4E0B\u6B21\u91CD\u65B0\u8BC6\u522B">\u6E05\u7F13\u5B58</button>
      <button class="ap-btn ghost" data-act="close" title="\u5173\u95ED\uFF08Esc\uFF09">\u2715</button>
    </div>
    <div class="ap-chips" id="apChips"></div>
    <div class="ap-tools">
      <input class="ap-filter" id="apFilter" placeholder="\u641C\u7D22\u5305\u540D\uFF0CEsc \u6E05\u7A7A" spellcheck="false">
      <span class="ap-tools-label">\u6279\u91CF\uFF1A</span>
      <button class="ap-btn tiny" data-batch="uninstall">\u5378\u8F7D</button>
      <button class="ap-btn tiny" data-batch="disable">\u7981\u7528</button>
      <button class="ap-btn tiny" data-batch="enable">\u542F\u7528</button>
      <button class="ap-btn tiny" data-batch="restore">\u6062\u590D</button>
      <span class="ap-tools-sep"></span>
      <button class="ap-btn tiny ghost" data-batch="select-all">\u5168\u9009\u53EF\u89C1</button>
      <button class="ap-btn tiny ghost" data-batch="clear-sel">\u6E05\u7A7A\u52FE\u9009</button>
    </div>
    <div class="ap-head">
      <span></span><span>\u5E94\u7528</span><span>\u7C7B\u578B</span><span>\u72B6\u6001</span><span>\u64CD\u4F5C</span>
    </div>
    <div class="ap-list" id="apList"></div>
    <div class="ap-detail" id="apDetail" hidden></div>
    <div class="ap-status" id="apStatus">\u8FDE\u63A5\u8BBE\u5907\u540E\u70B9\u300C\u5237\u65B0\u5217\u8868\u300D</div>
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
    selected: /* @__PURE__ */ new Set(),
    busy: false,
    detailPkg: null,
    stats: null,
    loadToken: 0,
    identifying: false,
    stopIdentify: false,
    caps: null,
    capsDriver: null
  };
  function setStatus(text, kind = "") {
    statusEl.textContent = text;
    statusEl.className = "ap-status" + (kind ? " " + kind : "");
  }
  function setBusy(on) {
    state.busy = on;
    container.classList.toggle("busy", on);
  }
  function getService() {
    const driver = getDriver();
    if (!driver?.connected) throw new Error("\u8BBE\u5907\u672A\u8FDE\u63A5");
    const service = new GJ.Service({
      output: (kind, text) => {
        const value = String(text).trim();
        if (!value) return;
        const prefix = kind === "command" ? "$ " : kind === "stderr" ? "! " : "  ";
        log(`[\u5E94\u7528] ${prefix}${value}`, "dim");
      },
      progress: (name, done, total) => {
        const percent = total ? Math.round(done / total * 100) : 0;
        setStatus(`${name} \u2026 ${percent}%\uFF08${formatSize(done)}${total ? " / " + formatSize(total) : ""}\uFF09`);
      },
      saveFile: (blob, name) => {
        downloadBlob(blob, name);
        log(`[\u5E94\u7528] \u5DF2\u4FDD\u5B58 ${name}\uFF08${formatSize(blob.size)}\uFF09`, "ok");
      },
      history: (item) => log(`[\u5E94\u7528] \u64CD\u4F5C\u8BB0\u5F55 ${item.action} ${item.package}`, "dim"),
      getSettings: () => GJ.defaults
    });
    service.driver = driver;
    return service;
  }
  async function load({ quiet = false, force = false, keepStatus = false } = {}) {
    const driver = getDriver();
    if (!driver?.connected) {
      setStatus("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
      return;
    }
    if (state.busy && !force) return;
    const token = ++state.loadToken;
    const wasBusy = state.busy;
    setBusy(true);
    if (!quiet) setStatus("\u6B63\u5728\u8BFB\u53D6\u5E94\u7528\u5217\u8868\u2026");
    try {
      const service = getService();
      const script = SECTIONS.map(([tag, cmd]) => `echo __${tag}__; ${cmd} 2>&1`).join("; ");
      const text = await service.text(script, { log: false, allowFailure: true });
      if (token !== state.loadToken) return;
      const sections = parseSections(text);
      const get = (tag) => sections[tag]?.names || /* @__PURE__ */ new Set();
      const u = get("U");
      const p = get("P");
      const third = get("3");
      const system = get("S");
      const disabled = get("D");
      const enabled = get("E");
      log(
        `[\u5E94\u7528] \u5206\u7EC4\u7EDF\u8BA1 U(\u542B\u5DF2\u5378\u8F7D)=${u.size} P(\u5F53\u524D)=${p.size} \u7B2C\u4E09\u65B9=${third.size} \u7CFB\u7EDF=${system.size} \u7981\u7528=${disabled.size} \u542F\u7528\u8FC7\u6EE4=${enabled.size}`,
        "dim"
      );
      for (const [tag, section] of Object.entries(sections)) {
        if (section.noise.length) {
          log(`[\u5E94\u7528] ${tag} \u6BB5\u6709 ${section.noise.length} \u884C\u975E\u5305\u540D\u8F93\u51FA\uFF1A${section.noise.slice(0, 4).join(" | ")}`, "err");
        }
      }
      if (!u.size) log("[\u5E94\u7528] -u \u6BB5\u4E3A\u7A7A\uFF1A\u8FD9\u53F0\u8BBE\u5907\u53EF\u80FD\u4E0D\u652F\u6301\u5217\u51FA\u5DF2\u5378\u8F7D\u5E94\u7528\uFF0C\u300E\u5DF2\u5378\u8F7D\u300F\u5206\u7EC4\u4F1A\u662F\u7A7A\u7684", "err");
      if (!p.size) log("[\u5E94\u7528] pm list packages \u6CA1\u6709\u8FD4\u56DE\u4EFB\u4F55\u5305\u540D\uFF0C\u8BF7\u68C0\u67E5 ADB \u6743\u9650", "err");
      const all = /* @__PURE__ */ new Set([...u, ...p, ...third, ...system, ...disabled, ...enabled]);
      const rows = [];
      for (const pkg of all) {
        if (!/^[\w]+(?:\.[\w]+)+$/.test(pkg)) continue;
        const type = system.has(pkg) ? "system" : third.has(pkg) ? "third" : "unknown";
        const status = u.has(pkg) && !p.has(pkg) ? "uninstalled" : disabled.has(pkg) ? "disabled" : "enabled";
        rows.push({ pkg, short: shortName(pkg), type, status });
      }
      rows.sort((a, b) => a.pkg.localeCompare(b.pkg, "en", { numeric: true }));
      state.rows = rows;
      state.stats = { u: u.size, p: p.size, third: third.size, system: system.size, disabled: disabled.size, enabled: enabled.size };
      const known = new Set(rows.map((row) => row.pkg));
      for (const pkg of state.selected) if (!known.has(pkg)) state.selected.delete(pkg);
      if (state.detailPkg && !known.has(state.detailPkg)) closeDetail();
      render();
      const removed = rows.filter((r) => r.status === "uninstalled").length;
      const off = rows.filter((r) => r.status === "disabled").length;
      const identified = rows.filter((r) => getCachedMeta(r.pkg)?.label).length;
      if (!keepStatus) {
        setStatus(`\u5171 ${rows.length} \u4E2A\u5E94\u7528 \xB7 \u7B2C\u4E09\u65B9 ${rows.filter((r) => r.type === "third").length} \xB7 \u5DF2\u7981\u7528 ${off} \xB7 \u53EF\u6062\u590D ${removed} \xB7 \u5DF2\u8BC6\u522B ${identified}${identified ? "" : "\uFF08\u70B9\u300C\u8BC6\u522B\u5E94\u7528\u300D\u663E\u793A\u540D\u79F0\u548C\u56FE\u6807\uFF09"}`);
      }
      log(`[\u5E94\u7528] \u5217\u8868\u5DF2\u66F4\u65B0\uFF1A${rows.length} \u4E2A\uFF08\u5DF2\u7981\u7528 ${off}\uFF0C\u53EF\u6062\u590D ${removed}\uFF09`, quiet ? "dim" : "ok");
    } catch (error) {
      const message = error?.message || String(error);
      if (!keepStatus) setStatus("\u8BFB\u53D6\u5931\u8D25\uFF1A" + message, "err");
      log(`[\u5E94\u7528] \u8BFB\u53D6\u5E94\u7528\u5217\u8868\u5931\u8D25\uFF1A${message}`, "err");
    } finally {
      setBusy(wasBusy);
    }
  }
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
    const op = (action, label, cls = "") => `<button class="ap-op ${cls}" data-op="${action}" title="${label}">${label}</button>`;
    if (row.status === "uninstalled") {
      return op("restore", "\u6062\u590D", "good") + op("detail", "\u8BE6\u60C5");
    }
    const list = [];
    if (row.status === "disabled") list.push(op("enable", "\u542F\u7528", "good"));
    else list.push(op("launch", "\u542F\u52A8"), op("stop", "\u5F3A\u505C"), op("disable", "\u7981\u7528"));
    list.push(op("uninstall", "\u5378\u8F7D", "danger"), op("clear", "\u6E05\u6570\u636E", "danger"), op("extract", "\u63D0\u53D6"), op("detail", "\u8BE6\u60C5"));
    return list.join("");
  }
  function nameHtml(row) {
    const meta = getCachedMeta(row.pkg);
    const label = meta?.label || "";
    const text = label || row.short;
    const icon = meta?.icon ? `<img class="ap-ico" src="${esc(meta.icon)}" alt="" loading="lazy">` : `<span class="ap-ico-fb">${esc((text[0] || "?").toUpperCase())}</span>`;
    return `<span class="ap-name">${icon}<span class="ap-text"><span class="ap-short${label ? " cn" : ""}" title="${esc(row.pkg)}">${esc(text)}</span><span class="ap-pkg">${esc(row.pkg)}</span></span></span>`;
  }
  function updateRow(pkg) {
    const selector = window.CSS?.escape ? `.ap-row[data-pkg="${CSS.escape(pkg)}"]` : null;
    const item = selector ? listEl.querySelector(selector) : [...listEl.querySelectorAll(".ap-row")].find((el) => el.dataset.pkg === pkg);
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
    countEl.textContent = `${rows.length} / ${state.rows.length} \u6761 \xB7 \u5DF2\u52FE\u9009 ${state.selected.size}`;
    listEl.textContent = "";
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "ap-empty";
      empty.textContent = state.rows.length ? "\u6CA1\u6709\u5339\u914D\u7684\u5E94\u7528" : "\u70B9\u300C\u5237\u65B0\u5217\u8868\u300D\u8BFB\u53D6\u8BBE\u5907\u4E0A\u7684\u5E94\u7528";
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
      more.textContent = `\u53EA\u663E\u793A\u524D 800 \u6761\uFF0C\u5171 ${rows.length} \u6761\uFF1B\u7528\u641C\u7D22\u7F29\u5C0F\u8303\u56F4`;
      listEl.appendChild(more);
    }
  }
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
    const title = label ? `${label} \xB7 ${pkg}` : pkg;
    detailEl.hidden = false;
    detailEl.innerHTML = `<div class="ap-detail-head"><b>${esc(title)}</b><button class="ap-op" data-d="close">\u5173\u95ED</button></div><div class="ap-detail-body">\u8BFB\u53D6\u4E2D\u2026</div>`;
    render();
    try {
      const service = getService();
      const [raw, pathText] = await Promise.all([
        service.text(`dumpsys package ${GJ.quote(pkg)}`, { log: false, allowFailure: true }),
        service.text(`pm path ${GJ.quote(pkg)}`, { log: false, allowFailure: true })
      ]);
      if (state.detailPkg !== pkg) return;
      const info = parseDetail(raw);
      const paths = String(pathText).split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("package:")).map((line) => line.slice(8).trim());
      log(`[\u5E94\u7528] \u8BE6\u60C5 ${pkg}\uFF1Adumpsys ${info.lines} \u884C\uFF0CAPK ${paths.length} \u4E2A\uFF0C\u5DF2\u6388\u6743\u9650 ${info.permissions.length} \u6761`, "dim");
      const kv = (label2, value) => `<div class="ap-kv"><span>${label2}</span><code>${esc(value)}</code></div>`;
      detailEl.innerHTML = `
        <div class="ap-detail-head"><b>${esc(title)}</b><span class="ap-detail-meta">${TYPE_LABEL[row?.type] || "\u672A\u77E5"} \xB7 ${STATE_LABEL[row?.status] || "\u2014"}</span><button class="ap-op" data-d="close">\u5173\u95ED</button></div>
        <div class="ap-detail-body">
          <div class="ap-kv-grid">
            ${kv("\u7248\u672C\u53F7", info.versionName)}
            ${kv("\u7248\u672C\u7801", info.versionCode)}
            ${kv("targetSdk", info.targetSdk)}
            ${kv("\u5B89\u88C5\u6765\u6E90", info.installer)}
            ${kv("\u9996\u6B21\u5B89\u88C5", info.firstInstall)}
            ${kv("\u6700\u540E\u66F4\u65B0", info.lastUpdate)}
          </div>
          <div class="ap-detail-sec">\u5B89\u88C5\u5305\u8DEF\u5F84\uFF08${paths.length} \u4E2A\uFF09</div>
          <div class="ap-paths">${paths.length ? paths.map((p) => `<code>${esc(p)}</code>`).join("") : "<code>\u8BE5\u5E94\u7528\u5F53\u524D\u6CA1\u6709\u5B89\u88C5\u8DEF\u5F84\uFF08\u53EF\u80FD\u5DF2\u88AB\u5378\u8F7D\uFF09</code>"}</div>
          <div class="ap-detail-sec">\u5DF2\u6388\u4E88\u6743\u9650\uFF08${info.permissions.length} \u6761\uFF09</div>
          <div class="ap-perms">${info.permissions.length ? info.permissions.slice(0, 40).map((p) => `<code>${esc(p)}</code>`).join("") : "<code>\u6CA1\u6709\u8BFB\u5230\u6743\u9650\u5217\u8868</code>"}${info.permissions.length > 40 ? `<code>\u2026 \u53E6\u6709 ${info.permissions.length - 40} \u6761</code>` : ""}</div>
        </div>
      `;
    } catch (error) {
      if (state.detailPkg !== pkg) return;
      detailEl.querySelector(".ap-detail-body").textContent = "\u8BFB\u53D6\u5931\u8D25\uFF1A" + (error?.message || error);
      log(`[\u5E94\u7528] \u8BFB\u53D6 ${pkg} \u8BE6\u60C5\u5931\u8D25\uFF1A${error?.message || error}`, "err");
    }
  }
  async function runOne(action, pkg, { quiet = false } = {}) {
    const label = ACTION_LABEL[action] || action;
    try {
      const service = getService();
      const out = await service.packageAction(action, pkg);
      const text = String(out || "").trim();
      if (action === "launch" && /No activities found|monkey aborted|Error/i.test(text)) {
        log(`[\u5E94\u7528] ${label} ${pkg}\uFF1A\u6CA1\u627E\u5230\u684C\u9762\u542F\u52A8\u5165\u53E3\uFF08${text.slice(0, 120)}\uFF09`, "err");
        if (!quiet) setStatus(`${label} ${pkg} \u5931\u8D25\uFF1A\u6CA1\u6709\u684C\u9762\u542F\u52A8\u5165\u53E3`, "err");
        return false;
      }
      log(`[\u5E94\u7528] ${label} ${pkg} \u6210\u529F${text ? `\uFF1A${text.slice(0, 120)}` : ""}`, quiet ? "dim" : "ok");
      return true;
    } catch (error) {
      const message = String(error?.message || error).trim();
      log(`[\u5E94\u7528] ${label} ${pkg} \u5931\u8D25\uFF1A${message.slice(0, 300)}`, "err");
      if (!quiet) setStatus(`${label} ${pkg} \u5931\u8D25\uFF1A${message.slice(0, 200)}`, "err");
      return false;
    }
  }
  const WARN = {
    uninstall: "\u7CFB\u7EDF\u5E94\u7528\u4F1A\u6309\u4E3B\u9875\u7684\u6210\u719F\u505A\u6CD5\u300C\u4FDD\u7559\u6570\u636E\u5378\u8F7D\u300D\uFF0C\u4E4B\u540E\u53EF\u4EE5\u5728\u300C\u5DF2\u5378\u8F7D\u300D\u91CC\u6062\u590D\u3002",
    disable: "\u7981\u7528\u540E\u5E94\u7528\u4F1A\u4ECE\u684C\u9762\u6D88\u5931\uFF0C\u4F46\u6570\u636E\u8FD8\u5728\uFF0C\u968F\u65F6\u53EF\u4EE5\u518D\u542F\u7528\u3002",
    enable: "\u4F1A\u628A\u9009\u4E2D\u7684\u5E94\u7528\u91CD\u65B0\u542F\u7528\u3002",
    restore: "\u53EA\u5BF9\u5DF2\u7ECF\u5378\u8F7D\u3001\u8FD8\u80FD\u627E\u56DE\u6765\u7684\u7CFB\u7EDF\u5E94\u7528\u6709\u6548\uFF1B\u7B2C\u4E09\u65B9\u5E94\u7528\u5378\u8F7D\u540E\u6CA1\u6CD5\u7528\u8FD9\u4E2A\u6062\u590D\u3002"
  };
  async function runBatch(action) {
    if (state.busy) return setStatus("\u4E0A\u4E00\u4E2A\u64CD\u4F5C\u8FD8\u6CA1\u7ED3\u675F", "err");
    if (blockedByIdentify("\u505A\u8FD9\u4E2A\u64CD\u4F5C")) return;
    const targets = visibleRows().filter((row) => state.selected.has(row.pkg));
    const label = ACTION_LABEL[action];
    if (!targets.length) return setStatus(`\u5148\u52FE\u9009\u8981${label}\u7684\u5E94\u7528`, "err");
    const usable = targets.filter((row) => {
      if (action === "restore") return row.status === "uninstalled";
      if (action === "enable") return row.status === "disabled";
      if (action === "disable") return row.status === "enabled";
      return row.status !== "uninstalled";
    });
    const skipped = targets.length - usable.length;
    if (!usable.length) return setStatus(`\u52FE\u9009\u7684\u5E94\u7528\u90FD\u4E0D\u9700\u8981\u300C${label}\u300D\uFF08\u72B6\u6001\u4E0D\u5339\u914D\uFF09`, "err");
    const preview = usable.slice(0, 8).map((row) => `  \xB7 ${row.pkg}`).join("\n");
    const more = usable.length > 8 ? `
  \u2026 \u8FD8\u6709 ${usable.length - 8} \u4E2A` : "";
    const hint = `

${WARN[action] || ""}${skipped ? `

\u53E6\u6709 ${skipped} \u4E2A\u72B6\u6001\u4E0D\u5339\u914D\uFF0C\u4F1A\u81EA\u52A8\u8DF3\u8FC7\u3002` : ""}`;
    if (!window.confirm(`\u786E\u5B9A\u5BF9 ${usable.length} \u4E2A\u5E94\u7528\u6267\u884C\u300C${label}\u300D\u5417\uFF1F
${preview}${more}${hint}`)) return;
    setBusy(true);
    let ok = 0;
    let fail = 0;
    try {
      for (let i = 0; i < usable.length; i += 1) {
        const pkg = usable[i].pkg;
        setStatus(`(${i + 1}/${usable.length}) ${label} ${pkg} \u2026`);
        if (await runOne(action, pkg, { quiet: true })) ok += 1;
        else fail += 1;
      }
      setStatus(`${label}\u5B8C\u6210\uFF1A\u6210\u529F ${ok} / \u5931\u8D25 ${fail} / \u5171 ${usable.length}${skipped ? `\uFF0C\u8DF3\u8FC7 ${skipped}` : ""}`, fail ? "err" : "");
      log(`[\u5E94\u7528] \u6279\u91CF${label}\u7ED3\u675F\uFF1A\u6210\u529F ${ok}\uFF0C\u5931\u8D25 ${fail}`, fail ? "err" : "ok");
      state.selected.clear();
      await load({ quiet: true, force: true, keepStatus: true });
    } finally {
      setBusy(false);
    }
  }
  async function singleOp(action, pkg) {
    if (state.busy) return setStatus("\u4E0A\u4E00\u4E2A\u64CD\u4F5C\u8FD8\u6CA1\u7ED3\u675F", "err");
    if (blockedByIdentify("\u505A\u8FD9\u4E2A\u64CD\u4F5C")) return;
    const label = ACTION_LABEL[action] || "\u64CD\u4F5C";
    if (action === "clear") {
      if (!window.confirm(`\u786E\u5B9A\u6E05\u9664\u300C${pkg}\u300D\u7684\u5168\u90E8\u6570\u636E\u5417\uFF1F

\u4F1A\u5220\u6389\u767B\u5F55\u72B6\u6001\u3001\u8BBE\u7F6E\u548C\u672C\u5730\u6587\u4EF6\uFF0C\u4E0D\u80FD\u6062\u590D\u3002
\u53EA\u6E05\u7F13\u5B58\u7684\u8BDD\uFF0C\u5B89\u5353\u6CA1\u6709\u7ED9 ADB \u5F00\u653E\u5355\u5E94\u7528\u6E05\u7F13\u5B58\u7684\u63A5\u53E3\uFF0C\u8FD9\u91CC\u6E05\u7684\u662F\u5B8C\u6574\u6570\u636E\u3002`)) return;
    } else if (action === "uninstall") {
      if (!window.confirm(`\u786E\u5B9A\u5378\u8F7D\u300C${pkg}\u300D\u5417\uFF1F

\u7CFB\u7EDF\u5E94\u7528\u4F1A\u4FDD\u7559\u6570\u636E\u5378\u8F7D\uFF0C\u4E4B\u540E\u53EF\u4EE5\u5728\u300C\u5DF2\u5378\u8F7D\u300D\u5206\u7EC4\u91CC\u70B9\u300C\u6062\u590D\u300D\u627E\u56DE\u6765\u3002`)) return;
    }
    setBusy(true);
    try {
      setStatus(`\u6B63\u5728${label} ${pkg} \u2026`);
      const ok = await runOne(action, pkg);
      if (ok) {
        setStatus(`${label} ${pkg} \u5B8C\u6210`);
        await load({ quiet: true, force: true, keepStatus: true });
      }
    } finally {
      setBusy(false);
    }
  }
  async function extractOne(pkg) {
    if (state.busy) return setStatus("\u4E0A\u4E00\u4E2A\u64CD\u4F5C\u8FD8\u6CA1\u7ED3\u675F", "err");
    if (blockedByIdentify("\u505A\u8FD9\u4E2A\u64CD\u4F5C")) return;
    setBusy(true);
    try {
      setStatus(`\u6B63\u5728\u63D0\u53D6 ${pkg} \u7684\u5B89\u88C5\u5305\u2026`);
      const service = getService();
      const blob = await service.extract(pkg);
      setStatus(`\u5DF2\u63D0\u53D6 ${pkg}\uFF08${formatSize(blob.size)}\uFF09`);
    } catch (error) {
      const message = String(error?.message || error).trim();
      setStatus(`\u63D0\u53D6 ${pkg} \u5931\u8D25\uFF1A${message.slice(0, 200)}`, "err");
      log(`[\u5E94\u7528] \u63D0\u53D6 ${pkg} \u5931\u8D25\uFF1A${message.slice(0, 300)}`, "err");
    } finally {
      setBusy(false);
    }
  }
  async function installFiles(files, split) {
    if (!files.length) return;
    if (state.busy) return setStatus("\u4E0A\u4E00\u4E2A\u64CD\u4F5C\u8FD8\u6CA1\u7ED3\u675F", "err");
    if (blockedByIdentify("\u505A\u8FD9\u4E2A\u64CD\u4F5C")) return;
    for (const file of files) {
      if (!/\.apk$/i.test(file.name)) {
        setStatus(`${file.name} \u4E0D\u662F APK \u6587\u4EF6`, "err");
        return;
      }
    }
    setBusy(true);
    try {
      setStatus(`\u6B63\u5728\u5B89\u88C5 ${files.length} \u4E2A APK\uFF08${split ? "\u62C6\u5206\u4F1A\u8BDD" : "\u9010\u4E2A\u5B89\u88C5"}\uFF09\u2026`);
      const service = getService();
      const results = await service.install(files, { split });
      const ok = results.filter((item) => item.success).length;
      const fail = results.length - ok;
      for (const item of results) {
        log(`[\u5E94\u7528] \u5B89\u88C5 ${item.name}\uFF1A${item.success ? "\u6210\u529F" : `\u5931\u8D25 ${String(item.output || "").slice(0, 200)}`}`, item.success ? "ok" : "err");
      }
      setStatus(`\u5B89\u88C5\u5B8C\u6210\uFF1A\u6210\u529F ${ok} / \u5931\u8D25 ${fail}`, fail ? "err" : "");
      await load({ quiet: true, force: true, keepStatus: true });
    } catch (error) {
      const message = String(error?.message || error).trim();
      setStatus("\u5B89\u88C5\u5931\u8D25\uFF1A" + message.slice(0, 200), "err");
      log(`[\u5E94\u7528] \u5B89\u88C5\u5931\u8D25\uFF1A${message.slice(0, 300)}`, "err");
    } finally {
      setBusy(false);
    }
  }
  function exportCsv() {
    const rows = state.selected.size ? state.rows.filter((row) => state.selected.has(row.pkg)) : visibleRows();
    if (!rows.length) return setStatus("\u6CA1\u6709\u53EF\u5BFC\u51FA\u7684\u5E94\u7528", "err");
    const header = ["\u5305\u540D", "\u5E94\u7528\u540D\u79F0", "\u77ED\u540D", "\u7C7B\u578B", "\u72B6\u6001", "\u5BFC\u51FA\u65F6\u95F4"].map(csvCell).join(",");
    const now = (/* @__PURE__ */ new Date()).toLocaleString("zh-CN");
    const lines = rows.map(
      (row) => [row.pkg, getCachedMeta(row.pkg)?.label || "", row.short, TYPE_LABEL[row.type], STATE_LABEL[row.status], now].map(csvCell).join(",")
    );
    const csv = "\uFEFF" + [header, ...lines].join("\r\n") + "\r\n";
    const name = `\u5E94\u7528\u6E05\u5355_${GJ.timestamp()}.csv`;
    downloadBlob(new Blob([csv], { type: "text/csv;charset=utf-8" }), name);
    setStatus(`\u5DF2\u5BFC\u51FA ${rows.length} \u6761\u5230 ${name}${state.selected.size ? "\uFF08\u4EC5\u52FE\u9009\uFF09" : "\uFF08\u5F53\u524D\u7B5B\u9009\uFF09"}`);
    log(`[\u5E94\u7528] \u5BFC\u51FA\u6E05\u5355 ${name}\uFF08${rows.length} \u6761\uFF09`, "ok");
  }
  function blockedByIdentify(what) {
    if (!state.identifying) return false;
    setStatus(`\u6B63\u5728\u8BC6\u522B\u5E94\u7528\uFF0C\u5148\u70B9\u300C\u505C\u6B62\u8BC6\u522B\u300D\u518D${what}`, "err");
    return true;
  }
  async function identify() {
    if (state.identifying) {
      state.stopIdentify = true;
      setStatus("\u6B63\u5728\u505C\u6B62\uFF0C\u7B49\u624B\u5934\u8FD9\u4E24\u4E2A\u8DD1\u5B8C\u2026");
      return;
    }
    if (state.busy) return setStatus("\u5148\u7B49\u5F53\u524D\u64CD\u4F5C\u7ED3\u675F", "err");
    const driver = getDriver();
    if (!driver?.connected) return setStatus("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
    const candidates = visibleRows().filter((row) => {
      if (row.status === "uninstalled") return false;
      const meta = getCachedMeta(row.pkg);
      return !(meta?.label || meta?.icon);
    });
    if (!candidates.length) {
      setStatus("\u5F53\u524D\u7B5B\u9009\u91CC\u7684\u5E94\u7528\u90FD\u8BA4\u8FC7\u4E86\uFF1B\u60F3\u91CD\u65B0\u8BFB\u4E00\u904D\u5148\u70B9\u300C\u6E05\u7F13\u5B58\u300D");
      return;
    }
    state.identifying = true;
    state.stopIdentify = false;
    identifyBtn.textContent = "\u505C\u6B62\u8BC6\u522B";
    const queue = [...candidates];
    const total = queue.length;
    let done = 0;
    let ok = 0;
    let fail = 0;
    try {
      if (!state.caps || state.capsDriver !== driver) {
        setStatus("\u6B63\u5728\u63A2\u6D4B\u5E73\u677F\u4E0A\u53EF\u7528\u7684\u547D\u4EE4\u2026");
        state.caps = await probeDevice(getService(), log);
        state.capsDriver = driver;
      }
      if (!state.caps.unzip || !state.caps.base64) {
        log("[\u8BC6\u522B] \u5E73\u677F\u6CA1\u6709\u53EF\u7528\u7684 unzip/base64\uFF0C\u6539\u8D70\u6574\u5305\u8BFB\u53D6\uFF0C\u4F1A\u6162\u4E0D\u5C11\uFF1B\u968F\u65F6\u53EF\u4EE5\u70B9\u300C\u505C\u6B62\u8BC6\u522B\u300D", "err");
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
            if (!meta.label && !meta.icon) log(`[\u8BC6\u522B] ${row.pkg}\uFF1A\u540D\u79F0\u548C\u56FE\u6807\u90FD\u6CA1\u53D6\u5230`, "dim");
          } catch (error) {
            fail += 1;
            log(`[\u8BC6\u522B] ${row.pkg} \u5931\u8D25\uFF1A${String(error?.message || error).slice(0, 180)}`, "dim");
          }
          done += 1;
          if (done % 5 === 0 || done === total || state.stopIdentify) {
            setStatus(`\u8BC6\u522B\u4E2D ${done}/${total} \xB7 \u6210\u529F ${ok} \xB7 \u5931\u8D25 ${fail}\uFF08\u518D\u70B9\u4E00\u6B21\u53EF\u505C\u6B62\uFF09`);
          }
        }
      };
      await Promise.all([worker(), worker()]);
      const stopped = state.stopIdentify;
      setStatus(
        `\u8BC6\u522B${stopped ? "\u5DF2\u505C\u6B62" : "\u5B8C\u6210"}\uFF1A\u6210\u529F ${ok} / \u5931\u8D25 ${fail} / \u8BA1\u5212 ${total}` + (stopped ? `\uFF0C\u8FD8\u6709 ${queue.length} \u4E2A\u6CA1\u8DD1` : ""),
        fail ? "err" : ""
      );
      const source = state.caps.aapt ? "aapt" : state.caps.unzip && state.caps.base64 ? "unzip+base64" : "ADB \u6574\u5305";
      log(`[\u8BC6\u522B] ${stopped ? "\u4E2D\u9014\u505C\u6B62" : "\u5B8C\u6210"}\uFF1A\u6210\u529F ${ok}\uFF0C\u5931\u8D25 ${fail}\uFF0C\u5171 ${total}\uFF0C\u53D6\u6570\u65B9\u5F0F ${source}`, fail ? "err" : "ok");
    } catch (error) {
      setStatus("\u8BC6\u522B\u4E2D\u65AD\uFF1A" + (error?.message || error), "err");
      log(`[\u8BC6\u522B] \u4E2D\u65AD\uFF1A${error?.message || error}`, "err");
    } finally {
      state.identifying = false;
      state.stopIdentify = false;
      identifyBtn.textContent = "\u8BC6\u522B\u5E94\u7528";
    }
  }
  container.querySelector(".ap-bar").addEventListener("click", (event) => {
    const act = event.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    if (act === "close") onClose();
    else if (act === "refresh") load();
    else if (act === "identify") identify();
    else if (act === "clear-meta") {
      if (blockedByIdentify("\u6E05\u7F13\u5B58")) return;
      clearMetaCache();
      render();
      setStatus("\u5DF2\u6E05\u6389\u8BB0\u4F4F\u7684\u540D\u79F0\u548C\u56FE\u6807\uFF0C\u70B9\u300C\u8BC6\u522B\u5E94\u7528\u300D\u53EF\u91CD\u65B0\u8BFB\u53D6");
      log("[\u5E94\u7528] \u5DF2\u6E05\u7A7A\u5E94\u7528\u540D\u79F0/\u56FE\u6807\u7F13\u5B58", "dim");
    } else if (act === "export") exportCsv();
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
    countEl.textContent = `${visibleRows().length} / ${state.rows.length} \u6761 \xB7 \u5DF2\u52FE\u9009 ${state.selected.size}`;
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
    }
  };
}

// js/core/terminal.js
var GJTerminal = /* @__PURE__ */ (() => {
  class Controller {
    constructor({ element, onState = () => {
    }, onError = () => {
    } }) {
      this.element = element;
      this.onState = onState;
      this.onError = onError;
      this.generation = 0;
      this.pending = [];
      this.starting = false;
    }
    get active() {
      return !!this.session;
    }
    ensure() {
      if (this.term) return;
      this.term = new globalThis.Terminal({ cursorBlink: true, fontSize: 14, fontFamily: 'ui-monospace, "Cascadia Mono", Consolas, monospace', lineHeight: 1.2, scrollback: 5e3, allowProposedApi: false, disableStdin: true, theme: { background: "#111e27", foreground: "#deebf0", cursor: "#deebf0", selectionBackground: "#4657be88" } });
      this.fitAddon = new globalThis.FitAddon.FitAddon();
      this.term.loadAddon(this.fitAddon);
      this.term.open(this.element);
      this.term.textarea.setAttribute("aria-label", "Android Shell \u7EC8\u7AEF");
      this.term.onData((data) => this.send(data));
      this.term.onBinary((data) => this.send(Uint8Array.from(data, (c) => c.charCodeAt(0))));
      this.term.onResize(({ rows, cols }) => {
        clearTimeout(this.resizeTimer);
        const s = this.session;
        this.resizeTimer = setTimeout(() => {
          if (s && this.session === s && s.pty.resize) Promise.resolve(s.pty.resize(rows, cols)).catch((error) => this.fail(s, error));
        }, 80);
      });
      this.term.attachCustomKeyEventHandler((event) => {
        if (event.type === "keydown" && event.ctrlKey && (event.code === "KeyC" || event.key?.toLowerCase() === "c")) {
          event.preventDefault();
          if (event.shiftKey) navigator.clipboard.writeText(this.text()).catch(this.onError);
          else this.interrupt();
          return false;
        }
        return true;
      });
      this.observer = new ResizeObserver(() => this.fit());
      this.observer.observe(this.element);
      for (const [kind, text] of this.pending) this.activity(kind, text);
      this.pending = [];
    }
    fit() {
      if (!this.term || !this.element.clientWidth || !this.element.clientHeight) return;
      this.fitAddon.fit();
    }
    focus() {
      this.term?.focus();
    }
    activity(kind, text) {
      if (this.active || this.starting) return;
      if (!this.term) {
        this.pending.push([kind, text]);
        if (this.pending.length > 1500) this.pending.shift();
        return;
      }
      const color = kind === "command" ? "\x1B[36m" : kind === "stderr" ? "\x1B[31m" : "\x1B[0m";
      this.term.write(color + String(text).replace(/\r?\n/g, "\r\n") + "\x1B[0m\r\n");
    }
    clear() {
      this.pending = [];
      this.term?.clear();
    }
    text() {
      if (!this.term) return this.pending.map(([, text]) => text).join("\n");
      if (this.term.hasSelection()) return this.term.getSelection();
      const lines = [], buffer7 = this.term.buffer.active;
      for (let i = 0; i < buffer7.length; i++) lines.push(buffer7.getLine(i)?.translateToString(true) || "");
      return lines.join("\n").trimEnd();
    }
    async open(driver) {
      this.ensure();
      this.fit();
      if (this.driver === driver && this.active) {
        this.focus();
        return;
      }
      if (this.driver === driver && this.starting) return this.opening;
      this.close();
      this.driver = driver;
      this.starting = true;
      const generation = this.generation;
      this.onState("\u6B63\u5728\u8FDE\u63A5\u7EC8\u7AEF\u2026");
      this.opening = (async () => {
        let pty;
        try {
          pty = await driver.openTerminal();
          if (generation !== this.generation || !driver.connected) {
            await pty.kill();
            return;
          }
          const s = { pty, writer: pty.input.getWriter(), reader: pty.output.getReader(), queue: Promise.resolve(), closed: false };
          this.session = s;
          const exited = Promise.resolve(pty.exited).then((code) => ({ code }), (error) => ({ error }));
          s.pump = (async () => {
            let failure;
            try {
              while (true) {
                const { value, done } = await s.reader.read();
                if (done) break;
                await new Promise((resolve) => this.term.write(value, resolve));
              }
              const result = await exited;
              if (result.error) throw result.error;
              s.exitCode = result.code;
            } catch (error) {
              failure = error;
            } finally {
              s.reader.releaseLock();
              try {
                s.writer.releaseLock();
              } catch {
              }
              if (this.session === s) {
                this.session = null;
                this.term.options.disableStdin = true;
                this.onState(failure ? "\u7EC8\u7AEF\u8FDE\u63A5\u5DF2\u5173\u95ED" : `\u4F1A\u8BDD\u5DF2\u7ED3\u675F${s.exitCode === void 0 ? "" : "\uFF08\u9000\u51FA\u7801 " + s.exitCode + "\uFF09"}\uFF0C\u53EF\u91CD\u5F00\u4F1A\u8BDD`);
                if (failure && !s.closed && driver.connected) this.onError(failure);
              }
            }
          })();
          if (pty.resize) await pty.resize(this.term.rows, this.term.cols);
          if (this.session === s) {
            this.term.options.disableStdin = false;
            this.onState("Android shell");
            this.focus();
          }
        } catch (error) {
          if (generation === this.generation) {
            this.close();
            this.onState("\u7EC8\u7AEF\u8FDE\u63A5\u5931\u8D25\uFF0C\u53EF\u91CD\u5F00\u4F1A\u8BDD");
            throw error;
          } else if (pty) await Promise.resolve(pty.kill()).catch(() => {
          });
        } finally {
          if (generation === this.generation) {
            this.starting = false;
            this.onState();
          }
        }
      })();
      return this.opening;
    }
    send(data) {
      const s = this.session;
      if (!s || s.closed) return;
      const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
      s.queue = s.queue.then(() => {
        if (this.session === s && !s.closed) return s.writer.write(bytes);
      }).catch((error) => this.fail(s, error));
    }
    interrupt() {
      this.send("");
      this.focus();
    }
    fail(s, error) {
      if (this.session !== s || s.closed) return;
      this.close();
      this.onState("\u7EC8\u7AEF\u8FDE\u63A5\u5DF2\u5173\u95ED\uFF0C\u53EF\u91CD\u5F00\u4F1A\u8BDD");
      this.onError(error);
    }
    close() {
      this.generation++;
      clearTimeout(this.resizeTimer);
      this.starting = false;
      this.driver = null;
      const s = this.session;
      this.session = null;
      if (s) {
        s.closed = true;
        Promise.resolve(s.pty.kill()).catch(() => {
        });
      }
      if (this.term) this.term.options.disableStdin = true;
      this.onState("\u7EC8\u7AEF\u672A\u8FDE\u63A5");
    }
    dispose() {
      this.close();
      this.observer?.disconnect();
      this.term?.dispose();
    }
  }
  return { Controller };
})();

// src/terminal/index.js
var HISTORY_KEY = "relive.termHistory";
var HISTORY_MAX = 60;
var PRESETS = [
  ["\u673A\u578B", "getprop ro.product.model"],
  ["\u5B89\u5353\u7248\u672C", "getprop ro.build.version.release"],
  ["\u7B2C\u4E09\u65B9\u5E94\u7528", "pm list packages -3"],
  ["\u7CFB\u7EDF\u5E94\u7528", "pm list packages -s"],
  ["\u7535\u91CF", "dumpsys battery"],
  ["\u5B58\u50A8", "df -h /sdcard"],
  ["\u5206\u8FA8\u7387", "wm size"],
  ["\u5F53\u524D\u754C\u9762", "dumpsys window | grep mCurrentFocus"],
  ["\u6700\u8FD1\u65E5\u5FD7", "logcat -d -t 200"]
];
var esc2 = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
function loadHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(value) ? value.filter((x) => typeof x === "string").slice(-HISTORY_MAX) : [];
  } catch {
    return [];
  }
}
function mountTerminalPanel({ container, getDriver, log = () => {
}, onClose = () => {
} }) {
  container.innerHTML = `
    <div class="tm-bar">
      <span class="tm-title">ADB \u7EC8\u7AEF</span>
      <span class="tm-state" id="tmState">\u7EC8\u7AEF\u672A\u8FDE\u63A5</span>
      <span class="tm-spacer"></span>
      <button class="tm-btn" data-act="copy" title="\u590D\u5236\u7EC8\u7AEF\u91CC\u7684\u6587\u5B57\uFF08\u6709\u9009\u4E2D\u5185\u5BB9\u65F6\u53EA\u590D\u5236\u9009\u4E2D\u90E8\u5206\uFF09">\u590D\u5236</button>
      <button class="tm-btn" data-act="clear" title="\u6E05\u7A7A\u5C4F\u5E55\u663E\u793A\uFF0C\u4E0D\u5F71\u54CD\u8BBE\u5907\u4E0A\u7684\u8FDB\u7A0B">\u6E05\u5C4F</button>
      <button class="tm-btn" data-act="interrupt" id="tmInterrupt" disabled title="\u53D1\u9001 Ctrl+C \u4E2D\u65AD\u5F53\u524D\u547D\u4EE4">\u4E2D\u65AD</button>
      <button class="tm-btn" data-act="restart" id="tmRestart" disabled title="\u7ED3\u675F\u5F53\u524D\u4F1A\u8BDD\uFF0C\u91CD\u65B0\u5F00\u4E00\u4E2A shell">\u91CD\u5F00\u4F1A\u8BDD</button>
      <button class="tm-btn ghost" data-act="close" title="\u5173\u95ED\u9762\u677F\uFF08Esc \u7559\u7ED9\u7EC8\u7AEF\u4F7F\u7528\uFF09">\u2715 \u5173\u95ED</button>
    </div>
    <div class="tm-presets">
      <span class="tm-label">\u5E38\u7528\u547D\u4EE4</span>
      ${PRESETS.map(([name, cmd], i) => `<button class="tm-chip" data-preset="${i}" title="${esc2(cmd)}">${esc2(name)}</button>`).join("")}
    </div>
    <div class="tm-screen" id="tmOutput"></div>
    <div class="tm-input">
      <span class="tm-prompt">$</span>
      <input id="tmCmd" placeholder="\u8F93\u5165 shell \u547D\u4EE4\uFF0C\u56DE\u8F66\u6267\u884C\uFF1B\u2191\u2193 \u7FFB\u5386\u53F2" autocomplete="off" spellcheck="false">
      <button class="tm-btn primary" data-act="run">\u6267\u884C</button>
    </div>
    <div class="tm-foot">
      <span>\u547D\u4EE4\u76F4\u63A5\u8DD1\u5728\u8BBE\u5907\u4E0A\uFF0C\u5220\u9664 / \u5237\u5199\u7C7B\u64CD\u4F5C\u8BF7\u5148\u786E\u8BA4\uFF1BCtrl+C \u4E2D\u65AD\uFF0CCtrl+Shift+C \u590D\u5236</span>
      <span>\u2191\u2193 \u7FFB\u5386\u53F2 \xB7 Esc \u7559\u7ED9\u7EC8\u7AEF\uFF0C\u70B9\u300C\u2715 \u5173\u95ED\u300D\u9000\u51FA</span>
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
    }
  }
  const controller = new GJTerminal.Controller({
    element: container.querySelector("#tmOutput"),
    onState: (message) => {
      if (message !== void 0) {
        const kind = /失败|关闭|结束|出错/.test(message) ? "err" : message === "Android shell" ? "ok" : "";
        setState(message, kind);
      }
      interruptBtn.disabled = !controller.active;
      restartBtn.disabled = !getDriver()?.connected;
    },
    onError: (error) => {
      const message = error?.message || String(error);
      setState("\u7EC8\u7AEF\u51FA\u9519\uFF1A" + message, "err");
      log("[\u7EC8\u7AEF] \u4F1A\u8BDD\u5F02\u5E38\uFF1A" + message, "err");
    }
  });
  async function ensureSession() {
    const driver = getDriver();
    if (!driver?.connected) {
      setState("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
      return false;
    }
    if (controller.active) return true;
    if (opening) return opening;
    if (!globalThis.Terminal || !globalThis.FitAddon?.FitAddon) {
      const message = "xterm.js / addon-fit.js \u672A\u52A0\u8F7D\uFF0C\u8BF7\u68C0\u67E5 index.html \u7684\u811A\u672C\u5F15\u7528";
      setState("\u7EC8\u7AEF\u7EC4\u4EF6\u672A\u52A0\u8F7D", "err");
      log("[\u7EC8\u7AEF] " + message, "err");
      return false;
    }
    opening = (async () => {
      try {
        setState("\u6B63\u5728\u8FDE\u63A5\u7EC8\u7AEF\u2026");
        await controller.open(driver);
        log("[\u7EC8\u7AEF] \u5DF2\u6253\u5F00\u8BBE\u5907 shell \u4F1A\u8BDD", "dim");
        return true;
      } catch (error) {
        const message = error?.message || String(error);
        setState("\u8FDE\u63A5\u5931\u8D25\uFF1A" + message, "err");
        log("[\u7EC8\u7AEF] \u6253\u5F00 shell \u5931\u8D25\uFF1A" + message, "err");
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
    if (!await ensureSession()) return;
    controller.send(command + "\r");
    log("[\u7EC8\u7AEF] $ " + command, "dim");
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
          setState("\u5DF2\u590D\u5236\u7EC8\u7AEF\u5185\u5BB9", "ok");
          setTimeout(() => {
            if (controller.active) setState("Android shell", "ok");
          }, 1800);
        } catch (error) {
          setState("\u590D\u5236\u5931\u8D25\uFF1A" + (error?.message || error), "err");
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
      controller.fit();
    },
    /** 设备断开 / 页面关闭时调用，真正结束 pty */
    shutdown() {
      controller.close();
      setState("\u7EC8\u7AEF\u672A\u8FDE\u63A5");
    },
    /** Esc 不关本面板，交回终端自己处理 */
    onEscape() {
      return true;
    }
  };
}

// src/desktop/index.js
var STORE_KEY = "relive.desktop.v1";
function clamp2(value, lo, hi) {
  return Math.max(lo, Math.min(hi, value));
}
function createDesktop({ layer, taskbar, tools = [], log = () => {
} }) {
  const byId = new Map(tools.map((tool) => [tool.id, tool]));
  const wins = /* @__PURE__ */ new Map();
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
  const trayAudio = document.createElement("button");
  trayAudio.id = "trayAudio";
  trayAudio.hidden = true;
  trayAudio.textContent = "\u{1F50A}";
  trayAudio.title = "\u58F0\u97F3";
  trayAudio.style.cssText = "background:transparent;border:none;color:inherit;cursor:pointer;font-size:14px;padding:0 6px;line-height:1;";
  const trayAudioVol = document.createElement("input");
  trayAudioVol.type = "range";
  trayAudioVol.id = "trayAudioVol";
  trayAudioVol.min = "0";
  trayAudioVol.max = "1";
  trayAudioVol.step = "0.05";
  trayAudioVol.value = "1";
  trayAudioVol.hidden = true;
  trayAudioVol.title = "\u97F3\u91CF";
  trayAudioVol.style.cssText = "width:64px;vertical-align:middle;";
  trayAudioVol.addEventListener("input", () => {
    if (window.ReLive && window.ReLive.setAudioVolume) window.ReLive.setAudioVolume(Number(trayAudioVol.value));
  });
  if (trayClock && trayClock.parentElement) {
    trayClock.parentElement.insertBefore(trayAudio, trayClock);
    trayClock.parentElement.insertBefore(trayAudioVol, trayAudio);
  }
  if (window.ReLive && window.ReLive.setAudioStateCb) {
    window.ReLive.setAudioStateCb((s) => {
      if (!s) return;
      if (s.error) {
        trayAudio.hidden = false;
        trayAudio.textContent = "\u{1F507}";
        trayAudio.title = "\u58F0\u97F3\uFF1A" + s.error;
        return;
      }
      trayAudio.hidden = !s.available;
      trayAudioVol.hidden = !s.available;
      trayAudio.textContent = s.muted ? "\u{1F507}" : "\u{1F50A}";
      if (s.running === false) trayAudio.title = "\u58F0\u97F3\u5DF2\u5C31\u7EEA\uFF0C\u70B9\u51FB\u64AD\u653E";
      else trayAudio.title = s.muted ? "\u58F0\u97F3\u5DF2\u9759\u97F3\uFF08\u70B9\u51FB\u5F00\u542F\uFF09" : "\u58F0\u97F3\u5F00\u542F\uFF08\u70B9\u51FB\u9759\u97F3\uFF09";
    });
  }
  trayAudio.addEventListener("click", () => {
    if (!window.ReLive || !window.ReLive.toggleAudioMuted) return;
    if (window.ReLive.resumeAudio) window.ReLive.resumeAudio();
    const muted = window.ReLive.toggleAudioMuted();
    trayAudio.textContent = muted ? "\u{1F507}" : "\u{1F50A}";
  });
  function persist() {
    for (const [id, win] of wins) {
      if (win.maximized) continue;
      saved[id] = {
        left: win.el.offsetLeft,
        top: win.el.offsetTop,
        width: win.el.offsetWidth,
        height: win.el.offsetHeight
      };
    }
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(saved));
    } catch {
    }
  }
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
      mark.textContent = tool?.mark || "\xB7";
      if (tool?.color) mark.style.background = tool.color;
      const label = document.createElement("span");
      label.className = "tb-label";
      label.textContent = tool?.title || id;
      btn.append(mark, label);
      btn.title = win.minimized ? "\u6062\u590D\u7A97\u53E3" : "\u6700\u5C0F\u5316 / \u7F6E\u9876";
      btn.addEventListener("click", () => toggle(id));
      taskButtons.appendChild(btn);
    }
  }
  function renderStartMenu() {
    if (!startMenu) return;
    startMenu.replaceChildren();
    const head = document.createElement("div");
    head.className = "tb-start-head";
    head.textContent = "\u8BBE\u5907\u5DE5\u5177";
    startMenu.appendChild(head);
    for (const tool of tools) {
      const item = document.createElement("button");
      item.className = "tb-start-item";
      const mark = document.createElement("span");
      mark.className = "tb-mark";
      mark.textContent = tool.mark || "\xB7";
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
      win.el.style.left = clamp2(win.el.offsetLeft, 0, Math.max(0, layer.clientWidth - w)) + "px";
      win.el.style.top = clamp2(win.el.offsetTop, 0, Math.max(0, layer.clientHeight - h)) + "px";
    }
  });
  layerRo.observe(layer);
  const clockTimer = setInterval(() => {
    if (trayClock) trayClock.textContent = (/* @__PURE__ */ new Date()).toLocaleTimeString("zh-CN", { hour12: false });
  }, 1e3);
  if (trayClock) trayClock.textContent = (/* @__PURE__ */ new Date()).toLocaleTimeString("zh-CN", { hour12: false });
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
        <button class="dw-act" data-act="min" title="\u6700\u5C0F\u5316\uFF08\u6536\u8FDB\u4EFB\u52A1\u680F\uFF0C\u4E0D\u5173\u4F1A\u8BDD\uFF09">\u2014</button>
        <button class="dw-act" data-act="max" title="\u6700\u5927\u5316 / \u8FD8\u539F">\u25A1</button>
        <button class="dw-act" data-act="close" title="\u5173\u95ED\u7A97\u53E3">\xD7</button>
      </div>
      <div class="dw-body"></div>
      <div class="dw-grip" title="\u62D6\u52A8\u8C03\u6574\u5927\u5C0F"></div>`;
    const mark = el.querySelector(".dw-mark");
    mark.textContent = tool.mark || "\xB7";
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
      restoreRect: null
    };
    el.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
      focus(tool.id);
    });
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
      }
      const move = (e) => {
        e.stopPropagation();
        el.style.left = clamp2(left0 + e.clientX - startX, 0, Math.max(0, layer.clientWidth - 150)) + "px";
        el.style.top = clamp2(top0 + e.clientY - startY, 0, Math.max(0, layer.clientHeight - 40)) + "px";
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
    bar.addEventListener("dblclick", (event) => {
      if (event.target.closest(".dw-act")) return;
      event.preventDefault();
      toggleMax(tool.id);
    });
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
      } catch {
      }
      const move = (e) => {
        e.stopPropagation();
        const w = clamp2(w0 + e.clientX - startX, tool.minWidth || 460, Math.max(460, layer.clientWidth - left));
        const h = clamp2(h0 + e.clientY - startY, tool.minHeight || 320, Math.max(320, layer.clientHeight - top));
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
    bar.addEventListener("click", (event) => {
      const act = event.target.closest(".dw-act")?.dataset.act;
      if (!act) return;
      event.stopPropagation();
      if (act === "min") minimize(tool.id);
      else if (act === "max") toggleMax(tool.id);
      else if (act === "close") close(tool.id);
    });
    const ro = new ResizeObserver(() => {
      if (!win.panel || win.minimized || !el.isConnected) return;
      try {
        byId.get(tool.id)?.onResize?.(win.panel);
      } catch (error) {
        log(`[\u684C\u9762] ${tool.title} \u91CD\u6392\u5931\u8D25\uFF1A${error?.message || error}`, "dim");
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
        log(`[\u684C\u9762] ${tool.title} \u6253\u5F00\u5931\u8D25\uFF1A${error?.message || error}`, "err");
      }
      return existing;
    }
    const win = makeWindow(tool);
    const rect0 = saved[id];
    const offset = wins.size % 6 * 28;
    const width = clamp2(rect0?.width || tool.width || 900, tool.minWidth || 460, Math.max(460, layer.clientWidth - 20));
    const height = clamp2(rect0?.height || tool.height || 620, tool.minHeight || 320, Math.max(320, layer.clientHeight - 20));
    applyRect(win, {
      left: clamp2(rect0?.left ?? 40 + offset, 0, Math.max(0, layer.clientWidth - 150)),
      top: clamp2(rect0?.top ?? 32 + offset, 0, Math.max(0, layer.clientHeight - 40)),
      width,
      height
    });
    win.body.appendChild(tool.host);
    layer.appendChild(win.el);
    wins.set(id, win);
    focus(id);
    renderTaskbar();
    try {
      win.panel = tool.onMount?.(tool.host) || null;
      tool.onOpen?.(win.panel);
    } catch (error) {
      log(`[\u684C\u9762] ${tool.title} \u6302\u8F7D\u5931\u8D25\uFF1A${error?.message || error}`, "err");
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
      btn.title = "\u6700\u5927\u5316";
    } else {
      win.restoreRect = {
        left: win.el.offsetLeft,
        top: win.el.offsetTop,
        width: win.el.offsetWidth,
        height: win.el.offsetHeight
      };
      win.maximized = true;
      win.el.classList.add("max");
      const btn = win.el.querySelector('[data-act="max"]');
      btn.classList.add("on");
      btn.title = "\u8FD8\u539F";
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
      log(`[\u684C\u9762] ${tool?.title || id} \u6536\u5C3E\u5931\u8D25\uFF1A${error?.message || error}`, "dim");
    }
    win.ro?.disconnect();
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
    } catch {
    }
    if (!handled) close(activeId);
    return true;
  }
  function setTray({ device, battery } = {}) {
    if (trayDevice && device !== void 0) trayDevice.textContent = device || "\u672A\u8FDE\u63A5";
    if (trayBattery && battery !== void 0) {
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
    }
  };
}

// src/tools/status.js
var COMMANDS = [
  ["props", "getprop"],
  ["size", "wm size"],
  ["density", "wm density"],
  ["battery", "dumpsys battery"],
  ["uptime", "cat /proc/uptime"],
  ["storage", "df -h /sdcard"],
  ["wifi", "settings get global wifi_on"],
  ["ip", "ip -o -4 addr show"],
  ["kernel", "uname -r"]
];
function esc3(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function pickStorage(text) {
  const lines = String(text).trim().split(/\r?\n/).filter((line) => line.trim());
  const row = lines.find((line) => /\d+%\s/.test(line)) || lines.at(-1) || "";
  const cols = row.trim().split(/\s+/);
  if (cols.length < 5) return { text: String(text).trim() || "\u672A\u8BFB\u5230", used: "\u2014", total: "\u2014", percent: "" };
  return {
    text: row.trim(),
    total: cols[1],
    used: cols[2],
    avail: cols[3],
    percent: cols[4]
  };
}
function pickIp(text) {
  const found = [...String(text).matchAll(/inet\s+(\d+\.\d+\.\d+\.\d+)\//g)].map((m) => m[1]).filter((ip) => ip !== "127.0.0.1");
  return found[0] || "\u2014";
}
function mountStatusPanel({ container, getDriver, log = () => {
}, onTray = () => {
} }) {
  container.innerHTML = `
    <div class="st-bar">
      <span class="st-title">\u8BBE\u5907\u72B6\u6001</span>
      <button class="st-btn primary" data-act="refresh">\u5237\u65B0</button>
      <label class="st-auto"><input type="checkbox" id="stAuto"> \u6BCF\u5206\u949F\u81EA\u52A8\u5237\u65B0\u7535\u91CF</label>
      <span class="st-spacer"></span>
      <span class="st-state" id="stState">\u7B49\u5F85\u8BFB\u53D6</span>
    </div>
    <div class="st-scroll">
      <div class="st-cards">
        <div class="st-card"><span class="st-k">\u8BBE\u5907</span><b class="st-v" id="stDevice">\u2014</b><span class="st-sub" id="stSystem">\u2014</span></div>
        <div class="st-card"><span class="st-k">\u7535\u91CF</span><b class="st-v" id="stLevel">\u2014</b><span class="st-sub" id="stPower">\u2014</span></div>
        <div class="st-card"><span class="st-k">\u5B58\u50A8\uFF08/sdcard\uFF09</span><b class="st-v" id="stUsed">\u2014</b><span class="st-sub" id="stStorage">\u2014</span></div>
        <div class="st-card"><span class="st-k">\u7F51\u7EDC / \u5F00\u673A\u65F6\u957F</span><b class="st-v" id="stIp">\u2014</b><span class="st-sub" id="stUptime">\u2014</span></div>
      </div>
      <div class="st-section">\u8BE6\u7EC6\u4FE1\u606F</div>
      <div class="st-grid" id="stGrid"></div>
      <div class="st-note">\u6240\u6709\u6570\u503C\u90FD\u6765\u81EA\u8BBE\u5907\u4E0A\u5B9E\u65F6\u6267\u884C\u7684\u53EA\u8BFB\u547D\u4EE4\uFF1B\u547D\u4EE4\u539F\u6587\u548C\u8FD4\u56DE\u5185\u5BB9\u5199\u5728\u53F3\u4FA7\u300C\u8BE6\u7EC6\u65E5\u5FD7\u300D\u91CC\uFF08\u5173\u6389\u7A97\u53E3\u4E0D\u5F71\u54CD\u6295\u5C4F\uFF09\u3002</div>
    </div>`;
  const $ = (id) => container.querySelector("#" + id);
  const stateEl = $("stState");
  const autoEl = $("stAuto");
  let timer = null;
  let loaded = false;
  let busy = false;
  let lastProps = {};
  function setState(text, kind = "") {
    stateEl.textContent = text;
    stateEl.className = "st-state" + (kind ? " " + kind : "");
  }
  async function run(command) {
    const driver = getDriver();
    if (!driver?.connected) throw new Error("\u8BBE\u5907\u672A\u8FDE\u63A5");
    const text = String(
      await driver.adb.subprocess.noneProtocol.spawnWaitText([command + " 2>&1"])
    ).trim();
    log(`[\u72B6\u6001] $ ${command} \u2192 ${text.slice(0, 160) || "\uFF08\u65E0\u8F93\u51FA\uFF09"}`, "dim");
    return text;
  }
  function renderOverview(raw) {
    const p = GJ.props(raw.props || "");
    lastProps = p;
    const d = GJ.display(raw.size || "", raw.density || "");
    const b = GJ.battery(raw.battery || "");
    const uptime = GJ.duration(parseFloat(raw.uptime || "0"));
    const storage = pickStorage(raw.storage || "");
    const ip = pickIp(raw.ip || "");
    const wifiOn = /^1$/.test(String(raw.wifi || "").trim());
    const charging = b.ac || b.usb || b.wireless;
    $("stDevice").textContent = GJ.deviceName(p) || "\u2014";
    $("stSystem").textContent = `Android ${p["ro.build.version.release"] || "?"} \xB7 API ${p["ro.build.version.sdk"] || "?"}`;
    $("stLevel").textContent = b.level === null ? "\u2014" : `${b.level}%${charging ? " \xB7 \u5145\u7535\u4E2D" : ""}`;
    $("stPower").textContent = `${b.voltage === null ? "\u2014" : b.voltage.toFixed(3) + " V"} \xB7 ${b.temperature === null ? "\u2014" : b.temperature + "\u2103"}`;
    $("stUsed").textContent = storage.percent || "\u2014";
    $("stStorage").textContent = `\u5DF2\u7528 ${storage.used} / \u5171 ${storage.total} \xB7 \u53EF\u7528 ${storage.avail || "\u2014"}`;
    $("stIp").textContent = `${wifiOn ? "Wi-Fi \u5F00" : "Wi-Fi \u5173"} \xB7 ${ip}`;
    $("stUptime").textContent = `\u5DF2\u5F00\u673A ${uptime}`;
    const rows = [
      ["\u54C1\u724C", p["ro.product.brand"]],
      ["\u578B\u53F7", p["ro.product.model"]],
      ["\u4EE3\u53F7", p["ro.product.device"]],
      ["\u5E02\u573A\u540D", GJ.deviceName(p)],
      ["\u7CFB\u7EDF\u7248\u672C", p["ro.build.version.release"]],
      ["SDK", p["ro.build.version.sdk"]],
      ["CPU \u67B6\u6784", p["ro.product.cpu.abi"]],
      ["\u5C4F\u5E55", d.width ? `${d.width}\xD7${d.height} \xB7 ${d.dpi || "?"} dpi` : "\u2014"],
      ["\u5185\u6838", (raw.kernel || "").trim()],
      ["\u7F16\u8BD1\u7248\u672C", p["ro.build.fingerprint"]],
      ["\u7535\u91CF\u539F\u59CB\u503C", b.level === null ? "\u2014" : String(b.level)],
      ["\u5145\u7535\u72B6\u6001", charging ? "\u5145\u7535\u4E2D" : "\u672A\u5145\u7535"],
      ["\u5B58\u50A8\u539F\u6587", storage.text],
      ["IP \u539F\u6587", String(raw.ip || "").trim().split(/\r?\n/).slice(0, 2).join(" / ")]
    ];
    $("stGrid").innerHTML = rows.map(([k, v]) => `<div class="st-pair"><span>${esc3(k)}</span><b title="${esc3(v || "\u2014")}">${esc3(v || "\u2014")}</b></div>`).join("");
    const tray = b.level === null ? "" : `${b.level}%${charging ? " \u5145\u7535\u4E2D" : ""}`;
    onTray({ battery: tray, device: GJ.deviceName(p) });
    return b;
  }
  async function refresh() {
    if (busy) return;
    const driver = getDriver();
    if (!driver?.connected) {
      setState("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
      return;
    }
    busy = true;
    setState("\u6B63\u5728\u8BFB\u53D6\u2026");
    const raw = {};
    try {
      for (const [key, command] of COMMANDS) {
        try {
          raw[key] = await run(command);
        } catch (error) {
          raw[key] = "";
          log(`[\u72B6\u6001] ${key} \u8BFB\u53D6\u5931\u8D25\uFF1A${error?.message || error}`, "dim");
        }
      }
      renderOverview(raw);
      loaded = true;
      setState("\u5DF2\u66F4\u65B0 " + (/* @__PURE__ */ new Date()).toLocaleTimeString(), "ok");
    } catch (error) {
      setState("\u8BFB\u53D6\u5931\u8D25\uFF1A" + (error?.message || error), "err");
      log("[\u72B6\u6001] \u8BFB\u53D6\u5931\u8D25\uFF1A" + (error?.message || error), "err");
    } finally {
      busy = false;
    }
  }
  async function refreshLight() {
    if (busy || !loaded) return;
    if (!container.isConnected || container.offsetParent === null) return;
    const driver = getDriver();
    if (!driver?.connected) return;
    try {
      const batteryText = await run("dumpsys battery");
      const uptimeText = await run("cat /proc/uptime");
      const b = GJ.battery(batteryText);
      const charging = b.ac || b.usb || b.wireless;
      $("stLevel").textContent = b.level === null ? "\u2014" : `${b.level}%${charging ? " \xB7 \u5145\u7535\u4E2D" : ""}`;
      $("stPower").textContent = `${b.voltage === null ? "\u2014" : b.voltage.toFixed(3) + " V"} \xB7 ${b.temperature === null ? "\u2014" : b.temperature + "\u2103"}`;
      $("stUptime").textContent = `\u5DF2\u5F00\u673A ${GJ.duration(parseFloat(uptimeText || "0"))}`;
      onTray({ battery: b.level === null ? "" : `${b.level}%${charging ? " \u5145\u7535\u4E2D" : ""}` });
      setState("\u5DF2\u66F4\u65B0 " + (/* @__PURE__ */ new Date()).toLocaleTimeString(), "ok");
    } catch (error) {
      log(`[\u72B6\u6001] \u8F7B\u91CF\u5237\u65B0\u5931\u8D25\uFF1A${error?.message || error}`, "dim");
    }
  }
  function syncTimer() {
    clearInterval(timer);
    timer = autoEl.checked ? setInterval(refreshLight, 6e4) : null;
  }
  autoEl.addEventListener("change", () => {
    syncTimer();
    log(autoEl.checked ? "[\u72B6\u6001] \u5DF2\u5F00\u542F\u6BCF\u5206\u949F\u5237\u65B0\u7535\u91CF" : "[\u72B6\u6001] \u5DF2\u5173\u95ED\u81EA\u52A8\u5237\u65B0", "dim");
  });
  container.addEventListener("click", (event) => {
    if (event.target.closest('[data-act="refresh"]')) refresh();
  });
  function clear() {
    clearInterval(timer);
    timer = null;
    loaded = false;
    onTray({ battery: "" });
    setState("\u8BBE\u5907\u672A\u8FDE\u63A5");
  }
  return {
    open() {
      syncTimer();
      if (!loaded) refresh();
    },
    refresh,
    close() {
      clearInterval(timer);
      timer = null;
    },
    clear,
    onEscape: () => false,
    get props() {
      return lastProps;
    }
  };
}

// src/tools/screenshot.js
var PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
function esc4(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function stamp() {
  const d = /* @__PURE__ */ new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}
function formatSize2(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}
function mountScreenshotPanel({ container, getDriver, log = () => {
} }) {
  container.innerHTML = `
    <div class="ss-bar">
      <span class="ss-title">\u622A\u56FE</span>
      <button class="ss-btn primary" data-act="shot">\u7ACB\u5373\u622A\u56FE</button>
      <button class="ss-btn" data-act="clear">\u6E05\u7A7A</button>
      <span class="ss-spacer"></span>
      <span class="ss-state" id="ssState">\u672C\u6B21\u4F1A\u8BDD 0 \u5F20</span>
    </div>
    <div class="ss-scroll">
      <div class="ss-grid" id="ssGrid"></div>
      <div class="ss-empty" id="ssEmpty">\u70B9\u300C\u7ACB\u5373\u622A\u56FE\u300D\u6293\u4E00\u5F20\u5E73\u677F\u753B\u9762\u3002<br>\u622A\u56FE\u53EA\u5B58\u5728\u6D4F\u89C8\u5668\u5185\u5B58\u91CC\uFF0C\u5237\u65B0\u9875\u9762\u4F1A\u4E22\u5931\uFF0C\u8981\u7559\u6863\u8BB0\u5F97\u70B9\u300C\u4E0B\u8F7D\u300D\u3002</div>
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
    grid.innerHTML = items.map(
      (item, index) => `
      <div class="ss-item" data-i="${index}">
        <img src="${item.url}" alt="\u622A\u56FE ${index + 1}">
        <div class="ss-meta"><span>${esc4(item.name)}</span><span>${formatSize2(item.size)}</span></div>
        <div class="ss-ops">
          <button data-op="view" title="\u67E5\u770B\u5927\u56FE">\u67E5\u770B</button>
          <button data-op="download" title="\u4FDD\u5B58\u5230\u7535\u8111">\u4E0B\u8F7D</button>
          <button data-op="remove" title="\u4ECE\u5217\u8868\u79FB\u9664">\u79FB\u9664</button>
        </div>
      </div>`
    ).join("");
    setState(`\u672C\u6B21\u4F1A\u8BDD ${items.length} \u5F20`);
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
      <div class="ss-lightbox-bar"><span>${esc4(item.name)} \xB7 ${formatSize2(item.size)}</span>
        <button data-op="download">\u4E0B\u8F7D</button><button data-op="close">\u5173\u95ED\uFF08Esc\uFF09</button></div>
      <img src="${item.url}" alt="\u622A\u56FE\u5927\u56FE">`;
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
    log(`[\u622A\u56FE] \u4E0B\u8F7D ${item.name}\uFF08${formatSize2(item.size)}\uFF09`, "dim");
  }
  async function shell2(driver, command) {
    return String(
      await driver.adb.subprocess.noneProtocol.spawnWaitText([command + " 2>&1"])
    ).trim();
  }
  async function shoot() {
    if (busy) return;
    const driver = getDriver();
    if (!driver?.connected) {
      setState("\u8BBE\u5907\u672A\u8FDE\u63A5", "err");
      return;
    }
    busy = true;
    setState("\u6B63\u5728\u622A\u56FE\u2026");
    const myToken = ++token;
    const remote = `/sdcard/gjw_shot_${stamp()}_${Math.random().toString(36).slice(2, 6)}.png`;
    let keepRemote = false;
    try {
      log(`[\u622A\u56FE] \u8BBE\u5907\u7AEF\u6267\u884C\uFF1Ascreencap -p ${remote}`, "dim");
      const out = await shell2(driver, `screencap -p '${remote}'`);
      if (out) log(`[\u622A\u56FE] screencap \u8F93\u51FA\uFF1A${out}`, "dim");
      const blob = await driver.read(remote);
      const head = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
      if (!PNG_SIGNATURE.every((b, i) => head[i] === b)) {
        keepRemote = true;
        throw new Error(`\u8BFB\u56DE\u7684\u4E0D\u662F PNG\uFF08${blob.size} \u5B57\u8282\uFF09\uFF0C\u539F\u6587\u4EF6\u5DF2\u4FDD\u7559\u5728 ${remote}`);
      }
      const name = remote.split("/").pop();
      const item = { name, url: URL.createObjectURL(blob), size: blob.size, blob };
      items.unshift(item);
      render();
      setState(`\u5DF2\u4FDD\u5B58 ${items.length} \u5F20`, "ok");
      log(`[\u622A\u56FE] \u5B8C\u6210\uFF1A${name}\uFF08${formatSize2(blob.size)}\uFF09`, "ok");
    } catch (error) {
      const message = error?.message || String(error);
      setState("\u622A\u56FE\u5931\u8D25\uFF1A" + message, "err");
      log(`[\u622A\u56FE] \u5931\u8D25\uFF1A${message}`, "err");
      log(`[\u622A\u56FE] \u8BBE\u5907\u7AEF\u4E34\u65F6\u6587\u4EF6\uFF1A${remote}${keepRemote ? "\uFF08\u5DF2\u4FDD\u7559\uFF09" : ""}`, "dim");
    } finally {
      if (!keepRemote) {
        try {
          await shell2(getDriver(), `rm -f '${remote}'`);
          log(`[\u622A\u56FE] \u5DF2\u6E05\u7406\u8BBE\u5907\u7AEF\u4E34\u65F6\u6587\u4EF6 ${remote}`, "dim");
        } catch (error) {
          log(`[\u622A\u56FE] \u6E05\u7406\u4E34\u65F6\u6587\u4EF6\u5931\u8D25\uFF08\u4E0D\u5F71\u54CD\u622A\u56FE\uFF09\uFF1A${error?.message || error}`, "dim");
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
      log("[\u622A\u56FE] \u5DF2\u6E05\u7A7A\u672C\u6B21\u4F1A\u8BDD\u7684\u622A\u56FE", "dim");
    }
  });
  return {
    open() {
    },
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
    }
  };
}

// src/relive/entry.js
window.ReLive = session_default;
window.ReLive.setAudioStateCb = setAudioStateCb;
window.ReLive.setAudioMuted = setAudioMuted;
window.ReLive.setAudioVolume = setAudioVolume;
window.ReLive.toggleAudioMuted = toggleAudioMuted;
window.ReLive.getAudioState = getAudioState;
window.ReLive.mountFilePanel = mountFilePanel;
window.ReLive.mountAppPanel = mountAppPanel;
window.ReLive.mountTerminalPanel = mountTerminalPanel;
window.ReLive.createDesktop = createDesktop;
window.ReLive.mountStatusPanel = mountStatusPanel;
window.ReLive.mountScreenshotPanel = mountScreenshotPanel;
