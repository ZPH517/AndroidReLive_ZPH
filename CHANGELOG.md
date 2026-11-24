# 更新记录

本项目的版本号与上游 [搞机工具箱 Web](https://github.com/CzJam/gjgjxweb) 独立。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.2.0] - 2026-11-24

### 新增：全设备无线连接（三条通道）
解决「新电脑配不上对」「老手机 / 智能电视连不上」两类高频失败。核心认识：ADB 的信任是按
**电脑公钥**记的，换电脑就相当于换钥匙，所以必须把「重新建立信任」做成一次点击，而不是一串命令。

- `bridge.mjs` 新增连接编排层（`/link/*`）：
  - `GET /link/info`：本机网段、adb 版本、已记住的设备。
  - `POST /link/probe`：一次收齐 USB 设备、mDNS 广播、局域网 5555、常用设备，按来源分组返回。
  - `POST /link/usb-bootstrap`：插线后执行 `adb tcpip 5555`，自动从设备读出局域网 IP 并连接，
    成功后写入设备档案。**覆盖 Android 2.x 至今所有版本**，也覆盖没有任何配对界面的老设备。
  - `POST /link/lan-scan`：并发扫描本网段 ADB 端口（默认 5555，约 1 秒 / 254 台），
    用于没有 mDNS 广播的智能电视、机顶盒、老手机。
  - `POST /link/connect`：只给 IP 即可连接。先问 mDNS 要当前 TLS 端口，再退 5555 等常用端口，
    解决「Android 11+ 端口每次变」；TCP 通但 adb 连不上时判定为**未配对**并给出下一步，而不是笼统报错。
  - `POST /link/pair`：配对 + 立即连接合并（配对只管信任，端口还得找回）。
  - `GET /link/known`、`POST /link/forget`、`POST /link/reconnect`：设备档案与本机持久化，
    端口变化时自动重找，支持一键重连。
- 前端无线面板改为「一键连接向导」：一键发现设备 / USB 一键开启无线 / 扫局域网（电视·老设备）/ 重连上次设备；
  设备列表按 USB、需配对码、可直连、常用分组并区分标签。
- 配对体验：新增「等待配对码」——每 1.5 秒轮询 mDNS，手机一广播配对端口就自动填地址（配对弹窗只有几十秒，
  手抄地址是最常见的失败原因）；配对码输满 6 位自动配对并连接。
- 失败提示分级：明确区分「未配对」（需要 6 位码）、「未授权」（需要在设备上点允许）、「网络不通」，各自给出下一步。

### 修复
- `js/core/transport.js` 的桥接请求在 HTTP 500 时会丢掉 `needAuthorize` / `needPair` 等结构化字段，
  导致前端只能显示一句话；现在会把整个响应体与标记透传。

## [1.1.0] - 2026-11-12（待真机实测）

### 新增：无线连接（无线调试）
- 顶栏新增「USB / 无线」连接方式切换；切到「无线」会展开无线面板。
- `bridge.mjs`：本地桥接程序（默认 127.0.0.1:8126，仅绑本机），把浏览器的 WebSocket 字节
  转发到手机无线调试端口；背后按需拉起本机 adb 服务端（5037）来承载配对 / 连接 / 局域网发现。
  - `GET /health`：自检桥是否在线。
  - `POST /mdns`：列出同 Wi-Fi 下已开无线调试的设备（含「可直连」与「需配对」两类地址）。
  - `POST /wireless/pair`、`POST /wireless/connect`：首次配对与连接。
  - `WS /server`：管道到本机 adb server（自动发现 / 连接走这条）。
  - `WS /adb`：直连设备端口（手动 IP 走这条，不依赖本机 adb）。
- 前端无线面板：桥地址配置 + 连通性测试、扫描设备列表（可直连/需配对标记）、手动 IP:端口连接、
  「添加新设备」配对（配对地址 + 6 位码）。
- `js/core/transport.js` 新增 `scanWireless` / `pairWireless`，复用已有 `connectServer` / `connectTcp`。
- 连接成功后，镜像 / 文件 / 应用 / 终端与 USB 模式完全一致（Driver 层零改动）。
- 桥的 WebSocket 服务端为自实现（握手 + 帧编解码），不引入新依赖。

### 说明
- 无线调试是 Android 11+ 自带功能，**无需 root**；建议在可信 Wi-Fi 下使用，用完关闭「无线调试」。
- 电脑端需能找到 `adb`：桥自动探测常见位置，找不到时设 `ADB_BIN` 环境变量指定。

## [1.0.0] - 2026-11-11

首个以「安卓重生 AndroidReLive_ZPH」名义发布的版本。
内容 = 上游搞机工具箱 Web 的全部功能 + 投屏控制台整层能力，经过目录重构与品牌重命名。

### 新增

**投屏与输入**
- 主屏实时镜像：scrcpy-server 3.3.3，WebCodecs 解码，Canvas 2D 渲染
- 鼠标 / 键盘 / 滚轮映射到设备触摸与按键，右键返回、中键桌面、侧键最近任务
- 熄屏唤醒（先试 `KEYCODE_WAKEUP` 名字写法，退回数字 224）、接 USB 期间保持常亮
- 「松手」按钮清理设备端卡住的按下状态
- 「显示触摸位置」开关，用于核对投屏坐标

**桌面窗口系统**
- 投屏画面铺底当桌面，工具独立成窗
- 窗口拖动 / 缩放 / 最大化 / 最小化 / 置顶 / 关闭
- 位置与尺寸写入 localStorage，下次打开还原
- 最小化只隐藏 DOM，终端会话与文件目录不销毁
- 窄窗口自动拉回可视区，避免拖出屏幕找不回来
- 桌面层 `pointer-events: none`，只有窗口自身接收事件（防止吞掉投屏鼠标）

**文件管理**
- 走 ADB sync 协议而非 `adb push` 命令：大文件有进度、可中断、中文文件名不出错
- 目录浏览、双向传输、新建 / 删除 / 重命名
- 图片 / 视频 / 音频 / PDF / 文本在线预览，支持全屏

**应用管理**
- 应用列表与状态分组、搜索、勾选、批量启用 / 禁用 / 卸载 / 恢复
- 安装 APK（含拆分 APK 会话）、提取安装包、导出 CSV 清单、应用详情
- 从设备 APK 解析中文应用名与桌面图标，结果按包名缓存

**ADB 终端**
- 复用上游 `GJTerminal.Controller`，xterm.js 渲染，支持 Ctrl+C 中断、复制、自动 resize
- 常用只读命令一键执行
- 命令输入框 + ↑↓ 历史（历史存本地）

**设备状态与截图**
- 电量 / 电压 / 温度 / 存储 / 网络 / 开机时长 / 设备详情
- 可选每分钟刷新电量并同步到任务栏托盘
- 一键截屏、会话截图墙、查看大图 / 下载 / 清空，自动清理设备端临时文件

**兼容性处理**
- 小米 / 红米 / POCO 的 `INJECT_EVENTS` 权限拒绝：顶栏显示开启步骤 + 一键自检
- 日志分级（普通 / 弱化 / 错误），可切换「详细日志」查看逐条触摸与服务端 DEBUG

### 修复（开发过程中定位并解决的关键问题）

这几条都是实测踩出来的，记录在此供后来者避坑：

- **设备端 shell 脚本从未真正执行**：投屏库把参数数组用空格拼成一条字符串交给设备 `sh -c`，
  于是 `spawnWaitText(["sh", "-c", "A=1; kill -9 $A"])` 会被拆开，只有第一个词被当脚本，
  变量恒空、管道恒返回 0、`for...do` 报 syntax error，并且不会报错失败，只会给出假结论。
  改为 `shCmd(adb, 整段脚本)` 单参数传递，全项目 7 处调用全部替换。
- **设备端 scrcpy-server 进程杀不掉**：库里 `process.kill()` 只关闭浏览器侧的 ADB socket，
  不杀设备端 `app_process`，残留进程占着硬件编码器导致重启必 `Aborted`。
  改为读 `/proc/<pid>/cmdline` 扫描（绕开部分 ROM 上不可靠的 `ps`）+ SIGTERM→SIGKILL + 复查剩余数。
- **设备端 jar 被系统清理**：原先用 WeakSet 记住「这台设备推过了」就永不再推，
  文件被 ROM 清理后再启动 `app_process` 加载不到类，直接 SIGABRT。
  改为每次启动前用 `wc -c` 核对设备上真实字节数，不符就重推。
- **唤醒命令误报**：`wakeLike()` 是 async 但调用处漏了 `await`，拿到 Promise，
  所有正则 `.test()` 恒为 false，导致「点亮成功」永远为真。
- **透明层吞鼠标**：桌面容器早期带 `pointer-events` 覆盖整个画面，投屏鼠标点不到设备。
- **全屏预览被任务栏压住**：文件预览全屏时临时挂到 `body`，避开祖先 transform 的包含块限制。
- **连上了设备但每次投屏都失败**：拆分 `session.js` / `device.js` 时，`injectIssueReported` 是 `device.js`
  的模块内变量，`session.js` 却直接给它赋值，ES 模块是严格模式，于是抛 `injectIssueReported is not defined`，
  表现为日志先「已连接」、随后连着几次「镜像失败」。改为 `device.js` 导出 `resetInjectIssue()`；
  同时在 `npm run check` 里加了跨模块变量检查：同目录 A.js 声明的变量，B.js 用了却没 import 就报错，
  这类拆文件留下的暗雷以后构建前就能拦住。
- **点「连接设备」直接报错**：目录重组后，`js/core/transport.js` 里四个按需加载的依赖仍写着
  `./vendor/xxx.js`，实际应为 `../vendor/xxx.js`，浏览器会去请求不存在的 `js/core/vendor/adb.js`，
  报 `Failed to fetch dynamically imported module`。这类"页面能开、一点就炸"的问题改目录时最容易漏，
  因此新增 `scripts/check-pages.cjs`，把 `index.html → JS → vendor` 整条依赖链在提测前扫一遍，
  并接进 `npm run check`。

### 变更

- 项目更名为「安卓重生 AndroidReLive_ZPH」，不再沿用「搞机工具箱」名称，避免与上游混淆
- 页面只保留一个：`index.html` 就是重生控制台（打开 `http://127.0.0.1:8125/` 直接进控制台，不再有中间介绍页）
- 目录重组：
  - `src/scrcpy/` → `src/relive/`，`src/relive/index.js` → `session.js`
  - 投屏核心从单文件 1284 行拆成 `session.js`（会话编排）+ `device.js`（设备侧操作）
  - `js/toolbox/` 里的核心命令层（`core.js` / `terminal.js` / `transport.js`）移到 `js/core/`，
    与控制台源码形成「要构建 / 不用构建」的清晰两层
- 全局命名空间 `window.GJScrcpy` → `window.ReLive`；本地存储前缀 `gjw.` → `relive.`
- 构建命令统一为 `npm run build` / `watch` / `check`，启动为 `npm start`
- 控制台页面拆分：`index.html` 从 802 行降到 122 行，样式移到 `css/relive.css`、页面逻辑移到 `js/relive-page.js`，HTML 只留结构
- 本地服务端口改为 **8125**，与上游默认端口区分
- 文档从 6 份精简为 3 份：`README.md`（怎么用）、`docs/开发指南.md`（怎么改）、`CONTRIBUTING.md`（怎么贡献）

### 移除

- **经典工具箱页面**（`toolbox.html` 及其 `js/toolbox/app.js`、`batch.js`、`css/toolbox.css`）。
  它与"复活旧设备"这条主线关系不大，却占了近四成代码量，还得维护两套页面。
  控制台已覆盖其中常用的能力（应用管理、终端、电池/显示状态）；
  需要原版完整功能请直接用[上游项目](https://github.com/CzJam/gjgjxweb)。
- **`src/relive/legacy-windows.js`**（虚拟屏多窗口）。依赖第二块虚拟屏，
  在只有一路硬件 H.264 编码器的设备上必然 `Aborted`，代码零引用，删除以免误导。
- **左侧「应用列表 / 应用独立开窗」界面**（同上原因）。
- 上游的 `docs/index.html`（561 KB 单文件整合版），不再维护两份页面。
