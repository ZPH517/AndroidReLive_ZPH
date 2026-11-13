/* 打包入口：把模块挂到全局，供普通 <script> 使用 */
import ReLive, { setAudioStateCb, setAudioMuted, setAudioVolume, toggleAudioMuted, getAudioState } from "./session.js";
import { mountFilePanel } from "../files/index.js";
import { mountAppPanel } from "../apps/index.js";
import { mountTerminalPanel } from "../terminal/index.js";
import { createDesktop } from "../desktop/index.js";
import { mountStatusPanel } from "../tools/status.js";
import { mountScreenshotPanel } from "../tools/screenshot.js";

window.ReLive = ReLive;
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

/* 「把应用单独开成小窗口」那套（windows.js + index.js 的 window 分支）
   还留在仓库里，但不再挂出来、页面也不再画左侧应用栏：
   这台展锐平板只有一个硬件 H.264 编码器，主屏投屏占着之后，
   虚拟第二块屏起不来（服务端 Aborted）。
   将来换设备或改走 freeform 自由窗口时，把下面两行加回来即可：
     import { createWindowManager, nextWindowId } from "./windows.js";
     window.ReLive.createWindowManager = createWindowManager;
     window.ReLive.nextWindowId = nextWindowId;
   同理 getAppMeta 之前是给左栏用的，应用面板自己管缓存，不用再导出。 */
