/* 校验 relive.bundle.js 的外部 import 符号，在 js/vendor 对应文件中是否真实导出
 *
 * 背景：投屏相关代码是以 esbuild 打包 + importmap 的方式跑起来的，
 *       @yume-chan/* 被标成 external，运行时由页面里的 importmap 指向 js/vendor/*.js。
 *       一旦某个符号在 vendor 文件里不存在，页面会在 import 阶段直接白屏，
 *       而且报错信息很难看出是哪个符号——所以用这个脚本在构建后立刻查一遍。
 *
 * 用法：node scripts/check-bundle-imports.cjs
 */
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const bundlePath = path.join(root, "js/vendor/relive.bundle.js");

if (!fs.existsSync(bundlePath)) {
  console.error("找不到 js/vendor/relive.bundle.js，请先执行 npm run build");
  process.exit(1);
}
const bundle = fs.readFileSync(bundlePath, "utf8");

const map = {
  "@yume-chan/adb": "adb.js",
  "@yume-chan/stream-extra": "stream-extra.js",
  "@yume-chan/struct": "struct.js",
  "@yume-chan/event": "event.js",
  "@yume-chan/async": "async.js",
  "@yume-chan/no-data-view": "no-data-view.js",
};

const re = /import\s*\{([^}]+)\}\s*from\s*"(@yume-chan\/[^"]+)"/g;
const missing = [];
const checked = new Set();
let match;

while ((match = re.exec(bundle))) {
  const spec = match[2];
  const file = map[spec];
  if (!file) {
    missing.push(`${spec} → 未在 importmap 中映射`);
    continue;
  }
  const target = path.join(root, "js/vendor", file);
  if (!fs.existsSync(target)) {
    missing.push(`${spec} → 文件不存在 ${file}`);
    continue;
  }
  const source = fs.readFileSync(target, "utf8");
  const names = match[1]
    .split(",")
    .map((s) => s.trim().split(/\s+as\s+/)[0].trim())
    .filter(Boolean);
  for (const name of names) {
    checked.add(`${spec}:${name}`);
    if (!new RegExp(`\\b${name}\\b`).test(source)) {
      missing.push(`${spec} → ${name}`);
    }
  }
}

console.log(`检查符号 ${checked.size} 个，涉及 ${Object.keys(map).length} 个包`);
if (missing.length) {
  console.error("缺失符号：");
  for (const item of [...new Set(missing)]) console.error("  " + item);
  process.exitCode = 1;
} else {
  console.log("全部通过：bundle 所需符号在 vendor 文件中均存在");
}
