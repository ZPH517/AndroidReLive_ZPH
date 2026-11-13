/* 校验浏览器真正加载的模块图：index.html 里的脚本 / 样式 / importmap 指向的文件都真实存在
 *
 * 背景：js/core/ 和 js/vendor/ 是浏览器直接按相对路径拉的原生 ES 模块，不经过打包。
 *       目录搬家（比如 js/toolbox/ → js/core/）时，里面写死的 ./vendor/xxx.js 不会有人提醒你，
 *       页面能打开，但一点「连接设备」就报 Failed to fetch dynamically imported module。
 *       所以每次改完目录结构都跑一遍这个脚本。
 *
 * 用法：node scripts/check-pages.cjs
 */
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const pages = ["index.html"];
const problems = [];

// 去掉注释，避免把注释里用来说明写法的 import 当成真依赖
const stripComments = code => code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");

function resolveSpecifier(spec, fromFile, importMap) {
  if (/^[a-z]+:/i.test(spec) || spec.startsWith("//")) return null; // http: / data: 等外部资源
  if (spec.startsWith(".") || spec.startsWith("/")) {
    const clean = spec.split("?")[0];
    return clean.startsWith("/")
      ? path.join(root, clean)
      : path.resolve(path.dirname(fromFile), clean);
  }
  return importMap[spec] ? path.resolve(root, "." + importMap[spec].replace(/^\.\//, "/")) : { unresolved: spec };
}

const checked = new Set();
function check(file, fromFile, spec) {
  const key = path.relative(root, file);
  if (checked.has(key)) return;
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    problems.push(`${path.relative(root, fromFile)} → ${spec}（找不到 ${key}）`);
    return;
  }
  checked.add(key);
  if (!/\.js$/.test(file)) return;
  const code = stripComments(fs.readFileSync(file, "utf8"));
  const pattern = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["']([^"']+)["']/g;
  for (const match of code.matchAll(pattern)) walk(match[1], file);
}

const importMap = {};
function walk(spec, fromFile) {
  const target = resolveSpecifier(spec, fromFile, importMap);
  if (!target) return;
  if (target.unresolved) {
    problems.push(`${path.relative(root, fromFile)} → ${spec}（importmap 里没有这个包名）`);
    return;
  }
  check(target, fromFile, spec);
}

for (const page of pages) {
  const html = fs.readFileSync(path.join(root, page), "utf8");
  const mapMatch = html.match(/<script\s+type="importmap"[^>]*>([\s\S]*?)<\/script>/);
  if (mapMatch) Object.assign(importMap, JSON.parse(mapMatch[1]).imports || {});

  const refs = [
    ...html.matchAll(/<script[^>]*\bsrc="([^"]+)"/g),
    ...html.matchAll(/<link[^>]*\bhref="([^"]+)"/g),
  ];
  for (const [, ref] of refs) {
    const target = resolveSpecifier(ref, path.join(root, page), importMap);
    if (target) check(target, path.join(root, page), ref);
  }
}

if (problems.length) {
  console.error("页面依赖有 " + problems.length + " 处指向不存在的文件：\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`页面模块图正常：${checked.size} 个文件全部存在`);

/* ---------- 第二部分：跨模块变量泄漏 ----------
 * 背景：拆文件时最容易犯的错是「变量定义搬走了，使用处留在原文件」。
 *       这种代码语法完全合法，构建也不报错，但一跑就是 xxx is not defined。
 *       这里按目录比对：同目录 A.js 声明的模块级变量，B.js 直接用了却没 import → 报错。
 */
const leaks = [];
function scanDir(dir) {
  if (!fs.existsSync(dir)) return;
  const files = fs.readdirSync(dir).filter(f => f.endsWith(".js"));
  if (files.length < 2) return;

  const info = files.map(f => {
    const code = stripComments(fs.readFileSync(path.join(dir, f), "utf8"));
    const declared = new Set();
    for (const m of code.matchAll(/^(?:export\s+)?(?:let|const|var|function|class)\s+([A-Za-z_$][\w$]*)/gm)) declared.add(m[1]);
    for (const m of code.matchAll(/^(?:export\s+)?(?:let|const|var)\s+[^;\n]*?,([^;\n]*)/gm)) {
      for (const part of m[1].split(",")) {
        const name = part.trim().match(/^([A-Za-z_$][\w$]*)\s*=/);
        if (name) declared.add(name[1]);
      }
    }
    const imported = new Set();
    for (const m of code.matchAll(/import\s*(?:\*\s*as\s*)?\{([^}]*)\}\s*from/g)) {
      for (const part of m[1].split(",")) imported.add(part.trim().split(/\s+as\s+/).pop());
    }
    for (const m of code.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from/g)) imported.add(m[1]);
    return { file: f, code, declared, imported };
  });

  for (const owner of info) {
    for (const name of owner.declared) {
      if (name.length < 4) continue;
      for (const user of info) {
        if (user.file === owner.file || user.declared.has(name) || user.imported.has(name)) continue;
        const used = new RegExp(`(?:^|[^.\\w$])${name}\\s*[=(]`, "m");
        if (used.test(user.code)) {
          leaks.push(`${path.join(path.relative(root, dir), user.file)} 用了 ${name}，但它只在本目录的 ${owner.file} 里声明（需要 import）`);
        }
      }
    }
  }
}
["src/relive", "src/apps", "src/desktop", "src/files", "src/tools", "js/core"].forEach(d => scanDir(path.join(root, d)));

if (leaks.length) {
  console.error("跨模块变量有 " + leaks.length + " 处没 import：\n  " + leaks.join("\n  "));
  process.exit(1);
}
console.log("跨模块变量检查通过：没有「用了别人文件的变量却没 import」");

