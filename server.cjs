/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-FileCopyrightText: 2026 晨钟酱Official
SPDX-License-Identifier: GPL-3.0-only
See LICENSE for the full license text.
*/
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=__dirname,port=Number(process.env.PORT||8125);
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.md':'text/plain; charset=utf-8','.txt':'text/plain; charset=utf-8'};
const server=http.createServer((req,res)=>{
  let filename;
  try{const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
    // 老链接兼容：以前控制台在 /relive.html，现在就是首页
    if(pathname==='/relive.html'){res.writeHead(302,{Location:'/'});res.end();return;}
    filename=path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));}catch{res.writeHead(400);res.end('Bad request');return;}
  if(!filename.startsWith(root+path.sep)){res.writeHead(403);res.end('Forbidden');return;}
  fs.readFile(filename,(error,data)=>{if(error){res.writeHead(404);res.end('Not found');return;}res.writeHead(200,{'Content-Type':types[path.extname(filename)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(data);});
});
server.on('error',error=>{console.error(error.code==='EADDRINUSE'?`端口 ${port} 已被占用，请设置 PORT 为其他端口后重试。`:error.message);process.exitCode=1;});
server.listen(port,'127.0.0.1',()=>console.log(`安卓重生 AndroidReLive 已启动：http://127.0.0.1:${port}\n按 Ctrl+C 停止。`));
