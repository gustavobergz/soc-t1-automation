'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = __dirname;
const PORT = Number(process.env.SOC_PREVIEW_PORT || 8893);
const ORIGIN = `http://127.0.0.1:${PORT}`;
const allowed = new Set(['index.html', 'clinica-205mil.txt', 'clinica-investigacao-205k.jsonl.gz']);
const server = http.createServer(async (req, res) => {
  try {
    if (req.headers.host !== `127.0.0.1:${PORT}`) { res.writeHead(403).end(); return; }
    const url = new URL(req.url, ORIGIN);
    if (req.headers.origin && req.headers.origin !== ORIGIN) { res.writeHead(403).end(); return; }
    if (url.pathname.startsWith('/ollama/')) {
      const endpoint = url.pathname.slice('/ollama'.length);
      if (!['/api/tags', '/api/version', '/api/chat'].includes(endpoint) || !['GET','POST'].includes(req.method)) { res.writeHead(404).end(); return; }
      const chunks=[]; let size=0;
      for await (const c of req) { size+=c.length; if(size>1000000) throw new Error('Entrada excessiva'); chunks.push(c); }
      const reply = await fetch('http://127.0.0.1:11434'+endpoint, {method:req.method, headers:{'Content-Type':'application/json'}, body:req.method==='POST'?Buffer.concat(chunks):undefined, signal:AbortSignal.timeout(300000)});
      res.writeHead(reply.status, {'Content-Type':'application/json'}); res.end(await reply.text()); return;
    }
    const savedSession=url.pathname.match(/^\/sessao\/([a-f0-9-]{36})$/i);
    if(savedSession && req.method==='GET') {
      const file=path.join(ROOT,'sessoes','sessao-'+savedSession[1]+'.json');
      if(!fs.existsSync(file)){res.writeHead(404,{'Content-Type':'application/json'}).end('{"error":"Sessão não encontrada"}');return;}
      res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
      fs.createReadStream(file).pipe(res);return;
    }
    if (url.pathname === '/sessao' && req.method === 'POST') {
      const chunks=[];let size=0;
      for await(const c of req) {size+=c.length;if(size>2000000) throw new Error('Auditoria excessiva');chunks.push(c);}
      const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if(!/^[a-f0-9-]{36}$/.test(data.sessao) || !Array.isArray(data.auditoria)) {res.writeHead(400).end();return;}
      const dir=path.join(ROOT,'sessoes');fs.mkdirSync(dir,{recursive:true});
      const dest=path.join(dir,`sessao-${data.sessao}.json`);
      fs.writeFileSync(dest+'.tmp',JSON.stringify(data,null,2));fs.renameSync(dest+'.tmp',dest);
      res.writeHead(200,{'Content-Type':'application/json'}).end('{"saved":true}');return;
    }
    const name=url.pathname==='/'?'index.html':url.pathname.slice(1);
    if(req.method!=='GET' || !allowed.has(name)) {res.writeHead(404).end();return;}
    const file=path.join(ROOT,name);
    res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.gz')?'application/gzip':'text/plain; charset=utf-8','Cache-Control':'no-store'});
    fs.createReadStream(file).pipe(res);
  }catch(e){if(!res.headersSent)res.writeHead(502,{'Content-Type':'application/json'});res.end(JSON.stringify({error:e.message}));}
});
server.listen(PORT,'127.0.0.1',()=>console.log(`SOC local: ${ORIGIN}`));
server.on('error',e=>{console.error(e.message);process.exitCode=1;});
