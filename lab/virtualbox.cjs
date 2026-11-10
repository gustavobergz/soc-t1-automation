const { execFile } = require('node:child_process');
const { createReadStream } = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');

const host = '127.0.0.1';
const port = 8771;
const origin = `http://${host}:${port}`;
const root = path.resolve(__dirname, '..');
const channels = new Map();
const listeners = new Set();
const journal = [];
let sequence = 0;

const commands = {
  manager: /^manual-detect SOC-\d{3,24} SOC-\d{3,24}-\d{2,4}(?:,SOC-\d{3,24}-\d{2,4}){0,29}$/,
  victim: /^prepare SOC-\d{3,}$/,
  attacker: /^(?:run SOC-\d{3,} (?:manual|auto|failure)|probe SOC-\d{3,} (?:pending|contained|released|denied|rejected|monitoring))$/,
  soar: /^(?:manual-triage SOC-\d{3,24} (?:alta|media|baixa) [A-Za-z0-9_-]{4,1600}|(?:approve|reject|rollback) SOC-\d{3,24})$/,
};
const assets = new Map([
  ['/', ['DEMO SOC.html', 'text/html; charset=utf-8']],
  ['/lab/painel.js', ['lab/painel.js', 'text/javascript; charset=utf-8']],
  ['/lab/painel.css', ['lab/painel.css', 'text/css; charset=utf-8']],
  ['/lab/dashboard.js', ['lab/dashboard.js', 'text/javascript; charset=utf-8']],
  ['/lab/assets/tcs-logo.webp', ['lab/assets/tcs-logo.webp', 'image/webp']],
  ['/lab/investigation.js', ['lab/investigation.js', 'text/javascript; charset=utf-8']],
  ['/lab/log-worker.js', ['lab/log-worker.js', 'text/javascript; charset=utf-8']],
  ['/logs/soc-demo.jsonl', ['logs/soc-demo.jsonl', 'application/x-ndjson; charset=utf-8']],
  ['/logs/soc-investigacao-205k.jsonl.gz', ['logs/soc-investigacao-205k.jsonl.gz', 'application/gzip']],
]);

function publish(event) {
  const item = { id: ++sequence, line: `id: ${sequence}\ndata: ${JSON.stringify(event)}\n\n` };
  journal.push(item);
  if (journal.length > 5000) journal.shift();
  for (const response of listeners) response.write(item.line);
}

function attach(role) {
  const socket = net.createConnection(`\\\\.\\pipe\\SOC-TIER1-${role}`);
  const channel = { socket, ready: false };
  channels.set(role, channel);
  let buffer = '';
  let handshake;
  socket.setEncoding('utf8');
  socket.on('connect', () => {
    socket.write('hello\n');
    handshake = setInterval(() => socket.write('hello\n'), 1500);
  });
  socket.on('data', (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
      if (!line.startsWith('@@SOC@@')) continue;
      try {
        const event = JSON.parse(line.slice(7));
        if (event.vm !== role) continue;
        if (event.event === 'vm.ready') {
          if (channel.ready) continue;
          channel.ready = true;
          clearInterval(handshake);
          console.log(`VM ${role} online em ${event.ip}`);
        }
        publish(event);
      } catch (error) {
        console.error(`Evento serial inválido em ${role}: ${error.message}`);
      }
    }
  });
  socket.on('error', () => socket.destroy());
  socket.on('close', () => {
    clearInterval(handshake);
    if (channel.ready) {
      publish({ timestamp: new Date().toISOString(), vm: role, event: 'vm.offline', synthetic: true });
    }
    setTimeout(() => attach(role), 1500);
  });
}

function reply(response, code) {
  response.writeHead(code).end();
}

async function handle(request, response) {
  if (request.headers.host !== `${host}:${port}`) return reply(response, 403);
  if (request.method === 'GET' && request.url === '/api/events') {
    response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' });
    response.write(': SOC Tier 1\n\n');
    for (const item of journal) {
      if (item.id > Number(request.headers['last-event-id'] || 0)) response.write(item.line);
    }
    listeners.add(response);
    response.on('close', () => listeners.delete(response));
    return;
  }
  if (request.method === 'POST' && request.url === '/api/command') {
    if (request.headers.origin !== origin || request.headers['content-type'] !== 'application/json') return reply(response, 403);
    let body = '';
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 4096) return reply(response, 413);
    }
    const data = JSON.parse(body);
    if (!data || !Object.hasOwn(commands, data.role) || typeof data.line !== 'string' || !commands[data.role].test(data.line)) {
      return reply(response, 400);
    }
    const channel = channels.get(data.role);
    if (!channel?.ready || channel.socket.destroyed) return reply(response, 503);
    channel.socket.write(`${data.line}\n`);
    return reply(response, 204);
  }
  const asset = request.method === 'GET' && assets.get(request.url);
  if (!asset) return reply(response, 404);
  const stream = createReadStream(path.join(root, asset[0]));
  stream.on('error', () => response.headersSent ? response.destroy() : reply(response, 404));
  stream.on('open', () => {
    response.writeHead(200, { 'Content-Type': asset[1], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    stream.pipe(response);
  });
}

const server = http.createServer((request, response) => {
  handle(request, response).catch(() => {
    if (!response.headersSent) reply(response, 400);
  });
});
server.listen(port, host, () => {
  for (const role of Object.keys(commands)) attach(role);
  console.log(`Painel VirtualBox em ${origin}. Mantenha esta janela aberta.`);
  if (process.argv.includes('--open')) {
    execFile('rundll32.exe', ['url.dll,FileProtocolHandler', origin], { windowsHide: true });
  }
});
