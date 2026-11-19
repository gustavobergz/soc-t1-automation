const { execFile } = require('node:child_process');
const { createReadStream } = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const ollama = require('./ollama.cjs');
const { createJournal, provenance } = require('./journal.cjs');

const host = '127.0.0.1';
const port = 8771;
const origin = `http://${host}:${port}`;
const root = path.resolve(__dirname, '..');
const runtimeProvenance = provenance(root);
const auditJournal = createJournal(root, runtimeProvenance.manifest_sha256);
const channels = new Map();
const listeners = new Set();
const journal = [];
let sequence = 0;

const commands = {
  manager: /^(?:benchmark(?:-clinic)?|manual-detect SOC-\d{3,24} SOC-\d{3,24}-\d{2,4}(?:,SOC-\d{3,24}-\d{2,4}){0,29})$/,
  victim: /^prepare SOC-\d{3,}(?: (?:stolen_account|data_export|privilege_change|authorized_shift))?$/,
  attacker: /^(?:run SOC-\d{3,} (?:manual|auto|failure|llm)(?: (?:stolen_account|data_export|privilege_change|authorized_shift))?|probe SOC-\d{3,} (?:pending|contained|released|denied|rejected|monitoring|legitimate))$/,
  soar: /^(?:manual-triage SOC-\d{3,24} (?:alta|media|baixa) [A-Za-z0-9_-]{4,1600}|(?:approve|reject|rollback) SOC-\d{3,24})$/,
};
const assets = new Map([
  ['/', ['DEMO SOC.html', 'text/html; charset=utf-8']],
  ['/lab/assets/soc-shield.svg', ['lab/assets/soc-shield.svg', 'image/svg+xml']],
  ['/lab/painel.js', ['lab/painel.js', 'text/javascript; charset=utf-8']],
  ['/lab/metrics.js', ['lab/metrics.js', 'text/javascript; charset=utf-8']],
  ['/lab/runtime-connector.js', ['lab/runtime-connector.js', 'text/javascript; charset=utf-8']],
  ['/lab/historical-results.js', ['lab/historical-results.js', 'text/javascript; charset=utf-8']],
  ['/lab/painel.css', ['lab/painel.css', 'text/css; charset=utf-8']],
  ['/lab/dashboard.js', ['lab/dashboard.js', 'text/javascript; charset=utf-8']],
  ['/lab/validation.js', ['lab/validation.js', 'text/javascript; charset=utf-8']],
  ['/lab/review.js', ['lab/review.js', 'text/javascript; charset=utf-8']],
  ['/lab/analysis.js', ['lab/analysis.js', 'text/javascript; charset=utf-8']],
  ['/lab/arena.js', ['lab/arena.js', 'text/javascript; charset=utf-8']],
  ['/lab/clinic.js', ['lab/clinic.js', 'text/javascript; charset=utf-8']],
  ['/lab/clinic.json', ['lab/clinic.json', 'application/json; charset=utf-8']],
  ['/lab/investigation.js', ['lab/investigation.js', 'text/javascript; charset=utf-8']],
  ['/lab/log-worker.js', ['lab/log-worker.js', 'text/javascript; charset=utf-8']],
  ['/logs/soc-demo.jsonl', ['logs/soc-demo.jsonl', 'application/x-ndjson; charset=utf-8']],
  ['/logs/clinica-demo.jsonl', ['logs/clinica-demo.jsonl', 'application/x-ndjson; charset=utf-8']],
  ['/logs/clinica-investigacao-205k.jsonl.gz', ['logs/clinica-investigacao-205k.jsonl.gz', 'application/gzip']],
  ['/DOCUMENTACAO_SIMULACAO.md', ['DOCUMENTACAO_SIMULACAO.md', 'text/plain; charset=utf-8']],
  ['/logs/soc-investigacao-205k.jsonl.gz', ['logs/soc-investigacao-205k.jsonl.gz', 'application/gzip']],
]);

function publish(event) {
  auditJournal.append(event, 'vm').catch((error) => console.error('Gravação da auditoria pendente:', error.message));
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
        if (role === 'soar' && event.event === 'soar.triage_requested' && /^SOC-\d{3,24}$/.test(event.run)) {
          ollama.triage(event).then((result) => {
            if (channel.ready && !socket.destroyed) {
              const reply = Buffer.from(JSON.stringify(result)).toString('base64url');
              socket.write(`llm-result ${event.run} ${reply}\n`);
            }
          });
        }
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
  if (request.method === 'GET' && request.url === '/api/capabilities') {
    const health = await ollama.health();
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify({ transport: 'virtualbox', journal: true, ollama_model: ollama.model, ollama: health, provenance: runtimeProvenance }));
    return;
  }
  if (request.method === 'GET' && request.url === '/api/provenance') {
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(runtimeProvenance));
    return;
  }
  if (request.method === 'GET' && request.url === '/api/journal-status') {
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(auditJournal.status()));
    return;
  }
  if (request.method === 'POST' && request.url === '/api/journal') {
    if (request.headers.origin !== origin || request.headers['content-type'] !== 'application/json') return reply(response, 403);
    let body = '';
    for await (const chunk of request) { body += chunk; if (Buffer.byteLength(body) > 512000) return reply(response, 413); }
    const payload = JSON.parse(body);
    if (!Array.isArray(payload.events) || payload.events.length > 60 || payload.events.some((item) =>
      !item || typeof item.id !== 'string' || !/^[a-zA-Z0-9_-]{8,100}$/.test(item.id) || !item.event ||
      item.event.vm !== 'panel' || !['panel.metrics', 'panel.run_started', 'panel.shadow_preview', 'panel.run_finished'].includes(item.event.event) ||
      !/^SOC-\d{3,24}$/.test(item.event.run) || !Number.isFinite(Date.parse(item.event.timestamp)))) return reply(response, 400);
    for (const item of payload.events) await auditJournal.append(item.event, 'panel', item.id);
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(auditJournal.status()));
    return;
  }
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
  const asset = request.method === 'GET' && assets.get(new URL(request.url, origin).pathname);
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
