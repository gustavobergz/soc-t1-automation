const { createWriteStream } = require('node:fs');
const { pipeline } = require('node:stream/promises');
const { createGzip } = require('node:zlib');
const path = require('node:path');

const size = 205000;
const epoch = Date.UTC(2026, 10, 9, 8);
const users = ['svc_ci', 'svc_backup', 'ops_demo', 'dev_demo', 'admin_lab', 'monitor_demo'];
const paths = ['/health', '/login', '/api/status', '/reports', '/assets/app.js'];
const scenarios = [
  { at: 175000, ip: '198.51.100.27', host: 'financeiro-07', user: 'soclab', kinds: [...Array(8).fill('ssh.failed'), 'ssh.accepted', 'sudo.list'] },
  { at: 163000, ip: '203.0.113.88', host: 'bastion-02', user: 'admin_lab', kinds: Array(9).fill('ssh.failed') },
  { at: 191000, ip: '192.0.2.144', host: 'rh-04', user: 'ops_demo', kinds: ['ssh.failed', 'ssh.accepted', 'session.closed'] },
];
const background = [
  ['web.request', 'info', 'allowed', (v) => `nginx: GET ${paths[v.n % paths.length]} 200`],
  ['dns.query', 'info', 'success', (v) => `resolver: query service-${v.n % 63}.example.test A`],
  ['ssh.accepted', 'info', 'success', (v) => `sshd: Accepted publickey for ${v.user} from ${v.ip}`],
  ['session.closed', 'info', 'success', (v) => `pam: session closed for ${v.user}`],
  ['process.started', 'info', 'success', (v) => `auditd: ${v.user} started /usr/bin/${['id', 'uptime', 'date'][v.n % 3]}`],
  ['firewall.allowed', 'info', 'allowed', (v) => `firewall: ALLOW SRC=${v.ip} DPT=443 PROTO=TCP`],
  ['web.denied', 'baixa', 'denied', (v) => `nginx: POST ${paths[v.n % paths.length]} 403`],
  ['ssh.failed', 'baixa', 'failure', (v) => `sshd: Failed password for ${v.user} from ${v.ip}`],
  ['firewall.denied', 'media', 'denied', (v) => `firewall: DENY SRC=${v.ip} DPT=445 PROTO=TCP`],
  ['sudo.denied', 'media', 'denied', (v) => `sudo: ${v.user} not in sudoers; COMMAND=/usr/bin/id`],
];

function row(index) {
  const n = Math.imul(index + 101, 2654435761) >>> 0;
  const scenario = scenarios.find(({ at, kinds }) => index >= at && index < at + kinds.length * 4 && (index - at) % 4 === 0);
  const kind = scenario?.kinds[(index - scenario.at) / 4];
  const host = scenario?.host ?? `srv-${String(1 + n % 96).padStart(2, '0')}`;
  const user = scenario?.user ?? users[(n >>> 15) % users.length];
  const ip = scenario?.ip ?? `10.${4 + ((n >>> 19) % 28)}.${(n >>> 8) % 256}.${1 + n % 254}`;
  const weight = (n >>> 7) % 100;
  const preset = kind === 'sudo.list'
    ? ['sudo.list', 'alta', 'observed', (v) => `sudo: ${v.user} queried privileges with /usr/bin/sudo -l`]
    : kind ? background.find((item) => item[0] === kind)
      : background[weight < 88 ? weight % 6 : weight < 97 ? 6 + weight % 2 : 8 + weight % 2];
  const [event_type, level, outcome, format] = preset;
  const severity = scenario?.at === 163000 ? 'media' : level;
  return {
    event_id: `ARCH-${String(index + 1).padStart(6, '0')}`, timestamp: new Date(epoch + index * 250).toISOString(),
    event_type, severity, host, username: user, source_ip: ip, outcome, message: format({ n, user, ip }), synthetic: true,
  };
}

function* batches() {
  for (let start = 0; start < size; start += 1000) {
    const lines = Array.from({ length: Math.min(1000, size - start) }, (_, index) => JSON.stringify(row(start + index)));
    yield `${lines.join('\n')}\n`;
  }
}

async function main() {
  const target = process.argv[2] || path.join(__dirname, '../logs/soc-investigacao-205k.jsonl');
  const destination = createWriteStream(target);
  if (target.endsWith('.gz')) await pipeline(batches(), createGzip({ level: 9 }), destination);
  else await pipeline(batches(), destination);
  console.log(`${size} registros sintéticos em ${target}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
