const { createWriteStream } = require('node:fs');
const { pipeline } = require('node:stream/promises');
const { createGzip } = require('node:zlib');
const path = require('node:path');
const scenarios = require('./clinic.json');

const total = 205000;
const epoch = Date.UTC(2026, 10, 11, 13);
const accounts = [
  ['MED-017', 'medica'], ['MED-022', 'medico'], ['ENF-009', 'enfermagem'],
  ['REC-004', 'recepcao'], ['ADM-002', 'administracao'], ['SVC-BKP', 'servico'],
];
const blocks = new Map();
for (const [index, scenario] of scenarios.entries()) {
  let offset = 0;
  for (const step of scenario.steps) {
    const copies = step.kind === 'ehr.record_read' ? step.count : 1;
    for (let copy = 0; copy < copies; copy++) {
      blocks.set([175000, 182000, 190000, 196000][index] + offset++, {
        scenario, step: { ...step, ...(step.kind === 'ehr.record_read' && { count: 1 }) },
      });
    }
  }
}

function row(index) {
  const n = Math.imul(index + 113, 2654435761) >>> 0;
  const block = blocks.get(index);
  const [user, role] = block ? [block.scenario.user, block.scenario.role] : accounts[(n >>> 15) % accounts.length];
  const timestamp = new Date(epoch + index * 350).toISOString();
  const hour = new Date(timestamp).getUTCHours();
  let kind = ['web.request', 'auth.login', 'ehr.record_read', 'session.closed', 'dns.query', 'backup.completed', 'auth.failed', 'ehr.access_denied'][n % 8];
  if (kind === 'auth.login' && (hour < 11 || hour > 22)) kind = 'web.request';
  const step = block?.step || {
    kind, message: `Atividade sintética da clínica: ${kind}.`, count: kind === 'ehr.record_read' ? 1 : 0,
    care_assigned: true, device_known: true, shift_active: true, approved: false,
    outcome: ['auth.failed', 'ehr.access_denied'].includes(kind) ? 'denied' : 'success',
  };
  const clinical = step.kind.startsWith('auth.') || step.kind.startsWith('ehr.') || step.kind.startsWith('iam.') || step.kind === 'change.approved';
  const record = {
    event_id: `CLIN-${String(index + 1).padStart(6, '0')}`, timestamp, event_type: step.kind,
    severity: block ? block.scenario.severity : step.kind === 'auth.failed' ? 'baixa' : step.outcome === 'denied' ? 'media' : 'info',
    host: block?.scenario.host || 'CLINICA-PEP-01', username: user, role,
    source_ip: block ? '10.77.0.30' : `10.77.1.${10 + n % 60}`,
    device_id: block && ['stolen_account', 'authorized_shift'].includes(block.scenario.id) ? 'ESTACAO-TEMPORARIA' : `ESTACAO-${user}`,
    session_id: block ? block.scenario.session : `SES-ROTINA-${user}-${Math.floor(index / 120)}`,
    sector: 'healthcare', application: 'prontuario-ficticio', outcome: step.outcome, message: step.message, synthetic: true,
    ...(clinical && { clinical: step }), ...(block && { scenario: block.scenario.id }),
  };
  if (step.kind === 'ehr.record_read') record.patient_ref = `PAC-FICT-${String(1 + n % 4000).padStart(5, '0')}`;
  return record;
}

function* batches() {
  for (let start = 0; start < total; start += 500) {
    yield Array.from({ length: Math.min(500, total - start) }, (_, index) => JSON.stringify(row(start + index))).join('\n') + '\n';
  }
}

async function main() {
  const target = process.argv[2] || path.join(__dirname, '../logs/clinica-investigacao-205k.jsonl.gz');
  if (target.endsWith('.gz')) await pipeline(batches(), createGzip({ level: 9 }), createWriteStream(target));
  else await pipeline(batches(), createWriteStream(target));
  console.log(`${total} eventos inteiramente fictícios da clínica em ${target}`);
}

if (require.main === module) main().catch((error) => { console.error(error); process.exitCode = 1; });
module.exports = { row, total };
