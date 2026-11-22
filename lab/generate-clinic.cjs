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
  const kinds = [
    'auth.login', 'auth.login', 'auth.login', 'auth.failed',
    'ehr.record_read', 'ehr.record_read', 'ehr.record_read', 'ehr.access_denied',
    'appointment.lookup', 'appointment.lookup', 'pharmacy.order_view',
    'export.requested', 'session.closed', 'dns.query', 'backup.completed', 'iam.permission_check',
  ];
  let kind = kinds[n % kinds.length];
  if (kind === 'auth.login' && (hour < 6 || hour > 22)) kind = 'web.request';

  const profiles = {
    'auth.login': ['CLIN-IDENTIDADE-01', 'identidade', 'Login aceito no portal interno da clínica.', 'success'],
    'auth.failed': ['CLIN-IDENTIDADE-01', 'identidade', 'Falha de autenticação no portal interno da clínica.', 'denied'],
    'ehr.record_read': ['CLIN-PRONTUARIO-01', 'prontuario', 'Acesso de leitura a referência fictícia de prontuário.', 'success'],
    'ehr.access_denied': ['CLIN-PRONTUARIO-01', 'prontuario', 'Acesso ao prontuário negado pela política de atendimento.', 'denied'],
    'appointment.lookup': ['CLIN-AGENDA-01', 'agendamento', 'Consulta de agenda sem conteúdo clínico.', 'success'],
    'pharmacy.order_view': ['CLIN-FARMACIA-01', 'farmacia', 'Consulta a pedido fictício da farmácia.', 'success'],
    'export.requested': ['CLIN-PRONTUARIO-01', 'prontuario', 'Solicitação de exportação registrada para revisão.', 'denied'],
    'session.closed': ['CLIN-IDENTIDADE-01', 'identidade', 'Sessão de acesso encerrada.', 'success'],
    'dns.query': ['CLIN-DNS-01', 'infraestrutura', 'Consulta DNS originada por serviço da clínica.', 'success'],
    'backup.completed': ['CLIN-BACKUP-01', 'infraestrutura', 'Rotina de backup concluída; conteúdo não incluído no log.', 'success'],
    'iam.permission_check': ['CLIN-IAM-01', 'identidade', 'Verificação de permissão administrativa.', 'success'],
    'web.request': ['CLIN-GATEWAY-01', 'portal', 'Requisição ao portal da clínica registrada pelo gateway.', 'success'],
  };
  const [defaultHost, service, defaultMessage, defaultOutcome] = profiles[kind];
  const careAssigned = n % 5 !== 0;
  const step = block?.step || {
    kind, message: defaultMessage, count: kind === 'ehr.record_read' ? 1 : 0,
    care_assigned: careAssigned, device_known: n % 13 !== 0, shift_active: n % 9 !== 0,
    approved: kind === 'export.requested' ? false : kind === 'iam.permission_check' && n % 20 === 0,
    outcome: defaultOutcome,
  };
  const clinical = step.kind.startsWith('auth.') || step.kind.startsWith('ehr.') || step.kind.startsWith('iam.') ||
    step.kind.startsWith('appointment.') || step.kind.startsWith('pharmacy.') || step.kind.startsWith('export.') ||
    step.kind === 'change.approved';
  const host = block?.scenario.host || defaultHost;
  const record = {
    event_id: `CLIN-${String(index + 1).padStart(6, '0')}`, timestamp, event_type: step.kind,
    severity: block ? block.scenario.severity : step.kind === 'auth.failed' ? 'baixa' :
      ['ehr.access_denied', 'export.requested'].includes(step.kind) ? 'media' : 'info',
    host, service: block ? 'prontuario' : service, username: user, role,
    source_ip: block ? '10.77.0.30' : `10.77.1.${10 + n % 60}`,
    device_id: block && ['stolen_account', 'authorized_shift'].includes(block.scenario.id)
      ? 'ESTACAO-TEMPORARIA' : `ESTACAO-${user}`,
    session_id: block ? block.scenario.session : `SES-ROTINA-${user}-${Math.floor(index / 120)}`,
    sector: 'healthcare', facility_id: 'CLINICA-FICTICIA-01', application: service,
    action: step.kind, outcome: step.outcome, message: step.message, synthetic: true,
    ...(clinical && { clinical: step }), ...(block && { scenario: block.scenario.id }),
  };
  if (step.kind === 'ehr.record_read') {
    record.patient_ref = `PAC-FICT-${String(1 + n % 4000).padStart(5, '0')}`;
    record.encounter_ref = `ATD-FICT-${String(1 + n % 1200).padStart(5, '0')}`;
  }
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
