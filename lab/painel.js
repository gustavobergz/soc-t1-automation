'use strict';

const $ = (id) => document.getElementById(id);
const records = [];
const ready = new Set();
const vmNames = { attacker: 'Atacante', victim: 'Endpoint', manager: 'SIEM', soar: 'SOAR', panel: 'Painel' };
const steps = ['detect', 'enrich', 'triage', 'approve-step', 'contain', 'ticket'];
const defaults = Object.fromEntries(steps.map((step) => [step, $(step).querySelector('p').textContent]));
const seconds = new Intl.NumberFormat('pt-BR', { minimumFractionDigits: 1, maximumFractionDigits: 2 });
const percentage = new Intl.NumberFormat('pt-BR', { style: 'percent', maximumFractionDigits: 1 });
const utcTime = (value) => `${new Date(value).toISOString().slice(11, 19)} UTC`;
const automation = new Map();
let lab;
let current;
let sequence = 0;
let filter = 'all';
let timeout;
let llmConfigured = false;
const virtualBox = location.origin === 'http://127.0.0.1:8771';

function status(message, error = false) {
  $('status').textContent = message;
  $('status').classList.toggle('error', error);
}

function updateActions() {
  const online = Boolean(lab && ready.size === 4);
  const phase = current?.phase;
  for (const id of ['manual', 'auto', 'failure', 'llm']) $(id).disabled = !online || (phase && phase !== 'done');
  $('llm').hidden = !llmConfigured;
  $('benchmark').disabled = !lab || !ready.has('manager');
  for (const [id, show] of Object.entries({
    'manual-detect': phase === 'manual-detect', 'manual-triage': phase === 'manual-triage',
    approve: phase === 'pending', reject: phase === 'pending',
    rollback: phase === 'blocked' && (current.verified || current.error),
  })) {
    $(id).hidden = !show;
    if (id !== 'manual-triage') $(id).disabled = !online;
  }
  $('save-triage').disabled = !online;
  $('view-triage').hidden = !current?.triageAudit;
  $('view-audit').hidden = !current?.auditAvailable;
  updateEvidence();
  $('export').disabled = records.length === 0;
}

function canMark() {
  return current?.mode === 'manual' && ['collecting', 'manual-detect'].includes(current.phase);
}

function updateEvidence() {
  const count = current?.evidence.size || 0;
  $('live-evidence').hidden = current?.mode !== 'manual';
  $('live-evidence-count').textContent = `${count} ${count === 1 ? 'evidência marcada' : 'evidências marcadas'}`;
  $('live-only').disabled = count === 0 && !current?.onlyEvidence;
  $('live-only').setAttribute('aria-pressed', String(Boolean(current?.onlyEvidence)));
  $('live-only').textContent = current?.onlyEvidence ? 'Ver todos' : 'Ver marcadas';
  $('manual-detect').disabled = ready.size !== 4 || count === 0;
}

function toggleEvidence(id) {
  if (!canMark()) return;
  if (current.evidence.has(id)) current.evidence.delete(id);
  else current.evidence.add(id);
  updateEvidence();
  if (current.onlyEvidence) showEvents();
  else {
    const check = document.getElementById(`evidence-${id}`);
    if (check) check.checked = current.evidence.has(id);
  }
}

function vmState(role, label, blocked = false) {
  const card = document.querySelector(`[data-vm="${role}"]`);
  card.querySelector('.vm-state').textContent = label;
  card.classList.toggle('ready', ready.has(role));
  card.classList.toggle('blocked', blocked);
  globalThis.SocDashboard?.machine(role, label, ready.size, ready.has(role), blocked);
}

function setStep(id, message, done = true) {
  $(id).querySelector('p').textContent = message;
  $(id).classList.toggle('done', done);
}

function showEvents() {
  const list = $('events');
  const matches = current ? records.filter((event) => event.run === current.id && (current.onlyEvidence
    ? event.event === 'siem.raw' && current.evidence.has(event.event_id)
    : filter === 'all' || filter === event.vm)) : [];
  list.replaceChildren();
  if (!matches.length) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.textContent = current ? 'Nenhum evento para este filtro.' : 'Inicie uma rodada para acompanhar os eventos aqui.';
    list.append(empty);
    return;
  }
  for (const event of matches.reverse()) {
    const row = document.createElement('li');
    row.className = 'event';
    const selection = document.createElement('span');
    const selectable = event.event === 'siem.raw' && current.mode === 'manual';
    if (selectable) {
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = `evidence-${event.event_id}`;
      checkbox.checked = current.evidence.has(event.event_id);
      checkbox.disabled = !canMark();
      checkbox.setAttribute('aria-label', `Marcar ${event.event_id} como evidência`);
      checkbox.addEventListener('change', () => toggleEvidence(event.event_id));
      selection.append(checkbox);
    }
    const time = document.createElement('time');
    time.dateTime = event.timestamp;
    time.textContent = event.timestamp.slice(11, 23);
    const origin = document.createElement('span');
    origin.className = 'origin';
    origin.textContent = vmNames[event.vm];
    const description = document.createElement('span');
    const type = document.createElement('button');
    type.type = 'button';
    type.className = 'log-link';
    type.textContent = event.kind || event.event;
    type.addEventListener('click', () => SocLogs.showDetails(event, {
      selected: () => current?.evidence.has(event.event_id),
      toggle: selectable && canMark() ? () => toggleEvidence(event.event_id) : null,
    }));
    description.append(type, event.message);
    row.append(selection, time, origin, description);
    list.append(row);
  }
}

function elapsed(from, to) {
  if (from === undefined || to === undefined) return null;
  return Math.max(0, Math.round(to - from));
}

function metrics() {
  const { started, detected, triaged, pending, approved, blocked } = current.marks;
  return {
    raw_events: current.rawCount, incidents: Number(detected !== undefined), detection_ms: elapsed(started, detected),
    triage_ms: elapsed(detected, triaged), approval_ms: elapsed(pending, approved), response_ms: elapsed(detected, blocked),
  };
}

function showMetrics() {
  if (current.mode === 'failure') return;
  const result = metrics();
  const cells = $(`metrics-${current.mode === 'llm' ? 'auto' : current.mode}`).querySelectorAll('td');
  Object.values(result).forEach((value, index) => {
    cells[index].textContent = value === null ? '—' : index < 2 ? String(value) : `${seconds.format(value / 1000)} s`;
  });
}

function showSessionMetrics() {
  const measured = records.filter((event) => event.event === 'panel.metrics' && event.response_ms !== null);
  for (const [mode, label] of [['manual', 'manual'], ['auto', 'assistido']]) {
    const values = measured.filter((event) => mode === 'manual' ? event.mode === 'manual' : ['auto', 'llm'].includes(event.mode));
    const mean = values.length ? values.reduce((sum, event) => sum + event.response_ms, 0) / values.length : null;
    $(`mttr-${mode}`).textContent = `MTTR ${label} ${mean === null ? '—' : `${seconds.format(mean / 1000)} s (n=${values.length})`}`;
  }
  const automated = [...automation.values()].filter(Boolean).length;
  $('automation-rate').textContent = `Automação elegível ${automation.size ? `${percentage.format(automated / automation.size)} (${automated}/${automation.size})` : '—'}`;
}

function recordMetrics(outcome) {
  if (current.measured) return;
  current.measured = true;
  records.push({ timestamp: new Date().toISOString(), vm: 'panel', event: 'panel.metrics', run: current.id, mode: current.mode,
    synthetic: true, message: 'Métricas observadas no painel para esta rodada.', outcome, ...metrics(),
    automation_eligible: automation.has(current.id), automatic_triage: automation.get(current.id) === true });
  showSessionMetrics();
}

function finish(message, outcome) {
  clearTimeout(timeout);
  current.phase = 'done';
  recordMetrics(outcome);
  status(`${current.id} · ${message}`, outcome === 'error');
  showEvents();
  updateActions();
}

function operationError(message) {
  if (current.marks.blocked !== undefined && !current.released) {
    current.phase = 'blocked';
    current.error = true;
    status(`${current.id} · ${message} O bloqueio expira na vítima.`, true);
    updateActions();
  } else {
    finish(message, 'error');
  }
}

function expectEvent(delay = 30000) {
  clearTimeout(timeout);
  timeout = setTimeout(() => operationError('Tempo limite na comunicação com as VMs.'), delay);
}

async function command(role, line) {
  try {
    await lab.command(role, [line[0], current.id, ...line.slice(1)].join(' '));
  } catch (error) {
    operationError(error.message);
  }
}

function manualStep(role, ...action) {
  current.phase = 'waiting';
  updateActions();
  expectEvent();
  command(role, action);
}

function probe(phase) {
  expectEvent();
  command('attacker', ['probe', phase]);
}

function checkContained() {
  if (current.verified && current.notified) {
    clearTimeout(timeout);
    recordMetrics('contained');
    status(`${current.id} · Bloqueio verificado. Desbloqueie agora ou aguarde a expiração.`);
  }
  if (current.verified) {
    setStep('contain', `${current.ttl} s de bloqueio · atacante HTTP 403${current.control ? ' · controle HTTP 204' : ''}.`);
  }
}

function checkProbe(event) {
  const expected = event.phase === 'contained' ? 403 : 204;
  if (event.http_status !== expected) {
    operationError(`Sonda ${event.phase} retornou HTTP ${event.http_status}, esperado ${expected}.`);
    return;
  }
  switch (event.phase) {
    case 'pending':
      clearTimeout(timeout);
      current.phase = 'pending';
      setStep('approve-step', `Aguardando analista-demo · sonda antes da aprovação HTTP 204 · validade de ${current.ttl} s.`, false);
      status(`${current.id} · Aguardando aprovação humana. A origem ainda está liberada.`);
      break;
    case 'contained':
      current.verified = true;
      vmState('attacker', 'Origem contida', true);
      checkContained();
      break;
    case 'released':
      setStep('contain', `${current.released === 'rollback' ? 'Desbloqueio manual' : 'Expiração automática'} verificado · atacante HTTP 204.`);
      finish('Origem liberada e verificada com HTTP 204.', 'released');
      break;
    case 'denied':
      setStep('approve-step', 'Política impediu a ação · sonda HTTP 204.');
      finish('Política de falha segura verificada com HTTP 204.', 'denied');
      break;
    case 'rejected':
      finish('Decisão de rejeição verificada com HTTP 204.', 'rejected');
      break;
    case 'monitoring':
      setStep('contain', 'Acompanhamento · atacante recebeu HTTP 204.');
      finish('Caso registrado para acompanhamento. Origem liberada (HTTP 204).', 'monitoring');
      break;
  }
}

function onEvent(event) {
  records.push(event);
  globalThis.SocDashboard?.ingest(event);
  globalThis.SocValidation?.ingest(event);
  if (event.event === 'vm.ready' || event.event === 'vm.offline') {
    if (event.event === 'vm.ready') {
      ready.add(event.vm);
      vmState(event.vm, 'Online');
    } else {
      ready.delete(event.vm);
      vmState(event.vm, 'Desconectada');
    }
    if (!current) {
      if (ready.size === 4) {
        clearTimeout(timeout);
        status('Quatro VMs online. Comece pela rodada manual.');
      } else {
        status(`Inicializando as VMs · ${ready.size} de 4 online.`);
      }
    }
    updateActions();
    return;
  }
  if (!current || event.run !== current.id) return;

  const now = performance.now();
  switch (event.event) {
    case 'endpoint.prepared':
      command('attacker', ['run', current.mode]);
      break;
    case 'attack.started':
      current.marks.started = now;
      break;
    case 'siem.raw':
      current.rawCount++;
      break;
    case 'attack.finished':
      if (current.mode === 'manual' && current.phase === 'collecting') {
        clearTimeout(timeout);
        current.phase = 'manual-detect';
        status(`${current.id} · Examine os eventos do SIEM e marque os registros que sustentam o incidente.`);
      }
      break;
    case 'siem.manual_detected':
    case 'siem.correlated':
      current.marks.detected = now;
      current.auditAvailable = true;
      $('severity').textContent = event.incident;
      setStep('detect', event.rule_id
        ? `Regra ${event.rule_id} · ${event.failures} falhas em até ${event.failure_window_seconds || 120} s, login aceito e sudo -l para ${event.username}.`
        : `${event.evidence_ids.length} evidências vinculadas · ${event.failures} falhas selecionadas para ${event.username}.`);
      break;
    case 'siem.selection_rejected':
      clearTimeout(timeout);
      current.phase = 'manual-detect';
      status(event.message, true);
      break;
    case 'soar.manual_started':
      clearTimeout(timeout);
      current.phase = 'manual-triage';
      status(`${current.id} · Escolha a severidade e justifique a classificação.`);
      break;
    case 'soar.enriched':
      automation.set(event.run, false);
      showSessionMetrics();
      setStep('enrich', `AbuseIPDB simulado ${event.reputation}/100 · VirusTotal não consultado · ${event.mitre.join(' e ')}. T1068 não atribuído.`);
      break;
    case 'soar.triage_requested':
      expectEvent(50000);
      status(`${current.id} · Aguardando triagem do Ollama local.`);
      break;
    case 'soar.triage_failed':
      current.triageAudit = event;
      break;
    case 'soar.manual_triaged':
    case 'soar.triaged':
      current.marks.triaged = now;
      current.triageAudit = event;
      if (event.event === 'soar.triaged' && event.validation === 'passed') {
        automation.set(event.run, true);
        showSessionMetrics();
      }
      $('severity').classList.add(`severity-${event.severity}`);
      $('severity').textContent = `SEVERIDADE ${SocLogs.severity(event.severity).toUpperCase()}`;
      setStep('triage', event.result ? `${event.simulation ? 'Simulada' : 'Ollama local'} · JSON validado · ${event.result.uncertainty}` : event.justification);
      break;
    case 'soar.triage_rejected':
      clearTimeout(timeout);
      current.phase = 'manual-triage';
      status(event.message, true);
      break;
    case 'soar.monitor_only':
      setStep('approve-step', event.reason === 'insufficient_evidence'
        ? 'A seleção não demonstra a sequência completa exigida para conter.'
        : 'A severidade registrada encaminha o caso para acompanhamento.');
      probe('monitoring');
      break;
    case 'soar.approval_requested':
      current.ttl = event.ttl_seconds;
      current.marks.pending = now;
      probe('pending');
      break;
    case 'soar.approval_granted':
      current.marks.approved = now;
      setStep('approve-step', `${event.actor} aprovou às ${utcTime(event.timestamp)} com ${event.evidence_ids.length} evidências.`);
      break;
    case 'soar.approval_rejected':
      setStep('approve-step', `${event.actor} rejeitou a contenção.`);
      probe('rejected');
      break;
    case 'soar.policy_denied':
      $('severity').textContent = 'AÇÃO IMPEDIDA';
      setStep('triage', event.message, false);
      probe('denied');
      break;
    case 'endpoint.block_applied':
      current.phase = 'blocked';
      current.marks.blocked = now;
      $('block-deadline').hidden = false;
      $('block-deadline').textContent = `Prazo de ${event.ttl_seconds} s · expiração prevista às ${utcTime(event.expires_at)}.`;
      setStep('contain', `${event.source_ip} bloqueado por ${event.ttl_seconds} s · verificando a sonda.`, false);
      probe('contained');
      break;
    case 'attack.probe':
      checkProbe(event);
      break;
    case 'soar.control_allowed':
      current.control = true;
      if (!current.released) checkContained();
      break;
    case 'soar.ticket':
      current.ticket = event.ticket;
      setStep('ticket', `${event.ticket} criado com evidências e decisão do analista.`);
      break;
    case 'soar.notification':
      current.notified = true;
      setStep('ticket', `${current.ticket} · ${event.channel} (simulado) · auditoria disponível em JSONL.`);
      if (!current.released) checkContained();
      break;
    case 'endpoint.block_released':
      current.released = event.reason;
      current.phase = 'waiting';
      $('block-deadline').textContent = `Origem liberada às ${utcTime(event.timestamp)} por ${event.reason === 'rollback' ? 'desbloqueio manual' : 'expiração automática'}.`;
      vmState('attacker', 'Online');
      probe('released');
      break;
    case 'lab.error':
      operationError(event.message);
      break;
  }
  showMetrics();
  showEvents();
  updateActions();
}

function selectFilter(value) {
  filter = value;
  if (current) current.onlyEvidence = false;
  for (const button of document.querySelectorAll('[data-filter]')) {
    button.setAttribute('aria-pressed', String(button.dataset.filter === value));
  }
  showEvents();
  updateEvidence();
}

function run(mode) {
  current = { id: `SOC-${Date.now()}${++sequence}`, mode, phase: 'collecting', rawCount: 0, marks: {}, evidence: new Set() };
  vmState('attacker', 'Online');
  $('severity').textContent = mode === 'manual' ? 'MODO MANUAL' : 'EM ESPERA';
  $('severity').className = 'pill';
  $('manual-triage').reset();
  $('block-deadline').hidden = true;
  for (const step of steps) setStep(step, defaults[step], false);
  selectFilter(mode === 'manual' ? 'manager' : 'all');
  status(`${current.id} · Preparando a vítima para a rodada.`);
  updateActions();
  showMetrics();
  expectEvent();
  command('victim', ['prepare']);
}

for (const id of ['manual', 'auto', 'failure', 'llm']) $(id).addEventListener('click', () => run(id));
$('view-triage').addEventListener('click', () => SocLogs.showDetails(current.triageAudit));
$('view-audit').addEventListener('click', () => globalThis.SocValidation?.openAudit(current.id));
$('benchmark').addEventListener('click', async () => {
  try {
    await lab.command('manager', 'benchmark');
    location.hash = '#validacao';
  } catch (error) {
    status(`Avaliação indisponível. ${error.message}`, true);
  }
});
for (const id of ['approve', 'reject', 'rollback']) {
  $(id).addEventListener('click', () => manualStep('soar', id));
}
$('manual-detect').addEventListener('click', () => {
  if (current.evidence.size) manualStep('manager', 'manual-detect', [...current.evidence].join(','));
});
$('manual-triage').addEventListener('submit', (event) => {
  event.preventDefault();
  if (current?.phase !== 'manual-triage') return;
  const reason = $('manual-reason').value.trim();
  if (reason.length < 3) {
    status('Escreva uma justificativa de pelo menos 3 caracteres.', true);
    return;
  }
  const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(reason))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  manualStep('soar', 'manual-triage', $('manual-severity').value, encoded);
});
$('live-only').addEventListener('click', () => {
  current.onlyEvidence = !current.onlyEvidence;
  updateEvidence();
  showEvents();
});
for (const button of document.querySelectorAll('[data-filter]')) {
  button.addEventListener('click', () => selectFilter(button.dataset.filter));
}
$('export').addEventListener('click', () => {
  const content = `${records.map((event) => JSON.stringify(event)).join('\n')}\n`;
  const url = URL.createObjectURL(new Blob([content], { type: 'application/x-ndjson' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'soc-demo-sessao.jsonl';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    script.onload = resolve;
    script.onerror = reject;
    document.head.append(script);
  });
}

function useVirtualBox() {
  $('runtime').textContent = 'VIRTUALBOX · REDE ISOLADA';
  fetch('/api/capabilities').then((response) => response.ok ? response.json() : null).then((capabilities) => {
    llmConfigured = Boolean(capabilities?.ollama_model);
    if (llmConfigured) $('llm-status').textContent = `Ollama local configurado · ${capabilities.ollama_model}`;
    updateActions();
  }).catch(() => {});
  const events = new EventSource('/api/events');
  events.onmessage = ({ data }) => onEvent(JSON.parse(data));
  events.onerror = () => status('Painel desconectado. Mantenha o iniciador VirtualBox aberto.', true);
  return {
    async command(role, line) {
      const response = await fetch('/api/command', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role, line }),
      });
      if (!response.ok) throw new Error(`A VM ${vmNames[role]} recusou a operação (${response.status}).`);
    },
  };
}

async function boot() {
  timeout = setTimeout(() => status('A inicialização está demorando. Verifique o iniciador ou mantenha a aba ativa.', true), 75000);
  try {
    if (!virtualBox) {
      $('runtime').textContent = 'V86 · NO NAVEGADOR';
      await Promise.all(['lab/runtime/worker.js', 'lab/runtime/images.js', 'lab/emulator.js'].map(loadScript));
      lab = await SocEmulator.start(SOC_IMAGES, SOC_WORKER, onEvent, (role, error) => {
        console.error(role, error);
        status(`Falha na VM ${vmNames[role]}. Reabra o arquivo no Chrome ou Edge.`, true);
      });
    } else {
      lab = useVirtualBox();
    }
    updateActions();
  } catch (error) {
    clearTimeout(timeout);
    console.error(error);
    status('Falha ao iniciar a demo. Confira se as pastas lab e logs estão junto do painel.', true);
  }
}

showEvents();
if (!virtualBox) $('runtime').textContent = 'V86 · NO NAVEGADOR';
if (virtualBox || !$('live-view').hidden) {
  boot();
} else {
  const openLive = () => {
    if ($('live-view').hidden) return;
    window.removeEventListener('hashchange', openLive);
    boot();
  };
  window.addEventListener('hashchange', openLive);
}
