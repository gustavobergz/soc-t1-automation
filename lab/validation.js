'use strict';

globalThis.SocValidation = (() => {
  const el = (id) => document.getElementById(id);
  const percent = new Intl.NumberFormat('pt-BR', { style: 'percent', maximumFractionDigits: 1 });
  const cases = new Map();
  const actions = {
    'siem.correlated': 'Correlação', 'siem.manual_detected': 'Identificação manual', 'soar.enriched': 'Enriquecimento',
    'soar.triage_requested': 'Solicitação ao Ollama', 'soar.triaged': 'Triagem automática validada', 'soar.triage_failed': 'Triagem rejeitada',
    'soar.manual_triaged': 'Triagem manual', 'soar.approval_requested': 'Pedido de aprovação', 'soar.approval_granted': 'Aprovação concedida',
    'soar.challenged': 'Contraprova consultiva', 'soar.shadow_preview': 'Impacto previsto pelo playbook', 'panel.shadow_preview': 'Simulação no painel',
    'soar.approval_rejected': 'Aprovação rejeitada', 'soar.policy_denied': 'Política impediu a ação', 'soar.monitor_only': 'Acompanhamento',
    'endpoint.block_applied': 'Bloqueio HTTP aplicado', 'soar.rollback_requested': 'Desbloqueio solicitado', 'endpoint.block_released': 'Origem liberada',
  };
  const select = el('audit-run');
  let actualBenchmark = false;
  let selectedRun;

  function empty(tbody, message) {
    const cell = tbody.insertRow().insertCell();
    cell.colSpan = 4;
    cell.textContent = message;
  }

  function renderAudit() {
    const list = el('audit-rows');
    const run = cases.get(select.value);
    list.replaceChildren();
    if (!run) {
      el('audit-source').textContent = 'Execute uma rodada para gerar a trilha.';
      empty(list, 'Nenhum registro selecionado.');
      return;
    }
    el('audit-source').textContent = run.historical ? 'Amostra de validação do laboratório' : 'Rodada desta sessão';
    for (const event of run.events) {
      const row = list.insertRow();
      row.insertCell().textContent = event.timestamp.slice(11, 23);
      const detail = document.createElement('button');
      detail.type = 'button';
      detail.className = 'link-button';
      detail.textContent = actions[event.event];
      detail.addEventListener('click', () => SocLogs.showDetails(event));
      row.insertCell().append(detail);
      const provider = event.provider?.startsWith('fixture local') ? 'fixture' : event.provider;
      row.insertCell().textContent = event.actor || event.approved_by || provider || event.vm;
      row.insertCell().textContent = event.evidence_ids?.length ?? event.result?.evidence_ids?.length ?? '—';
    }
  }

  function updateRuns() {
    const runs = [...cases.entries()].sort(([, a], [, b]) => Number(a.historical) - Number(b.historical) || b.start.localeCompare(a.start));
    select.replaceChildren(...runs.map(([id, item]) => new Option(`${id} · ${item.historical ? 'amostra' : 'sessão'}`, id)));
    if (!runs.length) select.append(new Option('Nenhuma rodada', ''));
    select.value = selectedRun || runs[0]?.[0] || '';
    renderAudit();
  }

  function renderBenchmark(event, historical) {
    if (historical && actualBenchmark) return;
    if (!historical) actualBenchmark = true;
    el('benchmark-state').textContent = historical ? 'Resultado da amostra de validação. Execute novamente para reproduzir.' : 'Avaliação executada nesta sessão pela VM SIEM.';
    el('benchmark-fp').textContent = `FP ${event.counts.fp} · ${percent.format(event.false_positive_rate)}`;
    el('benchmark-fn').textContent = `FN ${event.counts.fn} · ${percent.format(event.false_negative_rate)}`;
    el('benchmark-confusion').textContent = `VP ${event.counts.tp} · VN ${event.counts.tn}`;
    const list = el('benchmark-cases');
    list.replaceChildren();
    for (const example of event.cases) {
      const row = list.insertRow();
      for (const value of [example.scenario, example.ground_truth ? 'Ameaça' : 'Benigno', example.detected ? 'Sinalizou' : 'Sem alerta', { tp: 'VP', tn: 'VN', fp: 'FP', fn: 'FN' }[example.outcome]]) {
        row.insertCell().textContent = value;
      }
    }
  }

  function ingest(event, historical = false) {
    if (event.event === 'siem.benchmark') renderBenchmark(event, historical);
    if (!Object.hasOwn(actions, event.event) || !event.run) return;
    if (!cases.has(event.run)) cases.set(event.run, { historical, start: event.timestamp, events: [] });
    cases.get(event.run).events.push(event);
    if (!historical) updateRuns();
  }

  function openAudit(run) {
    selectedRun = run;
    updateRuns();
    location.hash = '#validacao';
  }

  select.addEventListener('change', () => {
    selectedRun = select.value;
    renderAudit();
  });
  globalThis.SocDashboard?.sampleRecords.then((events) => {
    for (const event of events) ingest(event, true);
    updateRuns();
  });

  return { ingest, openAudit };
})();
