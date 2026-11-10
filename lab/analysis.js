'use strict';

globalThis.SocAnalysis = (() => {
  const el = (id) => document.getElementById(id);
  const runSelect = el('analysis-run');
  const runs = new Map();
  const memoryKey = 'soc-tier1-reviewed-runs-v1';
  const memory = new Map();
  const resolutionLabels = SocReview.dispositions;
  const verdictLabels = { contradiction: 'Possível contradição', missing_evidence: 'Evidência insuficiente', no_clear_contradiction: 'Sem contradição clara' };
  const referenceSequence = ['failure', 'login', 'privilege'];
  const demonstrations = [
    { id: 'DEMO-117', title: 'Rotina autorizada de manutenção', resolution: 'falso_positivo', context: { sequence: referenceSequence, failures: 6, host: 'endpoint-01', user: 'soclab', mitre: ['T1110.001', 'T1078.003'] } },
    { id: 'DEMO-104', title: 'Validação autorizada de credencial', resolution: 'falso_positivo', context: { sequence: referenceSequence, failures: 8, host: 'endpoint-02', user: 'ops_demo', mitre: ['T1110.001'] } },
    { id: 'DEMO-092', title: 'Abuso confirmado após revisão', resolution: 'confirmado', context: { sequence: referenceSequence, failures: 7, host: 'endpoint-03', user: 'svc_demo', mitre: ['T1110.001', 'T1078.003'] } },
  ];
  let selected = '';
  let position = 0;
  let timer;
  let ordered = [];
  let preview;
  let review;

  try {
    for (const item of JSON.parse(localStorage.getItem(memoryKey) || '[]')) {
      if (typeof item?.id === 'string' && Object.hasOwn(resolutionLabels, item.resolution) && Array.isArray(item.context?.sequence)) memory.set(item.id, item);
    }
  } catch { /* An unavailable store leaves the example history available. */ }

  function fillList(id, messages) {
    const items = messages.map((message) => {
      const item = document.createElement('li');
      item.textContent = message;
      return item;
    });
    el(id).replaceChildren(...items);
  }

  function runLabel(run) {
    const prefix = { sample: 'amostra', session: 'sessão', import: 'importada', case: 'caso local' };
    return `${run.title || run.id} · ${prefix[run.source]}`;
  }

  function updateRuns() {
    const choices = [...runs.values()].sort((a, b) => (Number(b.source === 'session') - Number(a.source === 'session')) || b.timestamp.localeCompare(a.timestamp));
    runSelect.replaceChildren(...choices.map((run) => new Option(runLabel(run), run.id)));
    if (!choices.length) runSelect.append(new Option('Nenhuma rodada', ''));
    if (!runs.has(selected)) selected = choices[0]?.id || '';
    runSelect.value = selected;
  }

  function ingest(event, source = 'session') {
    if (!event || typeof event.run !== 'string' || !/^SOC-\d{3,24}$/.test(event.run) || typeof event.event !== 'string' ||
        typeof event.timestamp !== 'string' || !Number.isFinite(Date.parse(event.timestamp))) return;
    const existing = runs.get(event.run);
    if (existing && existing.source !== source) {
      if (source !== 'session') return;
      runs.delete(event.run);
    }
    if (!runs.has(event.run)) {
      runs.set(event.run, { id: event.run, timestamp: event.timestamp, source, events: [], keys: new Set() });
      if (source === 'session') updateRuns();
    }
    const run = runs.get(event.run);
    const key = JSON.stringify([event.event, event.timestamp, event.vm, event.event_id]);
    if (run.keys.has(key) || run.events.length >= 1200) return;
    run.keys.add(key);
    run.events.push(event);
    if (source === 'session' && selected === run.id && !el('analysis-view').hidden) render(false);
  }

  function memoryFor(context, id) {
    const archived = SocLogs.reviewedCases().map((item) => ({ ...item, context: SocReview.facts(item.entries, item.severity) }));
    const reviewed = SocReview.related(context, [...memory.values(), ...archived], id);
    return reviewed.length ? { reviewed: true, matches: reviewed } : { reviewed: false, matches: SocReview.related(context, demonstrations, id) };
  }

  function completed(events) {
    return events.some((event) => event.event === 'endpoint.block_released' || event.event === 'soar.monitor_only' ||
      event.event === 'soar.policy_denied' || event.event === 'soar.approval_rejected');
  }

  function renderMemory(context, run) {
    const { reviewed, matches } = memoryFor(context, run.id);
    const falsePositives = matches.filter((match) => match.resolution === 'falso_positivo').length;
    const suggestion = falsePositives * 2 > matches.length
      ? 'Sugestão: confira manutenção autorizada e validade da conta antes de escalar.'
      : 'Sugestão: investigue as diferenças antes de reaproveitar a resolução.';
    el('memory-summary').textContent = matches.length
      ? `${matches.length} ${reviewed ? 'da memória revisada' : 'da memória fictícia de demonstração'} · ${falsePositives} ${falsePositives === 1 ? 'falso positivo' : 'falsos positivos'}. ${suggestion}`
      : 'Nenhuma resolução semelhante encontrada nas fontes disponíveis.';
    const items = matches.map((match) => {
      const item = document.createElement('li');
      const headline = document.createElement('strong');
      const detail = document.createElement('small');
      headline.textContent = `${match.title} · ${resolutionLabels[match.resolution]} · ${Math.round(match.score * 100)}% de similaridade`;
      detail.textContent = match.differences.join(' · ') || 'Mesma sequência, host e conta no contexto observado.';
      item.append(headline, detail);
      return item;
    });
    el('memory-matches').replaceChildren(...items);
    el('memory-review').hidden = !completed(run.events) || !context.sequence.length || !['session', 'sample'].includes(run.source);
    if (el('memory-resolution').dataset.run !== run.id) {
      el('memory-resolution').dataset.run = run.id;
      el('memory-resolution').value = memory.get(run.id)?.resolution || '';
      el('memory-status').textContent = 'As classificações revisadas são armazenadas neste navegador.';
    }
  }

  function renderShadow() {
    el('shadow-json').hidden = !preview;
    if (!preview) {
      el('shadow-result').textContent = 'Simule o impacto da política local para esta rodada.';
      fillList('shadow-items', []);
      return;
    }
    const eligible = preview.predicted_source_status === 403;
    el('shadow-result').textContent = eligible ? 'Previsão · contenção limitada ao HTTP da vítima.' : 'Previsão · política não aplicaria contenção.';
    fillList('shadow-items', eligible ? [
      `${preview.source_ip} → ${preview.target_ip}: HTTP 403 previsto por ${preview.ttl_seconds} s.`,
      `Sonda de controle: HTTP ${preview.predicted_control_status} previsto.`,
      'A simulação não envia tráfego, não muda regras e não aprova o bloqueio.',
    ] : [preview.reason, 'A simulação não alterou o serviço.']);
  }

  function render(reset = true) {
    const run = runs.get(selected);
    if (!run) {
      el('analysis-status').textContent = 'Execute uma rodada ou importe a trilha JSONL para começar.';
      return;
    }
    const events = SocReview.timeline(run.events);
    if (reset || !timer) ordered = events;
    if (reset) {
      stop();
      position = 0;
      preview = undefined;
    }
    const context = SocReview.facts(events);
    const shadowAudit = events.findLast((event) => event.event === 'soar.shadow_preview' && event.applied === false);
    if (shadowAudit && !preview && typeof shadowAudit.source_ip === 'string' && typeof shadowAudit.target_ip === 'string') preview = shadowAudit;
    review = events.findLast((event) => event.event === 'soar.challenged');
    const hasReview = review?.provider === 'ollama' && review.validation === 'passed';
    el('analysis-status').textContent = `${events.length} eventos registrados · ordem cronológica em UTC · ${runLabel(run)}`;
    el('challenge-provider').textContent = hasReview ? 'OLLAMA · 2ª ANÁLISE' : 'REGRAS LOCAIS';
    const result = review?.result;
    el('challenge-verdict').textContent = hasReview && Object.hasOwn(verdictLabels, result?.verdict)
      ? `${verdictLabels[result.verdict]} · ${result.reason}`
      : 'Revisão consultiva das evidências e de possíveis explicações benignas.';
    const findings = SocReview.challenge(context);
    if (result?.reason && !hasReview && typeof result.reason === 'string') findings.push(result.reason);
    fillList('challenge-items', findings.length ? findings : ['Ainda não há evidências suficientes para uma contraprova.']);
    const missing = SocReview.gaps(context);
    fillList('gap-items', missing.length ? missing : ['O conjunto cobre os itens verificados pelo checklist do laboratório.']);
    el('challenge-json').hidden = !review;
    el('shadow-test').disabled = false;
    renderShadow();
    renderMemory(context, run);
    renderReplay();
  }

  function renderReplay() {
    const list = el('replay-events');
    el('replay-position').textContent = `${position} / ${ordered.length}`;
    el('replay-prev').disabled = !position;
    el('replay-next').disabled = position >= ordered.length;
    el('replay-play').disabled = !ordered.length;
    el('replay-play').textContent = timer ? 'Pausar' : position === ordered.length && position ? 'Recomeçar' : 'Reproduzir';
    el('replay-seek').disabled = !ordered.length;
    el('replay-seek').max = String(ordered.length);
    el('replay-seek').value = String(position);
    if (!position) {
      fillList('replay-events', ['Inicie a reprodução ou avance um evento por vez.']);
      return;
    }
    const items = ordered.slice(Math.max(0, position - 24), position).map((event, index, visible) => {
      const item = document.createElement('li');
      const time = document.createElement('time');
      const text = document.createElement('div');
      const detail = document.createElement('button');
      time.dateTime = event.timestamp;
      time.textContent = new Date(event.timestamp).toISOString().slice(11, 19);
      detail.type = 'button';
      detail.className = 'link-button';
      detail.textContent = event.event_type || event.event;
      detail.addEventListener('click', () => SocLogs.showDetails(event));
      text.append(detail, typeof event.message === 'string' ? event.message : '');
      item.append(time, text);
      if (index === visible.length - 1) item.className = 'replay-current';
      return item;
    });
    list.replaceChildren(...items);
    list.scrollTop = list.scrollHeight;
  }

  function stop() {
    clearTimeout(timer);
    timer = undefined;
  }

  function advance() {
    if (position >= ordered.length) {
      stop();
      renderReplay();
      return;
    }
    position++;
    const gap = Date.parse(ordered[position]?.timestamp) - Date.parse(ordered[position - 1].timestamp);
    if (position === ordered.length) stop();
    else timer = setTimeout(advance, Math.max(220, Math.min(2200, gap || 400)) / Number(el('replay-speed').value));
    renderReplay();
  }

  function choose(id) {
    selected = id;
    updateRuns();
    render();
  }

  function open(id) {
    choose(id);
    location.hash = '#analise';
  }

  function openCase(id, title, records) {
    const key = `caso:${id}`;
    const events = SocReview.timeline(records.map((event) => ({
      ...event, event: typeof event.event === 'string' ? event.event : event.event_type || 'archive.record',
      timestamp: event.event_time || event.timestamp || event['@timestamp'],
    })));
    runs.set(key, { id: key, title: title || 'Caso sem título', timestamp: events.at(-1)?.timestamp || '', source: 'case', events });
    open(key);
  }

  function summary(id) {
    const run = runs.get(id);
    if (!run) return '';
    const context = SocReview.facts(SocReview.timeline(run.events));
    const { matches, reviewed } = memoryFor(context, id);
    return `${SocReview.gaps(context).length} lacunas · ${matches.length} casos semelhantes (${reviewed ? 'revisados' : 'amostra'})`;
  }

  runSelect.addEventListener('change', () => choose(runSelect.value));
  el('replay-play').addEventListener('click', () => {
    if (timer) { stop(); renderReplay(); return; }
    if (position === ordered.length) position = 0;
    advance();
  });
  for (const [id, step] of [['replay-prev', -1], ['replay-next', 1]]) {
    el(id).addEventListener('click', () => { stop(); position += step; renderReplay(); });
  }
  el('replay-seek').addEventListener('input', (event) => { stop(); position = Number(event.target.value); renderReplay(); });
  el('challenge-json').addEventListener('click', () => { if (review) SocLogs.showDetails(review); });
  el('shadow-json').addEventListener('click', () => { if (preview) SocLogs.showDetails(preview); });
  el('shadow-test').addEventListener('click', () => {
    preview = SocReview.shadow(SocReview.facts(ordered), selected);
    if (runs.get(selected)?.source === 'session') document.dispatchEvent(new CustomEvent('soc:shadow-preview', { detail: preview }));
    renderShadow();
  });
  el('memory-review').addEventListener('submit', (event) => {
    event.preventDefault();
    const run = runs.get(selected);
    const resolution = el('memory-resolution').value;
    if (!run || !completed(run.events) || !Object.hasOwn(resolutionLabels, resolution)) return;
    const context = SocReview.facts(ordered);
    const { sequence, failures, host, user, mitre } = context;
    memory.set(run.id, { id: run.id, title: run.id, resolution, context: { sequence, failures, host, user, mitre } });
    try {
      localStorage.setItem(memoryKey, JSON.stringify([...memory.values()].slice(-100)));
      el('memory-status').textContent = `Conclusão salva: ${resolutionLabels[resolution]}.`;
    } catch {
      el('memory-status').textContent = 'Conclusão registrada nesta sessão. O navegador não permitiu gravá-la.';
    }
    renderMemory(context, run);
  });
  el('analysis-import').addEventListener('click', () => el('analysis-file').click());
  el('analysis-file').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) { el('analysis-status').textContent = 'Use uma trilha de rodada com até 4 MB.'; return; }
    try {
      const entries = (await file.text()).split('\n').filter((line) => line.trim()).map((line) => JSON.parse(line));
      const candidates = SocReview.timeline(entries).filter((entry) => typeof entry.run === 'string' && /^SOC-\d{3,24}$/.test(entry.run));
      if (!candidates.length) throw new Error('empty');
      for (const entry of candidates) ingest(entry, 'import');
      choose(candidates.at(-1).run);
    } catch {
      el('analysis-status').textContent = 'Arquivo inválido. Importe um JSONL de auditoria com eventos e IDs de rodada.';
    }
  });
  window.addEventListener('hashchange', () => {
    if (location.hash === '#analise') render(false);
    else { stop(); renderReplay(); }
  });
  SocDashboard.sampleRecords.then((events) => {
    for (const event of events) ingest(event, 'sample');
    updateRuns();
    if (!selected) el('analysis-status').textContent = 'Execute uma rodada ou importe a trilha JSONL para começar.';
    else render(false);
  });

  return { ingest, open, openCase, summary };
})();
