'use strict';

globalThis.SocLogs = (() => {
  const el = (id) => document.getElementById(id);
  const format = new Intl.NumberFormat('pt-BR');
  const labels = { alta: 'Alta', media: 'Média', baixa: 'Baixa', info: 'Informativa' };
  const severity = (value) => Object.hasOwn(labels, value) ? labels[value] : 'Sem nível';
  const corpus = 'soc-investigacao-205k.jsonl.gz';
  const hosted = location.protocol !== 'file:' && location.origin !== 'http://127.0.0.1:8771';
  const storageKey = 'soc-tier1-cases-v1';
  const form = el('search-logs');
  const rows = el('archive-rows');
  const caseInputs = { title: 'case-title', severity: 'case-severity', status: 'case-status', notes: 'case-notes' };
  const checkboxes = new Map();
  let worker;
  let loaded = 0;
  let page = 0;
  let pages = 0;
  let requestId = 0;
  let currentCase;
  let pendingFilters;
  const cases = new Map();

  function button(label, action, className = 'compact') {
    const control = document.createElement('button');
    control.type = 'button';
    control.className = className;
    control.textContent = label;
    control.addEventListener('click', action);
    return control;
  }

  function showDetails(event, actions = {}) {
    const dialog = el('log-detail');
    el('detail-title').textContent = event.event_id || event.id || event.event_type || event.event || 'Detalhe do evento';
    el('detail-message').textContent = event.message || event.raw || '';
    el('detail-json').textContent = JSON.stringify(event, null, 2);
    const mark = el('detail-select');
    const pivot = el('detail-pivot');
    mark.hidden = !actions.toggle;
    pivot.hidden = !actions.pivot;
    const label = () => { mark.textContent = actions.selected?.() ? 'Remover evidência' : 'Marcar como evidência'; };
    label();
    mark.onclick = () => { actions.toggle?.(); label(); };
    pivot.onclick = () => { dialog.close(); actions.pivot?.(); };
    if (!dialog.open) dialog.showModal();
  }

  function workspace() {
    const routes = { '#operacao': 'live', '#investigar': 'investigation', '#casos': 'cases', '#validacao': 'validation' };
    const view = routes[location.hash] || 'overview';
    const investigation = view === 'investigation' || view === 'cases';
    el('overview-view').hidden = view !== 'overview';
    el('live-view').hidden = view !== 'live';
    el('investigation-view').hidden = !investigation;
    el('validation-view').hidden = view !== 'validation';
    el('investigation-view').classList.toggle('cases-view', view === 'cases');
    for (const section of ['overview', 'live', 'investigation', 'cases', 'validation']) {
      const link = el(`link-${section}`);
      if (section === view) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    }
  }

  function loadState(text, error = false) {
    el('load-state').textContent = text;
    el('load-state').classList.toggle('notice-error', error);
  }

  function showEmpty(message) {
    const row = rows.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 6;
    cell.textContent = message;
  }

  function load(file) {
    if (!worker) {
      const url = URL.createObjectURL(new Blob([`(${archiveWorker.toString()})();`], { type: 'text/javascript' }));
      worker = new Worker(url, { name: 'soc-investigation' });
      URL.revokeObjectURL(url);
      worker.onmessage = ({ data }) => receive(data);
      worker.onerror = () => loadState('O explorador encontrou um erro. Reabra a página e tente carregar o arquivo novamente.', true);
    }
    requestId++;
    loaded = 0;
    page = 0;
    pages = 0;
    pagination();
    rows.replaceChildren();
    showEmpty('Lendo os registros…');
    el('result-count').textContent = 'Carregando';
    el('apply-search').disabled = true;
    el('clear-search').disabled = true;
    const source = file?.name || corpus;
    loadState(`Carregando ${source}…`);
    globalThis.SocDashboard?.archiveState('Carregando base…');
    worker.postMessage({
      type: 'load', source, file, url: file ? null : new URL(`logs/${corpus}`, location.href).href,
      legacyUrl: !file && !hosted ? new URL(`logs/${corpus.slice(0, -3)}`, location.href).href : null,
    });
  }

  function receive(data) {
    switch (data.type) {
      case 'progress':
        loadState(`${format.format(data.count)} registros lidos…`);
        break;
      case 'error':
        loadState(data.message, true);
        globalThis.SocDashboard?.archiveState('Base indisponível');
        el('result-count').textContent = 'Falha ao carregar';
        rows.replaceChildren();
        showEmpty('Abra outro arquivo JSONL para continuar.');
        break;
      case 'loaded':
        loaded = data.total;
        globalThis.SocDashboard?.archive(data);
        if (data.legacyUrl) {
          el('download-corpus').href = data.legacyUrl;
          el('download-corpus').textContent = 'Base de 205 mil eventos (.jsonl)';
        }
        loadState(`${format.format(loaded)} registros · ${data.source}${data.invalid ? ` · ${format.format(data.invalid)} linhas inválidas ignoradas` : ''}`);
        el('search-type').replaceChildren(new Option('Todos', ''), ...data.types.map((type) => new Option(type, type)));
        el('apply-search').disabled = false;
        el('clear-search').disabled = false;
        applyFilters();
        break;
      case 'results':
        if (data.id !== requestId) return;
        page = data.page;
        pages = data.pages;
        el('result-count').textContent = `${format.format(data.total)} de ${format.format(loaded)} registros`;
        renderRows(data.rows);
        pagination();
        break;
    }
  }

  function applyFilters() {
    form.reset();
    for (const [field, value] of Object.entries(pendingFilters || {})) {
      form.elements.namedItem(field).value = value;
    }
    pendingFilters = undefined;
    search(true);
  }

  function openSearch(filters) {
    pendingFilters = filters;
    location.hash = '#investigar';
    if (loaded) applyFilters();
    else if (location.protocol === 'file:') loadState('Carregue uma base de logs para aplicar a busca.');
  }

  function search(reset = false) {
    if (!loaded) return;
    if (reset) page = 0;
    const values = new FormData(form);
    const field = (name) => values.get(name).trim();
    const from = field('from') ? Date.parse(`${field('from')}:00Z`) : null;
    const to = field('to') ? Date.parse(`${field('to')}:59.999Z`) : null;
    if (from !== null && to !== null && from > to) {
      el('result-count').textContent = 'A data inicial precisa vir antes da data final.';
      return;
    }
    worker.postMessage({ type: 'search', id: ++requestId, page, size: Number(el('page-size').value), filters: {
      text: field('text'), severity: field('severity'), type: field('type'), ip: field('ip').toLowerCase(),
      user: field('user').toLowerCase(), host: field('host').toLowerCase(), from, to, order: el('archive-sort').value,
      selected: values.has('selected') ? Object.keys(currentCase.evidence) : null,
    } });
  }

  function pagination() {
    el('page-prev').disabled = page === 0;
    el('page-next').disabled = page + 1 >= pages;
    el('page-position').textContent = `Página ${pages ? format.format(page + 1) : 0} de ${format.format(pages)}`;
  }

  function isSelected(key) {
    return Object.hasOwn(currentCase.evidence, key);
  }

  function openRow(row, pivot = true) {
    showDetails(row.raw, {
      selected: () => isSelected(row.key), toggle: () => toggleRow(row),
      pivot: pivot && row.ip && loaded ? () => {
        form.reset();
        el('search-ip').value = row.ip;
        search(true);
      } : null,
    });
  }

  function renderRows(results) {
    rows.replaceChildren();
    checkboxes.clear();
    if (!results.length) showEmpty('Nenhum registro corresponde aos filtros.');
    for (const record of results) {
      const row = rows.insertRow();
      const check = document.createElement('input');
      check.type = 'checkbox';
      check.checked = isSelected(record.key);
      row.classList.toggle('marked', check.checked);
      check.setAttribute('aria-label', `Marcar ${record.eventId} como evidência`);
      check.addEventListener('change', () => toggleRow(record));
      checkboxes.set(record.key, check);
      row.insertCell().append(check);
      row.insertCell().textContent = record.timestamp ? record.timestamp.replace('T', ' ').replace('Z', '') : '—';
      const badge = document.createElement('span');
      badge.className = `level severity-${Object.hasOwn(labels, record.severity) ? record.severity : 'unknown'}`;
      badge.textContent = severity(record.severity);
      row.insertCell().append(badge);
      const detail = row.insertCell();
      detail.append(button(record.type, () => openRow(record), 'log-link'));
      const summary = document.createElement('small');
      summary.textContent = record.message;
      detail.append(summary);
      const entity = row.insertCell();
      entity.textContent = record.host || '—';
      const user = document.createElement('small');
      user.textContent = record.user;
      entity.append(user);
      row.insertCell().textContent = record.ip || '—';
    }
  }

  function saveCase() {
    currentCase.updated_at = new Date().toISOString();
    cases.set(currentCase.id, currentCase);
    try {
      localStorage.setItem(storageKey, JSON.stringify({ active: currentCase.id, cases: [...cases.values()] }));
      el('case-storage').textContent = 'Caso salvo neste navegador. Exporte para compartilhar.';
    } catch {
      el('case-storage').textContent = 'Armazenamento local indisponível. Exporte o caso antes de fechar.';
    }
    showCaseList();
  }

  function showCaseList() {
    const options = [...cases.values()].sort((a, b) => b.updated_at.localeCompare(a.updated_at))
      .map((item) => new Option(item.title || `Caso ${item.id.slice(-8)}`, item.id));
    if (!cases.has(currentCase.id)) options.unshift(new Option('Caso novo', currentCase.id));
    el('case-list').replaceChildren(...options);
    el('case-list').value = currentCase.id;
  }

  function selectCase(item) {
    currentCase = item || { id: crypto.randomUUID(), title: '', severity: '', status: 'investigando', notes: '', evidence: {} };
    for (const [key, id] of Object.entries(caseInputs)) el(id).value = currentCase[key];
    el('case-storage').textContent = item ? 'Caso local aberto.' : 'Marque um registro para iniciar um caso local.';
    showCaseList();
    renderEvidence();
    for (const [key, checkbox] of checkboxes) {
      checkbox.checked = isSelected(key);
      checkbox.closest('tr').classList.toggle('marked', checkbox.checked);
    }
    if (el('selected-filter').checked) search(true);
  }

  function toggleRow(row) {
    if (isSelected(row.key)) {
      delete currentCase.evidence[row.key];
    } else if (Object.keys(currentCase.evidence).length < 200) {
      currentCase.evidence[row.key] = row;
    } else {
      el('case-storage').textContent = 'O caso atingiu o limite de 200 evidências.';
      const checkbox = checkboxes.get(row.key);
      if (checkbox) checkbox.checked = false;
      return;
    }
    const checkbox = checkboxes.get(row.key);
    if (checkbox) {
      checkbox.checked = isSelected(row.key);
      checkbox.closest('tr').classList.toggle('marked', checkbox.checked);
    }
    saveCase();
    renderEvidence();
    if (el('selected-filter').checked) search();
  }

  function renderEvidence() {
    const list = el('case-evidence');
    const evidence = Object.values(currentCase.evidence);
    el('case-evidence-count').textContent = `${evidence.length} ${evidence.length === 1 ? 'evidência' : 'evidências'}`;
    el('export-case').disabled = !cases.has(currentCase.id);
    list.replaceChildren();
    for (const item of evidence) {
      const row = document.createElement('li');
      const details = button(`${item.eventId} · ${item.type}`, () => openRow(item, false), 'log-link');
      const remove = button('Remover', () => toggleRow(item));
      remove.setAttribute('aria-label', `Remover ${item.eventId}`);
      row.append(details, remove);
      list.append(row);
    }
  }

  function exportCase() {
    const { evidence, ...metadata } = currentCase;
    const artifact = { ...metadata, exported_at: new Date().toISOString(), evidence: Object.values(evidence).map((row) => ({ source: row.source, event: row.raw })) };
    const url = URL.createObjectURL(new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `caso-soc-${metadata.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  let lastCase;
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey));
    for (const item of saved?.cases || []) {
      if (item?.id && item.updated_at && item.evidence) cases.set(item.id, item);
    }
    lastCase = cases.get(saved?.active);
  } catch { /* A new case is available when browser storage is unavailable. */ }
  selectCase(lastCase);
  workspace();
  function loadDefaultCorpus() {
    if (location.protocol !== 'file:' && !worker && (!el('overview-view').hidden || !el('investigation-view').hidden)) load();
  }
  loadDefaultCorpus();
  window.addEventListener('hashchange', () => {
    workspace();
    loadDefaultCorpus();
    if (location.hash === '#casos') el('case-panel').focus({ preventScroll: true });
    window.scrollTo(0, 0);
  });
  el('global-search').addEventListener('submit', (event) => {
    event.preventDefault();
    openSearch({ text: el('global-query').value.trim() });
  });
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && !el('log-detail').open) {
      event.preventDefault();
      el('global-query').focus();
      el('global-query').select();
    }
  });
  el('load-corpus').addEventListener('click', () => {
    if (location.protocol === 'file:') {
      loadState(`No modo local, selecione o arquivo logs/${corpus}.`);
      el('log-file').click();
    } else load();
  });
  el('import-logs').addEventListener('click', () => el('log-file').click());
  el('log-file').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) load(file);
    event.target.value = '';
  });
  form.addEventListener('submit', (event) => { event.preventDefault(); search(true); });
  el('clear-search').addEventListener('click', () => { form.reset(); search(true); });
  for (const id of ['selected-filter', 'page-size', 'archive-sort']) el(id).addEventListener('change', () => search(true));
  el('page-prev').addEventListener('click', () => { page--; search(); });
  el('page-next').addEventListener('click', () => { page++; search(); });
  el('new-case').addEventListener('click', () => { selectCase(); el('case-title').focus(); });
  el('case-list').addEventListener('change', () => selectCase(cases.get(el('case-list').value)));
  el('export-case').addEventListener('click', exportCase);
  for (const [key, id] of Object.entries(caseInputs)) {
    el(id).addEventListener('change', () => {
      currentCase[key] = el(id).value.trim();
      saveCase();
      renderEvidence();
    });
  }
  return { showDetails, severity, openSearch };
})();
