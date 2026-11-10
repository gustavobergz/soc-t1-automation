'use strict';

globalThis.SocDashboard = (() => {
  const el = (id) => document.getElementById(id);
  const number = new Intl.NumberFormat('pt-BR');
  const date = new Intl.DateTimeFormat('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });
  const labels = { alta: 'Alta', media: 'Média', baixa: 'Baixa' };
  const sample = new Map();
  const live = new Map();

  function badge(severity) {
    const node = document.createElement('span');
    node.className = `level severity-${Object.hasOwn(labels, severity) ? severity : 'unknown'}`;
    node.textContent = labels[severity] || 'Sem nível';
    return node;
  }

  function chart(id, values) {
    const svg = el(id);
    const maximum = Math.max(1, ...values);
    const points = values.map((value, index) => `${index * 111 / (values.length - 1)},${28 - value * 24 / maximum}`);
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', `M${points.join(' L')}`);
    const fill = document.createElementNS(svg.namespaceURI, 'path');
    fill.setAttribute('d', `M${points.join(' L')} L111,32 L0,32 Z`);
    fill.setAttribute('class', 'spark-fill');
    svg.replaceChildren(fill, path);
  }

  function button(label, action) {
    const node = document.createElement('button');
    node.type = 'button';
    node.className = 'link-button';
    node.textContent = label;
    node.addEventListener('click', action);
    return node;
  }

  function archiveState(label) {
    el('kpi-source').textContent = label;
  }

  function archive({ total, source, summary }) {
    const { levels, buckets, recent, signals } = summary;
    el('kpi-total').textContent = number.format(total);
    el('kpi-high').textContent = number.format(levels.alta);
    el('kpi-medium').textContent = number.format(levels.media);
    archiveState(source.startsWith('soc-investigacao-205k.') ? 'Base sintética' : 'Arquivo importado');
    chart('trend-total', buckets.total);
    chart('trend-high', buckets.alta);
    chart('trend-medium', buckets.media);

    const table = el('recent-events');
    table.replaceChildren();
    if (!recent.length) {
      const empty = table.insertRow().insertCell();
      empty.colSpan = 5;
      empty.textContent = 'A base carregada não contém eventos classificados.';
    }
    for (const event of recent) {
      const row = table.insertRow();
      row.insertCell().textContent = Number.isFinite(event.time) ? new Date(event.time).toISOString().slice(11, 19) : '—';
      row.insertCell().append(badge(event.severity));
      row.insertCell().append(button(event.type, () => SocLogs.showDetails(event.raw, {
        pivot: event.ip ? () => SocLogs.openSearch({ ip: event.ip }) : null,
      })));
      row.insertCell().textContent = event.ip || '—';
      row.insertCell().textContent = event.host || '—';
    }

    const list = el('signal-list');
    list.replaceChildren();
    if (!signals.length) {
      const empty = document.createElement('li');
      empty.className = 'overview-empty';
      empty.textContent = 'Sem sinais classificados na base.';
      list.append(empty);
    }
    for (const [type, count] of signals) {
      const item = document.createElement('li');
      const label = button(type, () => SocLogs.openSearch({ type }));
      const value = document.createElement('span');
      value.textContent = number.format(count);
      const bar = document.createElement('span');
      bar.className = 'signal-bar';
      const fill = document.createElement('span');
      fill.style.width = `${count * 100 / signals[0][1]}%`;
      bar.append(fill);
      item.append(label, value, bar);
      list.append(item);
    }
  }

  function applyAudit(target, event) {
    const detected = event.event === 'siem.manual_detected' || event.event === 'siem.correlated';
    if (detected && event.incident) {
      target.set(event.run, { ...event, state: 'Em triagem' });
      return true;
    }
    const record = target.get(event.run);
    if (!record) return false;
    switch (event.event) {
      case 'soar.triaged':
      case 'soar.manual_triaged': record.severity = event.severity; break;
      case 'soar.approval_requested': record.state = 'Aguardando aprovação'; break;
      case 'endpoint.block_applied': record.state = 'Contido'; break;
      case 'endpoint.block_released': record.state = 'Origem liberada'; break;
      case 'soar.monitor_only': record.state = 'Em acompanhamento'; break;
      case 'soar.policy_denied': record.state = 'Ação impedida'; break;
      case 'soar.approval_rejected': record.state = 'Rejeitado'; break;
      default: return false;
    }
    return true;
  }

  function renderIncidents() {
    const list = el('recent-incidents');
    const active = live.size ? live : sample;
    list.replaceChildren();
    if (!active.size) {
      const empty = document.createElement('li');
      empty.className = 'overview-empty';
      empty.textContent = 'Execute uma rodada para registrar um incidente.';
      list.append(empty);
    }
    el('incident-source').textContent = live.size ? 'Nesta sessão' : sample.size ? 'Histórico de demonstração' : 'Nenhum incidente na sessão';
    for (const record of [...active.values()].reverse().slice(0, 3)) {
      const row = document.createElement('li');
      row.className = `incident-row severity-${Object.hasOwn(labels, record.severity) ? record.severity : 'unknown'}`;
      const header = document.createElement('div');
      const title = button(record.incident, () => SocLogs.showDetails(record));
      header.append(title, badge(record.severity));
      const state = document.createElement('p');
      state.textContent = `${record.mode === 'manual' ? 'Triagem manual' : 'Abuso de credenciais'} · ${record.state}`;
      const time = document.createElement('small');
      time.textContent = `${date.format(new Date(record.timestamp))} UTC`;
      row.append(header, state, time);
      list.append(row);
    }
  }

  function ingest(event) {
    if (applyAudit(live, event)) renderIncidents();
  }

  function machine(role, label, count, online, blocked) {
    const node = document.querySelector(`[data-topology="${role}"]`);
    node.querySelector('small').textContent = label;
    node.classList.toggle('map-online', online);
    node.classList.toggle('map-blocked', blocked);
    el('kpi-vm-count').textContent = String(count);
    el('lab-health').textContent = count === 4 ? 'SOC online' : count ? `${count} de 4 VMs online` : 'Laboratório em espera';
    el('lab-health').parentElement.classList.toggle('healthy', count === 4);
  }

  function clock() {
    el('soc-clock').textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
  }
  clock();
  setInterval(clock, 1000);
  for (const control of document.querySelectorAll('[data-severity-filter]')) {
    control.addEventListener('click', () => SocLogs.openSearch({ severity: control.dataset.severityFilter }));
  }
  if (location.protocol !== 'file:') {
    fetch('logs/soc-demo.jsonl').then((response) => response.ok ? response.text() : '').then((text) => {
      for (const line of text.trim().split('\n')) if (line) applyAudit(sample, JSON.parse(line));
      renderIncidents();
    }).catch(() => renderIncidents());
  } else renderIncidents();

  return { archive, archiveState, machine, ingest };
})();
