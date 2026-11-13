'use strict';

// Packaged as a Blob worker so the same parser works from the server and from a local file.
function archiveWorker() {
  let records = [];
  let cache;
  let generation = 0;
  let archiveSource = '';
  const scalar = (value) => typeof value === 'string' || typeof value === 'number' ? String(value) : '';
  const normalizeSeverity = (value) => ({ high: 'alta', medium: 'media', low: 'baixa', média: 'media', informational: 'info' })[value] || value;

  function normalize(raw, line, source) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const timestamp = scalar(raw.event_time ?? raw.timestamp ?? raw['@timestamp']);
    const time = Date.parse(timestamp);
    const eventId = scalar(raw.event_id ?? raw.id) || `linha-${line}`;
    const host = scalar(raw.host?.name ?? raw.host);
    const key = JSON.stringify([eventId, timestamp, host, eventId.startsWith('linha-') ? source : '']);
    return {
      key, eventId, time, timestamp, host, raw, source,
      severity: normalizeSeverity(scalar(raw.severity).toLowerCase()),
      type: scalar(raw.event_type ?? raw.kind ?? raw.event) || 'sem_tipo',
      user: scalar(raw.username ?? raw.user?.name ?? raw.user),
      ip: scalar(raw.source_ip ?? raw.source?.ip ?? raw.srcip),
      message: scalar(raw.message ?? raw.raw),
      session: scalar(raw.session_id), scenario: scalar(raw.scenario), patient: scalar(raw.patient_ref),
    };
  }

  function summarize(rows) {
    const levels = { alta: 0, media: 0, baixa: 0 };
    const buckets = { total: Array(24).fill(0), alta: Array(24).fill(0), media: Array(24).fill(0) };
    const signals = new Map();
    const first = rows.find((row) => Number.isFinite(row.time))?.time;
    const last = rows.findLast((row) => Number.isFinite(row.time))?.time;
    const span = Math.max(1, last - first + 1);
    const recent = [];
    for (const row of rows) {
      const bucket = Math.min(23, Math.floor((row.time - first) * 24 / span));
      if (Number.isFinite(bucket)) buckets.total[bucket]++;
      if (!Object.hasOwn(levels, row.severity)) continue;
      levels[row.severity]++;
      if (buckets[row.severity] && Number.isFinite(bucket)) buckets[row.severity][bucket]++;
      signals.set(row.type, (signals.get(row.type) || 0) + 1);
    }
    for (let index = rows.length - 1; index >= 0 && recent.length < 6; index--) {
      if (Object.hasOwn(levels, rows[index].severity)) recent.push(rows[index]);
    }
    return { levels, buckets, recent, signals: [...signals].sort((a, b) => b[1] - a[1]).slice(0, 4) };
  }

  async function load({ url, file, source, legacyUrl }) {
    const token = ++generation;
    records = [];
    cache = null;
    const loaded = [];
    const types = new Set();
    const keys = new Set();
    let line = 0;
    let invalid = 0;
    let tail = '';

    function read(text) {
      line++;
      if (!text.trim()) return;
      try {
        const record = normalize(JSON.parse(text), line, source);
        if (!record) throw new Error('Expected an object');
        if (keys.has(record.key)) record.key = JSON.stringify([record.key, source, line]);
        keys.add(record.key);
        types.add(record.type);
        loaded.push(record);
      } catch {
        invalid++;
      }
      if (line % 25000 === 0) postMessage({ type: 'progress', count: loaded.length });
    }

    try {
      let response = file ? null : await fetch(url);
      const legacy = response?.status === 404 && legacyUrl;
      if (legacy) {
        response = await fetch(legacyUrl);
        source = source.slice(0, -3);
      }
      if (response && !response.ok) throw new Error(`Arquivo indisponível (HTTP ${response.status}).`);
      const input = file ? file.stream() : response.body;
      const stream = source.toLowerCase().endsWith('.gz') ? input.pipeThrough(new DecompressionStream('gzip')) : input;
      const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (token !== generation) {
          await reader.cancel();
          return;
        }
        if (done) break;
        const lines = (tail + value).split('\n');
        tail = lines.pop();
        if (tail.length > 2_000_000) {
          await reader.cancel();
          throw new Error('O arquivo tem uma linha muito longa. Confira se está em formato JSONL.');
        }
        for (const text of lines) read(text);
      }
      if (tail) read(tail);
      if (loaded.length === 0) throw new Error('Nenhum objeto JSON válido encontrado. Use um objeto por linha.');
      loaded.sort((a, b) => (a.time || 0) - (b.time || 0));
      records = loaded;
      archiveSource = source;
      postMessage({ type: 'loaded', total: records.length, invalid, types: [...types].sort(), source, legacyUrl: legacy || null, summary: summarize(records) });
    } catch (error) {
      if (token === generation) postMessage({ type: 'error', message: error.message });
    }
  }

  function search({ id, filters, page, size }) {
    const key = JSON.stringify(filters);
    if (cache?.key !== key) {
      const { severity, type, ip, user, host, from, to, text, selected, order } = filters;
      const terms = text.toLowerCase().split(/\s+/).filter(Boolean);
      const evidence = selected ? new Set(selected) : null;
      const matches = records.filter((row) => {
        if ((evidence && !evidence.has(row.key)) || (severity && row.severity !== severity) || (type && row.type !== type) ||
            (ip && !row.ip.toLowerCase().includes(ip)) || (user && !row.user.toLowerCase().includes(user)) ||
            (host && !row.host.toLowerCase().includes(host)) || (from !== null && !(row.time >= from)) ||
            (to !== null && !(row.time <= to))) return false;
        if (!terms.length) return true;
        const haystack = `${row.eventId} ${row.type} ${row.message} ${row.host} ${row.user} ${row.ip} ${row.session} ${row.scenario} ${row.patient}`.toLowerCase();
        return terms.every((term) => haystack.includes(term));
      });
      if (order === 'desc') matches.reverse();
      cache = { key, matches };
    }
    const pages = Math.ceil(cache.matches.length / size);
    const actualPage = Math.min(page, Math.max(0, pages - 1));
    postMessage({ type: 'results', id, page: actualPage, pages, total: cache.matches.length, rows: cache.matches.slice(actualPage * size, (actualPage + 1) * size) });
  }

  function analyze({ id, query }) {
    if (query.kind === 'failed_ips') {
      const last = records.findLast((row) => Number.isFinite(row.time))?.time;
      const day = query.day || (last !== undefined ? new Date(last).toISOString().slice(0, 10) : '');
      const from = Date.parse(`${day}T00:00:00.000Z`);
      const to = from + 86_400_000;
      const origins = new Map();
      let total = 0;
      for (const row of records) {
        if (!['ssh.failed', 'auth.failed'].includes(row.type) || !(row.time >= from && row.time < to) || !row.ip) continue;
        total++;
        if (!origins.has(row.ip)) origins.set(row.ip, { ip: row.ip, count: 0, example: row.raw });
        origins.get(row.ip).count++;
      }
      const top = [...origins.values()].sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip)).slice(0, 5);
      postMessage({ type: 'analytics', id, source: archiveSource, result: { day, total, top } });
    }
    if (query.kind === 'baseline') {
      const hours = Array(24).fill(0);
      const hosts = new Map();
      let count = 0;
      let first;
      let last;
      for (const row of records) {
        if (!['ssh.accepted', 'auth.login'].includes(row.type) || row.user !== query.user || !Number.isFinite(row.time) || row.time >= query.before) continue;
        count++;
        hours[new Date(row.time).getUTCHours()]++;
        if (row.host) hosts.set(row.host, (hosts.get(row.host) || 0) + 1);
        first ??= row.time;
        last = row.time;
      }
      postMessage({ type: 'analytics', id, source: archiveSource, result: { count, hours, knownHost: hosts.has(query.host), hosts: hosts.size, first, last } });
    }
    if (query.kind === 'clinic_activity') {
      const accepted = {
        reads: ['ehr.record_read'], exports: ['ehr.export_requested', 'ehr.export_denied'],
        permissions: ['iam.role_changed', 'iam.admin_access'],
      };
      if (!Object.hasOwn(accepted, query.metric)) return;
      const groups = new Map();
      let total = 0;
      for (const row of records) {
        if (!accepted[query.metric].includes(row.type)) continue;
        const key = query.metric === 'reads' ? row.user : row.type;
        if (!groups.has(key)) groups.set(key, { key, count: 0, example: row.raw });
        const amount = query.metric === 'reads' ? row.raw.clinical?.count || 1 : 1;
        groups.get(key).count += amount;
        total += amount;
      }
      postMessage({ type: 'analytics', id, source: archiveSource, result: { total,
        top: [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 5) } });
    }
  }

  self.onmessage = ({ data }) => {
    if (data.type === 'load') load(data);
    if (data.type === 'search') search(data);
    if (data.type === 'analytics') analyze(data);
  };
}
