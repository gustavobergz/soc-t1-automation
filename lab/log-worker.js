'use strict';

// Packaged as a Blob worker so the same parser works from the server and from a local file.
function archiveWorker() {
  let records = [];
  let cache;
  let generation = 0;
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
    };
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
      postMessage({ type: 'loaded', total: records.length, invalid, types: [...types].sort(), source, legacyUrl: legacy || null });
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
        const haystack = `${row.eventId} ${row.type} ${row.message} ${row.host} ${row.user} ${row.ip}`.toLowerCase();
        return terms.every((term) => haystack.includes(term));
      });
      if (order === 'desc') matches.reverse();
      cache = { key, matches };
    }
    const pages = Math.ceil(cache.matches.length / size);
    const actualPage = Math.min(page, Math.max(0, pages - 1));
    postMessage({ type: 'results', id, page: actualPage, pages, total: cache.matches.length, rows: cache.matches.slice(actualPage * size, (actualPage + 1) * size) });
  }

  self.onmessage = ({ data }) => {
    if (data.type === 'load') load(data);
    if (data.type === 'search') search(data);
  };
}
