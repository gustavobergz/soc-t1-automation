'use strict';
globalThis.SocLocalRuntime = (() => {
  const local = location.hostname === '127.0.0.1' && ['8771', '8772'].includes(location.port);
  let capabilities = null;
  let pending = [];
  let flushing = false;
  let stopped = false;
  async function refresh() {
    if (!local) return null;
    try {
      const response = await fetch('/api/capabilities', { signal: AbortSignal.timeout(5000), cache: 'no-store' });
      if (!response.ok) throw new Error('capabilities_unavailable');
      capabilities = await response.json();
      document.dispatchEvent(new CustomEvent('soc:capabilities', { detail: capabilities }));
      return capabilities;
    } catch {
      capabilities = { ollama: { ready: false, status: 'unavailable' } };
      document.dispatchEvent(new CustomEvent('soc:capabilities', { detail: capabilities }));
      return capabilities;
    }
  }
  function ingest(event) {
    if (!local || !capabilities?.journal || event.vm !== 'panel' || stopped) return;
    pending.push({ id: crypto.randomUUID(), event });
    if (pending.length > 20000) {
      stopped = true;
      document.dispatchEvent(new CustomEvent('soc:journal-error', { detail: 'Limite local de registros pendentes atingido. Exporte o JSONL antes de continuar.' }));
    }
  }
  async function flush() {
    if (flushing || !pending.length || stopped) return;
    flushing = true;
    const batch = pending.slice(0, 60);
    try {
      const response = await fetch('/api/journal', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: batch }), signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error('journal_failed');
      pending.splice(0, batch.length);
      document.dispatchEvent(new CustomEvent('soc:journal-state', { detail: { pending: pending.length, stored: (await response.json()).stored } }));
    } catch {
      document.dispatchEvent(new CustomEvent('soc:journal-error', { detail: 'A gravação local está pendente. Os eventos continuam no painel; mantenha a aba aberta e exporte o JSONL.' }));
    } finally { flushing = false; }
  }
  if (local) setInterval(flush, 1200);
  return { local, refresh, ingest, flush, get capabilities() { return capabilities; } };
})();
