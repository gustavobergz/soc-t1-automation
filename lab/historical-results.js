'use strict';
(() => {
  const el = (id) => document.getElementById(id);
  const format = new Intl.NumberFormat('pt-BR', { minimumFractionDigits: 3, maximumFractionDigits: 3 });
  const seconds = (value) => value === null ? 'Não aplicável' : `${format.format(value / 1000)} s`;
  const expected = '05ba43798a039773bf8fc03d92359bb3faf5065681b9546763631dc52f6a4b4c';
  async function render() {
    el('recalculate-history').disabled = true;
    try {
      const response = await fetch('logs/clinica-demo.jsonl', { cache: 'no-store' });
      if (!response.ok) throw new Error('Arquivo histórico indisponível.');
      const bytes = await response.arrayBuffer();
      const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((item) => item.toString(16).padStart(2, '0')).join('');
      if (hash !== expected) throw new Error('O arquivo é diferente da fonte histórica avaliada no TCC.');
      const records = new TextDecoder().decode(bytes).split(/\r?\n/).filter((line) => line.trim()).map(JSON.parse);
      const result = SocMetrics.historicalSummary(records);
      el('historical-times').replaceChildren();
      for (const [mode, title] of [['manual', 'Manual de teste'], ['auto', 'Triagem simulada'], ['llm', 'Ollama local'], ['failure', 'Falha induzida de triagem']]) {
        const value = result.statistics[mode];
        const row = document.createElement('tr');
        for (const text of [title, value.count, seconds(value.detection_ms.meanMs), seconds(value.triage_ms.meanMs),
          value.response_ms.count ? `${seconds(value.response_ms.meanMs)} (n=${value.response_ms.count})` : 'Sem contenção no acervo']) {
          const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
        }
        el('historical-times').append(row);
      }
      const b = result.benchmark.counts;
      el('historical-evidence').textContent = `${result.rounds} rodadas em ${result.lines} linhas de auditoria. ${result.containments} contenções e ${result.releases} liberações. Detector: ${b.tp} VP, ${b.fp} FP, ${b.tn} VN e ${b.fn} FN.`;
      el('historical-model').textContent = `Triagens Ollama individuais: ${result.ollamaTriages.map(seconds).join(' e ')}. JSONs aceitos quanto à estrutura; o acervo registrou justificativas genéricas. Não houve comparação pareada com analistas humanos.`;
      el('historical-state').textContent = 'Arquivo original conferido por SHA256. Números recalculados, sem executar uma nova inferência do modelo.';
    } catch (error) { el('historical-state').textContent = error.message; }
    finally { el('recalculate-history').disabled = false; }
  }
  el('recalculate-history').addEventListener('click', render);
  render();
})();
