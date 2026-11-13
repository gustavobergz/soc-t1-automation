'use strict';

(async () => {
  const el = (id) => document.getElementById(id);
  const scenarios = await SocClinic.ready;
  if (!scenarios.length) {
    el('arena-brief').textContent = 'Use o site publicado ou o iniciador local para carregar os exercícios da clínica.';
    return;
  }
  const selector = el('arena-scenario');
  const solved = new Set();
  let current;
  let evidence;

  function render() {
    current = scenarios.find((scenario) => scenario.id === selector.value);
    evidence = current.steps.map((step, index) => ({
      timestamp: new Date(Date.UTC(2026, 10, 12, 6, 0, index * 12)).toISOString(),
      event: step.kind, message: step.message, event_id: `ARENA-${current.id}-${index + 1}`,
      host: current.host, username: current.user, source_ip: '10.77.0.30', session_id: current.session,
      scenario: current.id, clinical: step, sector: 'healthcare', synthetic: true,
    }));
    el('arena-brief').textContent = current.brief;
    el('arena-answer').value = '';
    el('arena-feedback').textContent = '';
    el('arena-reason').replaceChildren(new Option('Selecione', ''), ...evidence.map((entry, index) => new Option(`${index + 1} · ${entry.event}`, String(index))));
    el('arena-evidence').replaceChildren(...evidence.map((entry) => {
      const item = document.createElement('li');
      const detail = document.createElement('button');
      detail.type = 'button';
      detail.className = 'link-button';
      detail.textContent = `${entry.timestamp.slice(11, 19)} UTC · ${entry.event}`;
      detail.addEventListener('click', () => SocLogs.showDetails(entry));
      item.append(detail, entry.message);
      return item;
    }));
  }

  selector.replaceChildren(...scenarios.map((scenario) => new Option(scenario.title, scenario.id)));
  el('arena-progress').textContent = `0 de ${scenarios.length} cenários resolvidos nesta sessão.`;
  selector.addEventListener('change', render);
  el('arena-replay').addEventListener('click', () => SocAnalysis.openCase(current.id, current.title, evidence, 'training'));
  el('arena-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const classification = el('arena-answer').value === current.answer;
    const explanation = el('arena-reason').value === String(current.key_step);
    if (classification && explanation) solved.add(current.id);
    const feedback = classification && explanation ? 'Classificação e evidência corretas.' : classification ? 'Classificação correta. Revise a evidência decisiva.' : 'Revise a classificação.';
    el('arena-feedback').textContent = `${feedback} Gabarito: ${SocReview.dispositions[current.answer]}. ${current.explanation}`;
    el('arena-progress').textContent = `${solved.size} de ${scenarios.length} cenários resolvidos nesta sessão.`;
  });
  render();
})();
