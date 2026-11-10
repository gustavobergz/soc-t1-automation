'use strict';

(() => {
  const el = (id) => document.getElementById(id);
  const scenarios = [
    {
      id: 'A01', title: 'Mudança no financeiro',
      brief: 'Uma sequência de falhas foi seguida por um login aceito. Compare a telemetria com a janela de manutenção.',
      user: 'ops_demo', host: 'financeiro-07', ip: '198.51.100.44',
      steps: [
        ['14:00:00', 'change.approved', 'CHG-041 · Conta ops_demo e origem 198.51.100.44 autorizadas para o financeiro-07 entre 14h e 14h30 UTC.'],
        ['14:02:00', 'ssh.failed', 'Falha de SSH para ops_demo na origem autorizada.'],
        ['14:04:00', 'ssh.accepted', 'Login aceito no financeiro-07 durante a janela aprovada.'],
        ['14:05:00', 'sudo.list', 'Consulta de privilégios prevista no roteiro da mudança.'],
      ],
      answer: 'falso_positivo', key: 0,
      explanation: 'A mudança aprovada confirma origem, conta, host e horário. A consulta de permissões está prevista na mudança.',
    },
    {
      id: 'A02', title: 'Login fora da janela',
      brief: 'Investigue o acesso e a confirmação da origem antes de classificar o incidente.',
      user: 'ops_demo', host: 'rh-09', ip: '203.0.113.24',
      steps: [
        ['03:02:00', 'ssh.failed', 'Falha de SSH para ops_demo no rh-09.'],
        ['03:04:00', 'ssh.accepted', 'Login aceito para ops_demo no rh-09 na mesma origem.'],
        ['03:06:00', 'sudo.denied', 'O endpoint negou uma operação administrativa.'],
        ['03:16:00', 'incident.verified', 'Equipe de identidade vinculou a sessão aceita a uma origem não autorizada e confirmou acesso indevido com o responsável.'],
      ],
      answer: 'confirmado', key: 3,
      explanation: 'O vínculo entre a sessão e a origem não autorizada foi confirmado pela equipe de identidade. A operação negada não comprova elevação de privilégios.',
    },
    {
      id: 'A03', title: 'Telemetria interrompida',
      brief: 'O coletor recebeu falhas de autenticação e deixou de receber eventos do endpoint.',
      user: 'svc_ci', host: 'bastion-02', ip: '192.0.2.88',
      steps: [
        ['11:02:00', 'ssh.failed', 'Falha de SSH para svc_ci no bastion-02.'],
        ['11:02:15', 'ssh.failed', 'Segunda falha observada na mesma origem.'],
        ['11:02:20', 'collector.unavailable', 'O coletor perdeu contato com o endpoint. Resultado das autenticações posteriores indisponível.'],
      ],
      answer: 'inconclusivo', key: 2,
      explanation: 'A interrupção impede confirmar login aceito ou ausência de acesso. Recupere os registros do endpoint antes de concluir.',
    },
  ];
  const selector = el('arena-scenario');
  const form = el('arena-form');
  const cleared = new Set();
  let current;
  let evidence;

  function render() {
    current = scenarios.find((scenario) => scenario.id === selector.value);
    evidence = current.steps.map(([time, event, message], index) => ({
      timestamp: `2026-11-10T${time}Z`, event, message, event_id: `${current.id}-0${index + 1}`,
      host: current.host, username: current.user, source_ip: current.ip, synthetic: true,
    }));
    el('arena-brief').textContent = current.brief;
    el('arena-answer').value = '';
    el('arena-feedback').textContent = '';
    el('arena-reason').replaceChildren(new Option('Selecione', ''), ...evidence.map((entry, index) => new Option(`${entry.event_id} · ${entry.event}`, String(index))));
    el('arena-evidence').replaceChildren(...evidence.map((entry) => {
      const item = document.createElement('li');
      const detail = document.createElement('button');
      detail.type = 'button';
      detail.className = 'link-button';
      detail.textContent = `${entry.timestamp.slice(11, 19)} UTC · ${entry.event_id}`;
      detail.addEventListener('click', () => SocLogs.showDetails(entry));
      item.append(detail, entry.message);
      return item;
    }));
  }

  selector.replaceChildren(...scenarios.map((scenario) => new Option(scenario.title, scenario.id)));
  el('arena-progress').textContent = `0 de ${scenarios.length} cenários resolvidos nesta sessão.`;
  selector.addEventListener('change', render);
  el('arena-replay').addEventListener('click', () => SocAnalysis.openCase(current.id, current.title, evidence, 'training'));
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const correctClassification = el('arena-answer').value === current.answer;
    const correctEvidence = el('arena-reason').value === String(current.key);
    const correct = correctClassification && correctEvidence;
    if (correct) cleared.add(current.id);
    const classification = SocReview.dispositions[current.answer];
    const feedback = correct ? 'Classificação e evidência corretas.' : correctClassification ? 'Classificação correta. Revise a evidência decisiva.' : 'Revise a classificação.';
    el('arena-feedback').textContent = `${feedback} Gabarito: ${classification} · ${evidence[current.key].event_id}. ${current.explanation}`;
    el('arena-progress').textContent = `${cleared.size} de ${scenarios.length} cenários resolvidos nesta sessão.`;
  });
  render();
})();
