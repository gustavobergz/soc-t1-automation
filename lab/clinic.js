'use strict';

globalThis.SocClinic = (() => {
  let scenarios = [];
  const ready = fetch('lab/clinic.json')
    .then((response) => {
      if (!response.ok) throw new Error('catalog_unavailable');
      return response.json();
    })
    .then((catalog) => {
      scenarios = catalog;
      const select = document.getElementById('clinic-scenario');
      select.replaceChildren(...catalog.map((scenario) => new Option(scenario.title, scenario.id)), new Option('Laboratório anterior · SSH', ''));
      const describe = () => {
        const scenario = scenarios.find((item) => item.id === select.value);
        document.getElementById('clinic-brief').textContent = scenario?.brief || 'Cenário anterior de falhas de SSH, login aceito e consulta de privilégios.';
      };
      select.addEventListener('change', describe);
      describe();
      return catalog;
    })
    .catch(() => {
      document.getElementById('clinic-brief').textContent = 'Para carregar os cenários da clínica, use o site publicado ou o iniciador local. O laboratório SSH continua disponível.';
      return [];
    });
  function describe(facts) {
    const items = [];
    if (facts.successful_login === true) items.push('Login da sessão confirmado');
    if (facts.unknown_device === true) items.push('Dispositivo desconhecido');
    if (facts.out_of_shift === true) items.push('Fora da escala fictícia');
    if (Number.isFinite(facts.records_accessed) && facts.records_accessed > 0) items.push(`${facts.records_accessed} consultas registradas`);
    if (Number.isFinite(facts.unassigned_records) && facts.unassigned_records > 0) items.push(`${facts.unassigned_records} consultas sem vínculo`);
    if (facts.export_requested === true) items.push('Exportação solicitada');
    if (facts.export_denied === true) items.push('Pedido de exportação negado');
    else if (facts.export_requested === true) items.push('Resultado da exportação ainda desconhecido');
    if (facts.role_changed === true) items.push('Permissão de administrador concedida');
    if (facts.admin_access === true) items.push('Acesso administrativo registrado');
    if ([facts.approved_context, facts.export_authorized, facts.role_authorized].includes(true)) items.push('Indicação de autorização registrada');
    return items.join(' · ');
  }

  return { ready, describe, get: (id) => scenarios.find((item) => item.id === id) };
})();
