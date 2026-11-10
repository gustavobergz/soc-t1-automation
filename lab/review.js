'use strict';

globalThis.SocReview = (() => {
  const threatSource = '10.77.0.30';
  const victim = '10.77.0.20';
  const protectedIPs = ['10.77.0.10', victim, '10.77.0.40'];
  const dispositions = { confirmado: 'Confirmado', falso_positivo: 'Falso positivo', inconclusivo: 'Inconclusivo' };
  const kinds = new Map([
    ['ssh.failed', 'failure'], ['ssh.accepted', 'login'], ['sudo.attempt', 'privilege'], ['sudo.list', 'privilege'],
    ['change.approved', 'change'], ['audit.command', 'activity'], ['process.exec', 'activity'], ['network.connection', 'activity'],
  ]);

  function timeline(entries) {
    return entries.filter((entry) => entry && typeof entry.event === 'string' && typeof entry.timestamp === 'string' && Number.isFinite(Date.parse(entry.timestamp)))
      .slice().sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  }

  function facts(entries, severity = '') {
    const audit = entries.findLast((event) => event.event === 'siem.correlated' || event.event === 'siem.manual_detected');
    const selected = new Set(Array.isArray(audit?.evidence_ids) ? audit.evidence_ids : []);
    const raw = entries.filter((event) => event.event === 'siem.raw');
    const observed = raw.length ? raw : entries;
    const events = [];
    const ids = new Set();
    for (const event of observed) {
      if (selected.size && !selected.has(event.event_id)) continue;
      const kind = kinds.get(event.event_type || event.kind || event.event);
      const id = typeof event.event_id === 'string' ? event.event_id : '';
      if (!kind || (id && ids.has(id))) continue;
      if (id) ids.add(id);
      const timestamp = typeof event.event_time === 'string' ? event.event_time : event.timestamp;
      events.push({ kind, time: typeof timestamp === 'string' ? Date.parse(timestamp) : NaN, ip: event.source_ip, host: event.host, user: event.username || event.user });
    }
    events.sort((a, b) => (a.time || 0) - (b.time || 0));
    const sequence = events.map((event) => event.kind).filter((kind, index, order) => kind !== order[index - 1]).slice(0, 48);
    const failures = events.filter((event) => event.kind === 'failure').length;
    const login = events.find((event) => event.kind === 'login');
    const privilege = events.find((event) => event.kind === 'privilege' && (!login || event.time >= login.time));
    const entity = audit || events.find((event) => event.kind !== 'change');
    const mitre = entries.findLast((event) => event.event === 'soar.enriched')?.mitre;
    const text = (value) => typeof value === 'string' ? value : '';
    return {
      source: text(entity?.source_ip || entity?.ip), host: text(entity?.host), user: text(entity?.username || entity?.user),
      sequence, failures, evidenceIds: [...ids], login: Boolean(login), privilege: Boolean(privilege),
      otherActivity: Boolean(privilege && events.some((event) => event.kind === 'activity' && event.time > privilege.time && event.host === privilege.host)),
      authorizedChange: events.some((event) => event.kind === 'change'),
      mixed: new Set(events.filter((event) => event.kind !== 'change').map((event) => JSON.stringify([event.ip, event.host, event.user]))).size > 1,
      chain: audit?.chain_complete === true,
      severity: entries.findLast((event) => event.event === 'soar.triaged' || event.event === 'soar.manual_triaged')?.severity || severity,
      mitre: Array.isArray(mitre) ? mitre.filter((value) => typeof value === 'string').slice(0, 10) : [],
    };
  }

  function gaps(context) {
    const missing = [];
    if (context.failures < 5) missing.push('Conferir se há mais falhas da mesma origem, conta e máquina na janela de correlação.');
    if (!context.login) missing.push('Confirmar o resultado da autenticação nos registros do endpoint.');
    if (!context.privilege) missing.push('Buscar atividade administrativa associada ao login.');
    if (context.privilege && !context.otherActivity) missing.push('Buscar registros de processo ou rede após a consulta de privilégios.');
    if (!context.authorizedChange) missing.push('Consultar a agenda de mudanças e confirmar o contexto com o responsável pela conta.');
    if (context.mixed) missing.push('Separar evidências de origens, contas ou máquinas diferentes antes de concluir.');
    return missing;
  }

  function challenge(context) {
    const findings = [];
    if (protectedIPs.includes(context.source)) findings.push('A origem está na lista de IPs protegidos do laboratório.');
    if (context.authorizedChange) findings.push('Há um registro de mudança autorizada. Valide se ele corresponde a esta atividade.');
    if (context.mixed) findings.push('As evidências não pertencem todas à mesma origem, conta e máquina.');
    if (context.failures < 5) findings.push('A seleção contém menos de cinco falhas de autenticação.');
    if (context.login) findings.push('Um login aceito também é compatível com uso autorizado da conta.');
    if (context.privilege) findings.push('A consulta de privilégios, sozinha, não comprova elevação.');
    return findings;
  }

  function shadow(context, run) {
    const eligible = context.source === threatSource && context.chain && context.severity === 'alta';
    return {
      event: 'panel.shadow_preview', run, timestamp: new Date().toISOString(), synthetic: true,
      action: eligible ? 'http_block' : 'no_action', applied: false, eligible,
      source_ip: context.source || null, target_ip: victim, scope: 'serviço HTTP de demonstração',
      ttl_seconds: eligible ? 45 : 0, predicted_source_status: eligible ? 403 : null,
      predicted_control_status: eligible ? 204 : null, protected_ips: [...protectedIPs], evidence_ids: context.evidenceIds,
      reason: eligible ? 'Previsão da política local, sujeita à aprovação humana.' : 'A origem, a severidade ou a sequência não atendem à política de contenção do laboratório.',
    };
  }

  function commonSequence(left, right) {
    let previous = Array(right.length + 1).fill(0);
    for (const step of left) {
      const next = [0];
      for (const [index, value] of right.entries()) {
        next.push(step === value ? previous[index] + 1 : Math.max(previous[index + 1], next[index]));
      }
      previous = next;
    }
    return previous[right.length];
  }

  function related(context, candidates, current) {
    if (!context.sequence.length) return [];
    return candidates.filter((item) => item.id !== current && Object.hasOwn(dispositions, item.resolution) && Array.isArray(item.context?.sequence))
      .map((item) => {
        const other = item.context;
        const order = 2 * commonSequence(context.sequence, other.sequence) / (context.sequence.length + other.sequence.length);
        const sameHost = Boolean(context.host && context.host === other.host);
        const sameUser = Boolean(context.user && context.user === other.user);
        const sameTechnique = context.mitre.some((technique) => other.mitre?.includes(technique));
        const score = 0.75 * order + 0.10 * sameHost + 0.08 * sameUser + 0.07 * sameTechnique;
        const differences = [];
        if (context.failures !== other.failures) differences.push(`${context.failures} falhas agora × ${other.failures} no histórico`);
        if (!sameHost) differences.push('host diferente ou ausente');
        if (!sameUser) differences.push('conta diferente ou ausente');
        if (order < 1) differences.push('sequência parcialmente diferente');
        return { ...item, score, differences };
      }).filter((item) => item.score >= 0.55)
      .sort((a, b) => b.score - a.score).slice(0, 3);
  }

  return { timeline, facts, gaps, challenge, shadow, related, dispositions };
})();

if (typeof module === 'object') module.exports = globalThis.SocReview;
