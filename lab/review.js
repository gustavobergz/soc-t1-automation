'use strict';

globalThis.SocReview = (() => {
  const threatSource = '10.77.0.30';
  const victim = '10.77.0.20';
  const protectedIPs = ['10.77.0.10', victim, '10.77.0.40'];
  const dispositions = { confirmado: 'Confirmado', falso_positivo: 'Falso positivo', inconclusivo: 'Inconclusivo' };
  const kinds = new Map([
    ['ssh.failed', 'failure'], ['ssh.accepted', 'login'], ['sudo.attempt', 'privilege'], ['sudo.list', 'privilege'],
    ['sudo.denied', 'admin_denied'], ['change.approved', 'change'], ['audit.command', 'activity'],
    ['process.exec', 'activity'], ['process.started', 'activity'], ['network.connection', 'activity'],
    ['auth.failed', 'failure'], ['auth.login', 'login'], ['ehr.record_read', 'record_read'],
    ['ehr.export_requested', 'export_request'], ['ehr.export_denied', 'export_denied'],
    ['iam.role_changed', 'role_change'], ['iam.admin_access', 'admin_access'],
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
      events.push({ kind, time: typeof timestamp === 'string' ? Date.parse(timestamp) : NaN, ip: event.source_ip, host: event.host, user: event.username || event.user, record: event });
    }
    events.sort((a, b) => (a.time || 0) - (b.time || 0));
    const sequence = events.map((event) => event.kind).filter((kind, index, order) => kind !== order[index - 1]).slice(0, 48);
    const failures = events.filter((event) => event.kind === 'failure').length;
    const login = events.find((event) => event.kind === 'login');
    const privilege = events.find((event) => event.kind === 'privilege' && (!login || event.time >= login.time));
    const assets = [...new Set(events.map((event) => event.host).filter((host) => typeof host === 'string' && host))].sort();
    const entity = audit || events.find((event) => event.kind !== 'change');
    const scenario = audit?.scenario || events.find((event) => event.record.scenario)?.record.scenario || '';
    const clinical = events.some((event) => event.record.clinical || event.record.sector === 'healthcare');
    const session = audit?.session_id || events.find((event) => event.record.session_id)?.record.session_id || '';
    const authorized = events.some((event) => event.kind === 'change' && event.record.clinical?.approved === true);
    const exportDenied = events.some((event) => event.kind === 'export_denied');
    const mitre = entries.findLast((event) => event.event === 'soar.enriched')?.mitre || globalThis.SocClinic?.get(scenario)?.mitre;
    const text = (value) => typeof value === 'string' ? value : '';
    return {
      source: text(entity?.source_ip || entity?.ip), host: text(entity?.host), user: text(entity?.username || entity?.user),
      sequence, failures, evidenceIds: [...ids], login: Boolean(login), privilege: Boolean(privilege), events, assets,
      clinical, scenario, session, authorized, exportDenied,
      authorizationClaimed: events.some((event) => ['export_request', 'role_change'].includes(event.kind) && event.record.clinical?.approved === true),
      exportRequested: events.some((event) => event.kind === 'export_request'),
      recordsRead: events.filter((event) => event.kind === 'record_read').reduce((total, event) => total + (event.record.clinical?.count || 1), 0),
      otherActivity: Boolean(privilege && events.some((event) => event.kind === 'activity' && event.time > privilege.time && event.host === privilege.host)),
      authorizedChange: events.some((event) => event.kind === 'change'),
      mixed: new Set(events.filter((event) => event.kind !== 'change').map((event) => JSON.stringify([event.ip, event.host, event.user, event.record.session_id]))).size > 1,
      chain: audit?.chain_complete === true,
      severity: entries.findLast((event) => event.event === 'soar.triaged' || event.event === 'soar.manual_triaged')?.severity || severity,
      mitre: Array.isArray(mitre) ? mitre.filter((value) => typeof value === 'string').slice(0, 10) : [],
    };
  }

  function gaps(context) {
    if (context.clinical) {
      const missing = [];
      if (!context.login) missing.push('Recuperar o login e vincular as ações à mesma sessão clínica.');
      if (!context.authorized) missing.push('Verificar escala, mudança aprovada e autorização com o responsável.');
      if (context.scenario === 'stolen_account') missing.push('Confirmar com a titular se reconhece a sessão e o dispositivo.');
      if (context.exportRequested && !context.exportDenied) missing.push('Buscar resultado da exportação e evidência de entrega. O pedido não confirma vazamento.');
      if (context.mixed) missing.push('Separar contas, serviços e sessões diferentes antes de concluir.');
      if (context.scenario === 'privilege_change') missing.push('Revisar a origem da concessão de administrador e o histórico de IAM.');
      return missing;
    }
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
    if (context.authorizedChange && !context.clinical) findings.push('Há um registro de mudança autorizada. Valide se ele corresponde a esta atividade.');
    if (context.mixed) findings.push('As evidências não pertencem todas à mesma origem, conta e máquina.');
    if (context.clinical) {
      if (context.authorized) findings.push('Há autorização vinculada à sessão e ao serviço. Confirme a validade do registro.');
      if (context.authorizationClaimed && !context.authorized) findings.push('O evento indica autorização. Recupere o registro de aprovação correspondente antes de concluir.');
      if (context.exportDenied) findings.push('A aplicação negou a exportação. Este pedido não comprova extração de dados.');
      if (context.login) findings.push('Login fora da escala ou em dispositivo novo pode ter explicação legítima. Confira o plantão.');
      if (context.exportRequested && !context.exportDenied) findings.push('Solicitação de exportação exige verificar o resultado antes de concluir que houve vazamento.');
      return findings;
    }
    if (context.failures < 5) findings.push('A seleção contém menos de cinco falhas de autenticação.');
    if (context.login) findings.push('Um login aceito também é compatível com uso autorizado da conta.');
    if (context.privilege) findings.push('A consulta de privilégios, sozinha, não comprova elevação.');
    return findings;
  }

  function shadow(context, run) {
    const eligible = context.source === threatSource && context.chain && context.severity === 'alta' &&
      !context.authorized && !context.authorizationClaimed && !context.exportDenied && !context.mixed;
    return {
      event: 'panel.shadow_preview', run, timestamp: new Date().toISOString(), synthetic: true,
      action: eligible ? 'http_block' : 'no_action', applied: false, eligible,
      source_ip: context.source || null, target_ip: victim, scope: 'serviço HTTP de demonstração',
      session_id: context.session || null, simulation_action: context.clinical ? 'temporary_session_suspension' : 'http_block',
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

  const stepLabels = {
    failure: 'Falha de autenticação', login: 'Autenticação aceita', privilege: 'Consulta de privilégios',
    admin_denied: 'Operação administrativa negada', change: 'Mudança autorizada registrada', activity: 'Atividade do endpoint',
    record_read: 'Consulta a prontuários fictícios', export_request: 'Exportação solicitada',
    export_denied: 'Exportação negada pela aplicação', role_change: 'Permissão administrativa concedida', admin_access: 'Área administrativa acessada',
  };

  function story(context) {
    const steps = [];
    for (const event of context.events.filter((entry) => Number.isFinite(entry.time))) {
      const previous = steps.at(-1);
      if (event.kind === 'failure' && previous?.kind === 'failure' && previous.ip === event.ip &&
          previous.host === event.host && previous.user === event.user) {
        previous.end = event.time;
        previous.records.push(event.record);
      } else steps.push({ ...event, end: event.time, records: [event.record] });
    }
    return steps.map((step) => ({
      ...step,
      label: step.kind === 'record_read' ? `${step.record.clinical?.count || 1} consultas a prontuários fictícios` :
        step.records.length === 1 ? stepLabels[step.kind] : `${step.records.length} falhas de autenticação`,
    }));
  }

  function signature(context) {
    const assets = context.assets || (context.host ? [context.host] : []);
    return JSON.stringify([context.sequence, [...new Set(context.mitre)].sort(), [...new Set(assets)].sort()]);
  }

  function receipt(entries, id, source) {
    const triage = entries.findLast((event) => ['soar.triaged', 'soar.manual_triaged'].includes(event.event));
    if (!triage) return null;
    const audit = entries.findLast((event) => ['siem.correlated', 'siem.manual_detected'].includes(event.event));
    const result = triage.result || {};
    const evidence = [result.evidence_ids, triage.input?.evidence_ids, triage.evidence_ids, audit?.evidence_ids].find(Array.isArray) || [];
    const decision = entries.findLast((event) => ['soar.approval_granted', 'soar.approval_rejected', 'soar.policy_denied', 'soar.monitor_only'].includes(event.event));
    return {
      event: 'panel.decision_receipt', version: 1, run: id, source,
      scenario: audit?.scenario || null, session_id: audit?.session_id || null,
      timestamp: triage.timestamp, incident: triage.incident || audit?.incident || null,
      rule_id: audit?.rule_id || null, correlation_event: audit?.event || null,
      provider: triage.provider || 'analista', model: triage.model || null, model_version: triage.model_version || null,
      prompt_version: triage.prompt_version || null, prompt: triage.prompt || null, validation: triage.validation || null,
      severity: triage.severity || null, reason: triage.policy_reason || result.severity_reason || triage.justification || triage.message || '',
      severity_source: triage.severity_source || null, model_suggested_severity: triage.model_suggested_severity || null,
      severity_disagreement: triage.severity_disagreement === true, model_reason: result.severity_reason || null,
      triage_actor: triage.actor || null,
      uncertainty: result.uncertainty || null,
      recommendations: Array.isArray(result.recommendations) ? result.recommendations.filter((item) => typeof item === 'string') : [],
      evidence_ids: [...new Set(evidence.filter((item) => typeof item === 'string'))],
      human_or_policy_decision: decision ? { event: decision.event, action: decision.action || null, actor: decision.actor || null, timestamp: decision.timestamp, reason: decision.message || null } : null,
    };
  }

  function pulse(items) {
    const severityWeight = { alta: 18, media: 9, baixa: 4 };
    const active = items.filter((item) => !item.closed);
    const assets = new Set(active.flatMap((item) => item.assets).filter(Boolean));
    const severity = active.reduce((total, item) => total + (Object.hasOwn(severityWeight, item.severity) ? severityWeight[item.severity] : 2), 0);
    const pending = active.filter((item) => item.pending).length;
    const points = { severity, assets: assets.size * 4, approval: pending * 8 };
    return { score: Math.min(100, points.severity + points.assets + points.approval), active: active.length, assets: assets.size, pending, points };
  }

  function related(context, candidates, current) {
    if (!context.sequence.length) return [];
    return candidates.filter((item) => item.id !== current && Object.hasOwn(dispositions, item.resolution) && Array.isArray(item.context?.sequence))
      .map((item) => {
        const other = item.context;
        const order = 2 * commonSequence(context.sequence, other.sequence) / (context.sequence.length + other.sequence.length);
        const assets = context.assets?.length ? context.assets : [context.host];
        const otherAssets = other.assets?.length ? other.assets : [other.host];
        const sameHost = assets.some((host) => host && otherAssets.includes(host));
        const sameUser = Boolean(context.user && context.user === other.user);
        const sameTechnique = context.mitre.some((technique) => other.mitre?.includes(technique));
        const score = 0.75 * order + 0.10 * sameHost + 0.08 * sameUser + 0.07 * sameTechnique;
        const differences = [];
        if (context.failures !== other.failures) differences.push(`${context.failures} falhas agora × ${other.failures} no histórico`);
        if (!sameHost) differences.push('host diferente ou ausente');
        if (!sameUser) differences.push('conta diferente ou ausente');
        if (order < 1) differences.push('sequência parcialmente diferente');
        return { ...item, score, differences, exact: signature(context) === signature(other) };
      }).filter((item) => item.score >= 0.55)
      .sort((a, b) => b.score - a.score).slice(0, 3);
  }

  return { timeline, facts, gaps, challenge, shadow, story, signature, receipt, pulse, related, dispositions };
})();

if (typeof module === 'object') module.exports = globalThis.SocReview;
