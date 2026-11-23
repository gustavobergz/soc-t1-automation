(function(root,factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.SocReport=factory();
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const text=value=>value===null||value===undefined?'':String(value).replace(/[\u0000-\u001f\u007f]+/g,' ').trim();
  const sev=value=>({alta:'ALTA',media:'MÉDIA',baixa:'BAIXA'}[text(value).toLowerCase()]||'Não registrada');
  const rec={investigar_conta:'Investigar a conta e a titularidade da sessão',monitorar:'Investigar e acompanhar',avaliar_contencao:'Avaliar necessidade e impacto da contenção'};
  const status={ok:'Resposta aceita quanto à estrutura',invalid:'Resposta recusada pela validação',error:'Falha na chamada',running:'Análise em andamento',idle:'Não executada'};
  const bool=value=>value===true?'sim':value===false?'não':text(value);
  function decision(d){
    if(!d)return 'Pendente ou reaberto: decisão de resposta não registrada.';
    if(d.tipo==='approved')return 'Atividade considerada legítima pelo analista; sem nova contenção.';
    if(d.tipo==='monitoring')return 'Investigação e acompanhamento; sem nova contenção.';
    if(d.tipo==='blocked')return ({active:'Contenção SIMULADA ativa.',released:'Contenção SIMULADA revertida manualmente.',expired:'Contenção SIMULADA encerrada pelo prazo.'}[d.estado]||'Contenção SIMULADA registrada.');
    return text(d.tipo)+'; estado: '+text(d.estado);
  }
  function draftKey(snapshot){
    const s=snapshot||{},log=s.log||{};
    const seed=JSON.stringify([s.tipo_execucao||'demonstration',log.arquivo,log.eventos,(s.incidentes||[]).map(i=>[i.id,i.titulo])]);
    let h=2166136261;
    for(let i=0;i<seed.length;i++){h^=seed.charCodeAt(i);h=Math.imul(h,16777619);}
    return 'soc-t2-draft-'+(h>>>0).toString(16);
  }
  function createReport(snapshot,options={}){
    if(!snapshot||!Array.isArray(snapshot.incidentes))throw new Error('Registro de incidentes inválido.');
    const cases=snapshot.incidentes,log=snapshot.log||{},audit=Array.isArray(snapshot.auditoria)?snapshot.auditoria:[];
    const lines=[
      'RELATÓRIO DE TRIAGEM - ENCAMINHAMENTO AO T2','',
      'Gerado em (UTC): '+text(options.generatedAt||new Date().toISOString()),
      'Analista T1: '+(text(snapshot.analista)||'Não informado'),
      'Sessão de origem: '+(text(snapshot.sessao)||'Não informada'),
      'Arquivo de logs: '+(text(log.arquivo)||'Não informado'),
      'Eventos processados: '+(Number.isFinite(log.eventos)?log.eventos.toLocaleString('pt-BR'):'Não informado'),
      'Ambiente: protótipo; as ações de resposta descritas são simuladas.',
      'O texto pode ser revisado antes do envio. A auditoria e os logs originais são as referências das evidências.','',
      'RESUMO',
      'Casos incluídos: '+cases.length,
      'Casos sem decisão registrada: '+cases.filter(i=>!i.decisao).length,
      'Respostas de IA aceitas quanto à estrutura: '+cases.filter(i=>i.ia&&i.ia.status==='ok').length+'/'+cases.length,
      'Decisões e severidades abaixo refletem o registro de origem; sugestões da IA são apresentadas separadamente.',''
    ];
    for(const i of cases){
      const ai=i.ia||{},p=ai.resposta||{},d=i.decisao,entities=i.entidades||{};
      const justification=(i.revisao_severidade&&i.revisao_severidade.note)||(i.revisao_humana&&i.revisao_humana.justification);
      lines.push('='.repeat(68),text(i.id)+' - '+text(i.titulo),'',
        'Severidade final do analista/regra: '+sev(i.prioridade_final||i.prioridade_regra),
        'Origem da classificação final: '+(i.revisao_severidade?'revisão do analista':i.revisao_humana&&i.revisao_humana.completed_at?'regra conferida em revisão humana':'referência da regra; revisão humana não registrada'),
        'Severidade de referência da regra: '+sev(i.prioridade_regra),
        'Justificativa do analista: '+(text(justification)||'Não registrada. Conferir as evidências e complementar a avaliação.'),
        'Campanha/grupo: '+(text(i.campanha)||'Sem vínculo registrado'),
        'Técnicas relacionadas: '+((i.mitre||[]).map(text).filter(Boolean).join(', ')||'Não informadas'));
      for(const [label,value] of [['Contas',entities.users],['IPs relacionados',entities.ips],['Hosts',entities.hosts],['Sessão',entities.session]]){
        const v=Array.isArray(value)?value.map(text).filter(Boolean).join(', '):text(value);
        if(v)lines.push(label+': '+v);
      }
      if(i.fatos&&typeof i.fatos==='object'){
        lines.push('','FATOS EXTRAÍDOS DOS EVENTOS');
        for(const [key,value] of Object.entries(i.fatos))lines.push('- '+text(key)+': '+bool(value));
      }
      lines.push('','TRIAGEM ASSISTIDA',
        'Provedor/modelo: '+(text(ai.provedor)||'Não utilizado')+(ai.modelo?' / '+text(ai.modelo):''),
        'Situação da resposta: '+(status[ai.status]||'Não executada'));
      if(ai.status==='ok'){
        lines.push('Tipo de ameaça sugerido: '+(text(p.threat_type)||'Não informado'),
          'Severidade sugerida pela IA: '+sev(p.severity),
          'Justificativa da IA: '+(text(p.severity_reason)||'Não informada'),
          'Impacto possível: '+(text(p.possible_impact)||'Não informado'),
          'Incertezas: '+(text(p.uncertainty)||'Não informadas'),
          'Recomendações da IA: '+((p.recommendations||[]).map(v=>rec[v]||text(v)).join('; ')||'Não informadas'));
      }else if(ai.erros)lines.push('Detalhe da falha/validação: '+(Array.isArray(ai.erros)?ai.erros.map(text).join('; '):text(ai.erros)));
      if(Number.isFinite(ai.tempo_ms))lines.push('Tempo da chamada e validação: '+(ai.tempo_ms/1000).toFixed(3).replace('.',',')+' s');
      lines.push('','DECISÃO E RESPOSTA',decision(d));
      if(d){
        lines.push('Responsável pela decisão: '+(text(d.por)||'Não informado'),'ID da decisão: '+text(d.id));
        if(d.nota)lines.push('Justificativa da conduta: '+text(d.nota));
        if(d.tipo==='blocked'&&Number.isFinite(d.ttl_s))lines.push('Prazo configurado: '+(d.ttl_s===0?'até desbloqueio manual':d.ttl_s+' segundos'));
        for(const s of d.passos||[])lines.push('- '+text(s.text||s.kind)+'; alvo: '+text(s.target)+'; resultado: '+text(s.result));
      }
      const history=audit.filter(a=>a.incident===i.id&&/^(DECISAO_|CONTENCAO_|SEVERIDADE_)/.test(a.type));
      if(history.length){
        lines.push('','HISTÓRICO DE DECISÕES E AÇÕES (UTC)');
        for(const a of history)lines.push(text(a.ts)+' | '+text(a.actor)+' | '+text(a.type)+' | '+text(a.detail));
      }
      lines.push('','REFERÊNCIAS DE EVIDÊNCIA','Eventos associados ao caso: '+(Number.isFinite(i.evidencias)?i.evidencias:'Não informado'));
      const refs=Array.isArray(i.evidencias_referencia)?i.evidencias_referencia:[];
      if(refs.length)for(const e of refs)lines.push('- '+text(e.id)+(e.source_id?' / '+text(e.source_id):'')+(e.timestamp?' | '+text(e.timestamp):'')+(e.event?' | '+text(e.event):''));
      else lines.push('IDs enviados à IA: '+((p.evidence_ids||[]).map(text).join(', ')||'Não disponíveis neste registro; consultar os logs originais.'));
      lines.push('','PONTOS PARA INVESTIGAÇÃO PELO T2',
        '- Conferir a titularidade da sessão e o contexto de autorização.',
        '- Correlacionar os IDs acima com o arquivo de logs original.',
        '- Avaliar as incertezas registradas e aprofundar a investigação antes de concluir o caso.','');
    }
    lines.push('='.repeat(68),'ANEXOS PARA O ENCAMINHAMENTO',
      '- Este relatório TXT, após a revisão do analista.',
      '- O arquivo de logs original: '+(text(log.arquivo)||'identificar o arquivo utilizado')+'.',
      '- A auditoria JSON exportada pelo aplicativo.',
      '', 'O relatório contém um resumo e referências de evidência; não incorpora todas as linhas brutas do log.',
      'A edição deste texto não modifica as classificações, decisões ou registros originais da aplicação.');
    return lines.join('\n')+'\n';
  }
  return {createReport,draftKey};
});
