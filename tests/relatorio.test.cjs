'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createReport,draftKey}=require('../relatorio.js');
const fixture=()=>({
  sessao:'00000000-0000-4000-8000-000000000001',tipo_execucao:'software_validation',analista:'Analista de teste',
  log:{arquivo:'clinica-205mil.txt',eventos:205000},
  incidentes:[{
    id:'INC-001',titulo:'Sessão suspeita',campanha:'CAMP-01',prioridade_regra:'alta',prioridade_final:'alta',
    revisao_severidade:{note:'Conferi o acesso sem autorização.'},revisao_humana:{completed_at:'2026-11-23T10:00:00Z',justification:'Justificativa anterior'},
    fatos:{'Consultas sem vínculo':80,'Autorização registrada':false},entidades:{users:['MED-FICT'],ips:['10.0.0.1'],hosts:['HOST-FICT'],session:'SES-FICT'},
    mitre:['T1078'],evidencias:82,evidencias_referencia:[{id:'EV-000001',source_id:'CLIN-000001',timestamp:'2026-11-23T09:00:00Z',event:'auth.login'}],
    ia:{status:'ok',provedor:'ollama',modelo:'modelo-teste',tempo_ms:20123,resposta:{severity:'baixa',severity_reason:'Sugestão inicial do modelo.',threat_type:'inconclusivo',uncertainty:'Autoria não confirmada.',recommendations:['investigar_conta'],evidence_ids:['EV-000001']}},
    decisao:{tipo:'blocked',estado:'released',id:'APR-001',por:'Analista de teste',ttl_s:45,nota:'Contenção temporária revisada.',passos:[{text:'Suspender sessão',target:'SES-FICT',result:'executado (simulado)'}]}
  },{id:'INC-002',titulo:'Exportação recusada',prioridade_regra:'media',prioridade_final:'media',evidencias:3,mitre:[],ia:null,decisao:null}],
  auditoria:[{seq:1,ts:'2026-11-23T10:00:01Z',actor:'Analista de teste',type:'DECISAO_BLOQUEIO',incident:'INC-001',detail:'APR-001; bloqueio simulado'},
    {seq:2,ts:'2026-11-23T10:00:05Z',actor:'Analista de teste',type:'CONTENCAO_REVERTIDA',incident:'INC-001',detail:'APR-001; desbloqueio manual'}]
});
test('Relatório inclui contexto, justificativa, evidências, decisão e anexos de T2',()=>{
  const r=createReport(fixture(),{generatedAt:'2026-11-23T11:00:00Z'});
  for(const s of ['ENCAMINHAMENTO AO T2','205.000','Casos incluídos: 2','MED-FICT','SES-FICT','Conferi o acesso sem autorização.','CLIN-000001','Contenção SIMULADA revertida manualmente.','APR-001','auditoria JSON','não incorpora todas as linhas brutas'])assert.ok(r.includes(s),s);
});
test('Severidade humana e sugestão da IA permanecem separadas',()=>{
  const r=createReport(fixture());
  assert.ok(r.includes('Severidade final do analista/regra: ALTA'));
  assert.ok(r.includes('Severidade sugerida pela IA: BAIXA'));
  assert.ok(!r.includes('Justificativa do analista: Justificativa anterior'));
});
test('Ausência de triagem ou decisão não vira análise ou aprovação inventada',()=>{
  const s=fixture();s.incidentes=[s.incidentes[1]];
  const r=createReport(s);assert.ok(r.includes('Casos sem decisão registrada: 1'));assert.ok(r.includes('Situação da resposta: Não executada'));assert.ok(r.includes('Justificativa do analista: Não registrada.'));assert.ok(!r.includes('Atividade considerada legítima'));
});
test('Resposta inválida registra a falha, sem atribuir severidade aceita à IA',()=>{
  const s=fixture();s.incidentes=[s.incidentes[0]];s.incidentes[0].ia={status:'invalid',provedor:'ollama',erros:['IDs divergentes'],tempo_ms:1000,resposta:null};
  const r=createReport(s);assert.ok(r.includes('Resposta recusada pela validação'));assert.ok(r.includes('IDs divergentes'));assert.ok(!r.includes('Severidade sugerida pela IA: BAIXA'));
});
test('Histórico continua mostrando a contenção após acompanhamento ou reabertura',()=>{
  const s=fixture();s.incidentes[0].decisao={tipo:'monitoring',estado:'monitoring',por:'Analista de teste',id:'MON-001'};
  const r=createReport(s);assert.ok(r.includes('Investigação e acompanhamento; sem nova contenção.'));assert.ok(r.includes('DECISAO_BLOQUEIO'));assert.ok(r.includes('CONTENCAO_REVERTIDA'));
});
test('Tempo usa milissegundos do registro e mantém zero válido',()=>{
  const s=fixture();assert.ok(createReport(s).includes('20,123 s'));s.incidentes[0].ia.tempo_ms=0;assert.ok(createReport(s).includes('0,000 s'));
});
test('Texto é preservado como texto e campos simples não podem injetar cabeçalhos',()=>{
  const s=fixture();s.analista='Nome\nSEVERIDADE: BAIXA';s.incidentes[0].revisao_severidade.note='<b>texto para revisão</b>';
  const r=createReport(s);assert.ok(r.includes('Analista T1: Nome SEVERIDADE: BAIXA'));assert.ok(r.includes('<b>texto para revisão</b>'));
});
test('Gerar ou editar o resultado não altera o registro original',()=>{
  const s=fixture(),before=structuredClone(s);let r=createReport(s);r=r.replace('ALTA','BAIXA');assert.deepEqual(s,before);assert.ok(r.includes('BAIXA'));
});
test('Rascunhos são vinculados à base e separados de testes técnicos',()=>{
  const a=fixture(),b=fixture();b.sessao='outra-sessao';b.exportado_em='outro-horario';assert.equal(draftKey(a),draftKey(b));b.tipo_execucao='demonstration';assert.notEqual(draftKey(a),draftKey(b));b.tipo_execucao=a.tipo_execucao;b.log.eventos=10;assert.notEqual(draftKey(a),draftKey(b));
});
test('Registro sem lista de incidentes é recusado de forma explícita',()=>assert.throws(()=>createReport({}),/inválido/));
