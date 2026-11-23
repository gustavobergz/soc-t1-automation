'use strict';
const fs=require('node:fs'),path=require('node:path'),zlib=require('node:zlib'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const SOC=require(root+'/motor.js');
const ui=fs.readFileSync(root+'/interface.js','utf8');
const src=fs.readFileSync(root+'/index.html','utf8');
const parse=text=>text.trim().split('\n').map((l,i)=>SOC.parseLine(l,i+1)).filter(Boolean);
const events=parse(zlib.gunzipSync(fs.readFileSync(root+'/clinica-investigacao-205k.jsonl.gz')).toString('utf8'));
const cases=SOC.detect(events).incidents;
const testResults=[];
function test(name,fn){fn();testResults.push({name,status:'passed'});}
function fresh(){
  const ctx={S:{contained:new Map(),set:{analyst:'teste-tecnico'}},entries:[],toasts:[],render(){},recordHumanDecision(){},Date,Number};
  ctx.audit=(type,inc,detail)=>ctx.entries.push({type,id:inc.id,detail});
  ctx.toast=message=>ctx.toasts.push(message);
  const code=ui.slice(ui.indexOf('function actionReadiness('),ui.indexOf('function monitor('))+
    ui.slice(ui.indexOf('function block('),ui.indexOf('function release('))+
    ui.slice(ui.indexOf('function release('),ui.indexOf('function reopen('));
  vm.createContext(ctx);vm.runInContext(code,ctx);return ctx;
}
test('Os 205 mil eventos e os quatro casos continuam sendo interpretados',()=>{assert.equal(events.length,205000);assert.equal(cases.length,4);assert.deepEqual(cases.map(i=>i.sev.level),['alta','media','alta','baixa']);});
test('Nenhuma contenção é aplicada apenas por detectar um incidente',()=>{assert.ok(cases.every(i=>!i.decision));});
for(const item of cases){
  test(`${item.id}: bloqueio manual e reversão funcionam sem triagem prévia`,()=>{
    const ctx=fresh(),inc=structuredClone(item);
    assert.ok(!inc.ai && !inc.humanReview);
    assert.equal(ctx.actionReadiness(inc),'');
    ctx.block(inc,45,'Autorização manual em teste técnico');
    assert.equal(inc.decision.state,'active');
    assert.ok(inc.decision.steps.every(s=>s.result==='executado (simulado)'));
    assert.equal(ctx.entries[0].type,'DECISAO_BLOQUEIO');
    ctx.release(inc,'manual');assert.equal(inc.decision.state,'released');assert.equal(ctx.S.contained.size,0);
    assert.equal(ctx.entries.at(-1).type,'CONTENCAO_REVERTIDA');
  });
}
test('Exportação recusada permanece como evidência e não impede contenção manual',()=>{const ctx=fresh(),inc=structuredClone(cases[1]);assert.equal(inc.facts.export_denied,true);assert.ok(inc.contextNote);assert.equal(ctx.actionReadiness(inc),'');});
test('Autorização e severidade baixa permanecem visíveis sem proibir a decisão manual',()=>{const ctx=fresh(),inc=structuredClone(cases[3]);assert.equal(inc.facts.approved_context,true);assert.ok(inc.sev.authorized);assert.equal(ctx.actionReadiness(inc),'');});
test('JSON inválido continua sendo recusado pela validação, sem impedir resposta manual',()=>{const ctx=fresh(),inc=structuredClone(cases[0]);const proposed=SOC.simTriage(inc);proposed.evidence_ids=['inventado'];assert.equal(SOC.validateTriage(proposed,inc).ok,false);inc.ai={status:'invalid'};ctx.block(inc,45,'Decisão manual independente da IA');assert.equal(inc.decision.state,'active');});
test('Uma sugestão baixa do modelo não veta a contenção decidida pelo operador',()=>{const ctx=fresh(),inc=structuredClone(cases[0]);inc.ai={status:'ok',parsed:{severity:'baixa'}};ctx.block(inc,45,'Autorização manual');assert.equal(inc.decision.state,'active');});
test('Não há lista fixa de hosts que impeça a ação simulada',()=>{const ctx=fresh(),inc={id:'TESTE-HOST',key:'ransom',entities:{ips:[],users:['teste'],hosts:['SRV-AD-01','SRV-AV-01','SRV-DNS-01']}};inc.plan=SOC.planFor(inc);assert.equal(inc.plan.steps.length,4);assert.ok(inc.plan.steps.every(s=>!s.protectedAsset));ctx.block(inc,45,'Teste de simulação');assert.equal(inc.decision.state,'active');});
test('Ação sem alvo válido é recusada como erro técnico',()=>{const ctx=fresh(),inc=structuredClone(cases[0]);inc.plan.steps[0].target='';ctx.block(inc,45,'');assert.ok(!inc.decision);assert.equal(ctx.entries[0].type,'ACAO_INVALIDA');});
test('Prazo inválido não gera uma ação ou expiração incoerente',()=>{const ctx=fresh(),inc=structuredClone(cases[0]);ctx.block(inc,NaN,'');assert.ok(!inc.decision);assert.equal(ctx.S.contained.size,0);});
test('As oito famílias da amostra anterior continuam sendo detectadas',()=>{const old=parse(zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'fixtures/amostra-infra.log.gz'))).toString('utf8'));assert.equal(SOC.detect(old).incidents.length,8);});
test('O HTML contém exatamente o mesmo motor e interface distribuídos',()=>{assert.ok(src.includes(fs.readFileSync(root+'/motor.js','utf8')));assert.ok(src.includes(ui));assert.ok(!/policyReason|protectedAsset|POLITICA_NEGOU/.test(ui));});
const report={kind:'software_validation',app_version:JSON.parse(fs.readFileSync(root+'/manifesto.json','utf8')).app_version,human_comparative_study:false,tests:testResults.length,results:testResults};
fs.mkdirSync(root+'/validacao',{recursive:true});fs.writeFileSync(root+'/validacao/ultima-validacao-resposta-manual.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
