
(() => {
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nf = (n) => Number(n).toLocaleString("pt-BR");
const pad = (n) => String(n).padStart(2, "0");
const L = (t) => new Date(t); // horário do próprio log (UTC)
const fT = (t) => L(t).toISOString().slice(11, 19);
const fHM = (t) => L(t).toISOString().slice(11, 16);
const fD = (t) => { const d = L(t); return pad(d.getUTCDate()) + "/" + pad(d.getUTCMonth() + 1); };
const REC = { investigar_conta: "Investigar conta", monitorar: "Monitorar", avaliar_contencao: "Avaliar contenção" };
const KIND = { fw_block_ip: "Firewall", disable_account: "Conta", kill_session: "Sessão", quarantine_ip: "Quarentena", isolate_host: "Isolar host", dns_sinkhole: "DNS", remove_group: "Grupo" };
const TTLS = [[45, "45 s (padrão do TCC)"], [300, "5 minutos"], [1800, "30 minutos"], [14400, "4 horas"], [0, "Até desbloquear"]];

const S = {
  sessionId: crypto.randomUUID(), executionKind: new URLSearchParams(location.search).has('validation') ? 'software_validation' : 'demonstration',
  events: [], incs: [], file: "", lines: 0, sample: false, sel: null, provider: ["manual","ollama"].includes(new URLSearchParams(location.search).get("provider")) ? new URLSearchParams(location.search).get("provider") : "sim", loading: null,
  audit: [], showAudit: false, showSet: false, showReport:false, reportMode:'edit', reportDraft:null, reportPrevious:null, reportSource:null, evLimit: 60, batch: null,
  set: { analyst: "analista-demo", ttl: 45, ollamaUrl: location.protocol === "http:" && location.hostname === "127.0.0.1" ? "/ollama" : "http://localhost:11434", model: "qwen2.5:1.5b", authorized: "" },
  datasetInfo: null, claudeOK: false, contained: new Map(), ollamaMsg: "", t0: 0, t1: 0,
};
let sampleFn = null, dlFn = null;

/* ---------- auditoria ---------- */
let saveTimer;
function queueSessionSave() {
  if (location.protocol === 'http:' && location.hostname === '127.0.0.1') {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => fetch('/sessao', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(auditPayload()) }).catch(() => {}), 200);
  }
}
function audit(type, inc, detail) {
  S.audit.push({ seq: S.audit.length + 1, ts: new Date().toISOString(), actor: type.startsWith("IA") || type === "LOG_CARREGADO" || type === "INCIDENTE_DETECTADO" ? "sistema" : S.set.analyst, type, incident: inc ? inc.id : "", detail });
  queueSessionSave();
}
async function sha(text) {
  try { const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)); return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("").slice(0, 16); }
  catch { let h = 2166136261; for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16); }
}

/* ---------- carga do log ---------- */
const tick = () => new Promise((r) => setTimeout(r, 0));
async function loadStream(file) {
  S.loading = { name: file.name, pct: 0 }; render();
  const events = []; let source = file.stream();
  if (/\.gz$/i.test(file.name || '')) {
    if (typeof DecompressionStream === 'undefined') throw new Error('Este navegador não suporta gzip. Carregue o TXT fornecido.');
    source = source.pipeThrough(new DecompressionStream('gzip'));
  }
  const reader = source.getReader(); const dec = new TextDecoder();
  let buf = "", n = 0, read = 0, k = 0;
  for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    read += value.length; buf += dec.decode(value, { stream: true });
    let last = 0, idx;
    while ((idx = buf.indexOf("\n", last)) >= 0) { n++; const e = SOC.parseLine(buf.slice(last, idx).replace(/\r$/, ""), n); if (e) events.push(e); last = idx + 1; }
    buf = buf.slice(last);
    if (++k % 4 === 0) { S.loading.pct = Math.min(99, Math.round((read / file.size) * 100)); const p = $("#pg"); if (p) p.style.width = S.loading.pct + "%"; await tick(); }
  }
  buf += dec.decode();
  if (buf.trim()) { n++; const e = SOC.parseLine(buf, n); if (e) events.push(e); }
  return { events, lines: n };
}
function loadText(text) {
  const events = []; let n = 0;
  for (const ln of text.split("\n")) { n++; const e = SOC.parseLine(ln.replace(/\r$/, ""), n); if (e) events.push(e); }
  return { events, lines: n };
}
async function ingest({ events, lines }, name, isSample) {
  if (!events.length) { S.loading = null; S.error = "Nenhum evento no formato chave=valor com data ISO foi encontrado nesse arquivo."; render(); return; }
  if (ctl) ctl.abort();
  if (S.reportDraft) persistReportDraft();
  if (S.events.length) S.sessionId=crypto.randomUUID();
  S.showReport=false; S.reportDraft=null; S.reportPrevious=null; S.reportSource=null;
  S.error = ""; S.contained.clear();
  const analysisStart = performance.now();
  const r = SOC.detect(events, { authorized: authList() });
  S.datasetInfo = { detection_ms: Math.round(performance.now() - analysisStart), rejected_lines: lines - events.length };
  S.events = r.events; S.incs = r.incidents; S.file = name; S.lines = lines; S.sample = isSample; S.loading = null; S.evLimit = 60;
  S.t0 = r.events[0].t; S.t1 = r.events[r.events.length - 1].t;
  S.audit = [];
  audit("LOG_CARREGADO", null, `${name}: ${lines} linhas, ${events.length} eventos válidos`);
  for (const i of S.incs) audit("INCIDENTE_DETECTADO", i, `${i.title}; prioridade ${i.sev.level} (regra); ${i.evCount} evidências; ${i.mitre.join(", ")}${i.campaign ? "; " + i.campaign : ""}`);
  S.sel = S.incs.length ? S.incs[0].id : null;
  render();
  if (S.provider !== "manual") await triageAll();
}
const authList = () => S.set.authorized.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

/* ---------- triagem (IA) ---------- */
let ctl = null;
async function triage(inc, signal) {
  const prov = S.provider;
  if (prov === "manual") { toast("Modo manual: registre a classificação na revisão de severidade."); return; }
  inc.ai = { status: "running", provider: prov, model: "" }; render();
  const input = SOC.buildAIInput(inc), prompt = SOC.renderPrompt(inc), hash = await sha(JSON.stringify(input) + prompt);
  const t0 = performance.now(); let raw = null, obj = null, model = "";
  try {
    if (prov === "sim") { obj = SOC.simTriage(inc); raw = JSON.stringify(obj); model = "fixture"; }
    else if (prov === "ollama") {
      model = S.set.model;
      const res = await fetch(S.set.ollamaUrl.replace(/\/$/, "") + "/api/chat", { method: "POST", signal, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, stream: false, format: SOC.SCHEMA([SOC.THREATS[inc.scenario], "inconclusivo"]), options: { temperature: 0, num_ctx: 4096, num_predict: 900 }, messages: [{ role: "user", content: prompt }] }) });
      if (!res.ok) throw new Error("Ollama respondeu HTTP " + res.status);
      raw = (await res.json()).message.content; obj = JSON.parse(raw);
    } else {
      model = "Claude (sample)";
      const out = await sampleFn.json(prompt, { signal, modelTier: "default" }); obj = out; raw = JSON.stringify(out);
    }
    const v = SOC.validateTriage(obj, inc);
    inc.ai = { status: v.ok ? "ok" : "invalid", provider: prov, model, raw, parsed: v.ok ? obj : null, errors: v.errors, ms: Math.round(performance.now() - t0), hash, prompt, input };
    audit(v.ok ? "IA_TRIAGEM_VALIDADA" : "IA_TRIAGEM_INVALIDA", inc, `provedor=${prov}; modelo=${model}; prompt=${SOC.PROMPT_VERSION}; entrada_sha256=${hash}; ${Math.round(performance.now() - t0)} ms${v.ok ? "; sugestão=" + obj.severity : "; erros=" + v.errors.join(" | ")}`);
  } catch (e) {
    if (e && (e.code === "cancelled" || e.name === "AbortError")) { inc.ai = { status: "idle" }; render(); throw e; }
    let msg = e && e.message ? e.message : String(e);
    if (e && e.code === "not_granted") msg = "Você não autorizou o uso do Claude nesta página.";
    else if (e && e.code === "rate_limited") msg = "Limite de uso atingido. Tente de novo mais tarde.";
    else if (e && e.code === "invalid_json") msg = "O Claude não devolveu um JSON válido.";
    else if (prov === "ollama" && /Failed to fetch|NetworkError|Load failed/i.test(msg)) msg = "Não foi possível falar com o Ollama em " + S.set.ollamaUrl + ". Confira se ele está rodando e se OLLAMA_ORIGINS permite esta página. Em artefatos publicados o navegador pode bloquear o acesso a localhost; baixe o arquivo HTML e abra no seu computador.";
    inc.ai = { status: "error", provider: prov, model, message: msg, hash, prompt, input, raw: e && e.text };
    audit("IA_TRIAGEM_FALHOU", inc, `provedor=${prov}; ${msg}`);
  }
  render();
}
async function triageAll() {
  if (S.batch || S.provider === "manual") return;
  ctl = new AbortController(); S.batch = { i: 0, n: S.incs.length }; render();
  try { for (const inc of S.incs) { S.batch.i++; if (inc.decision && inc.decision.state === "active") continue; await triage(inc, ctl.signal); } }
  catch (e) { /* cancelado */ }
  S.batch = null; ctl = null; render();
}

/* ---------- decisão humana ---------- */
function startHumanReview(inc) {
  if (inc.humanReview && !inc.humanReview.completed_at) return;
  if (inc.humanReview) { if (!inc.humanHistory) inc.humanHistory=[]; inc.humanHistory.push(inc.humanReview); }
  inc.humanReview = { kind:S.executionKind === 'software_validation' ? 'software_validation' : 'guided_human_review',
    analyst:S.set.analyst, started_at:new Date().toISOString(), start_monotonic:performance.now() };
  audit('REVISAO_HUMANA_INICIADA', inc, 'Revisão guiada; relógio inicia no clique do participante. A classificação termina em Salvar severidade.');
  render();
}
function completeHumanReview(inc, note) {
  const h=inc.humanReview;
  if (!h || h.completed_at) return;
  h.completed_at=new Date().toISOString(); h.classification_ms=Math.round(performance.now()-h.start_monotonic);
  h.severity=effectiveSeverity(inc); h.justification=note; h.ai_visible=!!(inc.ai && inc.ai.status==='ok');
  audit('REVISAO_HUMANA_CONCLUIDA',inc,`revisao_guiada_ms=${h.classification_ms}; severidade=${h.severity}; justificativa=${note}`);
}
function recordHumanDecision(inc, decision) {
  const h=inc.humanReview;
  if (!h) return;
  h.decision=decision; h.decision_at=new Date().toISOString(); h.review_to_decision_ms=Math.round(performance.now()-h.start_monotonic);
}
const effectiveSeverity = (i) => i.manualSeverity ? i.manualSeverity.level : i.sev.level;
function changeSeverity(inc, level, note) {
  note = note.trim();
  if (level !== 'rule' && !SOC.SEV.includes(level)) return;
  if (note.length < 5 || note.length > 300) { toast('Informe uma justificativa de 5 a 300 caracteres.'); return; }
  const before = effectiveSeverity(inc);
  const previous = inc.manualSeverity || null;
  inc.manualSeverity = level === 'rule' ? null : { level, note, by:S.set.analyst, at:new Date().toISOString() };
  completeHumanReview(inc, note);
  audit('SEVERIDADE_AJUSTADA', inc, `anterior=${before}; atual=${effectiveSeverity(inc)}; regra=${inc.sev.level}; origem=${level === 'rule' ? 'regra restaurada' : 'analista'}; justificativa=${note}`);
  if (!inc.severityHistory) inc.severityHistory = [];
  inc.severityHistory.push({ previous, current:inc.manualSeverity, rule:inc.sev.level, by:S.set.analyst, note, at:new Date().toISOString() });
  render();
}
const sel = () => S.incs.find((i) => i.id === S.sel);
function actionReadiness(inc) {
  if (!inc || !inc.plan || !Array.isArray(inc.plan.steps) || !inc.plan.steps.length)
    return 'Não há ação simulada definida para este incidente.';
  if (inc.plan.steps.some((s) => !s || typeof s.kind !== 'string' || !s.kind.trim() || typeof s.target !== 'string' || !s.target.trim()))
    return 'A ação precisa de um tipo e um alvo válidos.';
  return '';
}
function monitor(inc, note) {
  inc.decision={type:'monitoring',state:'monitoring',id:'MON-'+inc.id.slice(4)+'-'+Date.now().toString(36).toUpperCase(),at:Date.now(),by:S.set.analyst,note};
  recordHumanDecision(inc,'investigar_e_acompanhar_sem_contencao');
  audit('DECISAO_ACOMPANHAMENTO',inc,`${inc.decision.id}; acompanhar e investigar; não declara a atividade legítima; justificativa=${note}`);
  render();
}
function approve(inc, note) {
  inc.decision = { type: "approved", state: "approved", id: "APR-" + inc.id.slice(4) + "-" + Date.now().toString(36).toUpperCase(), at: Date.now(), by: S.set.analyst, note };
  recordHumanDecision(inc, "acompanhar_sem_contencao");
  audit("DECISAO_APROVADA", inc, `${inc.decision.id}; atividade tratada como legítima, sem contenção${note ? "; nota: " + note : ""}`);
  render();
}
function block(inc, ttlS, note) {
  const why = actionReadiness(inc);
  if (why) { audit("ACAO_INVALIDA", inc, why); toast(why); return; }
  if (!Number.isFinite(ttlS) || ttlS < 0) { toast('O prazo precisa ser um número igual ou maior que zero.'); return; }
  const id = "APR-" + inc.id.slice(4) + "-" + Date.now().toString(36).toUpperCase();
  const steps = inc.plan.steps.map((s) => {
    const key = s.kind + ":" + s.target;
    if (S.contained.has(key)) return Object.assign({}, s, { result: "já contido por " + S.contained.get(key).inc });
    S.contained.set(key, { inc: inc.id, dec: id });
    return Object.assign({}, s, { result: "executado (simulado)", owns: key });
  });
  const now = Date.now();
  inc.decision = { type: "blocked", state: "active", id, at: now, by: S.set.analyst, note, ttlS, expiresAt: ttlS ? now + ttlS * 1000 : 0, steps };
  recordHumanDecision(inc, "contencao_simulada_aprovada");
  audit("DECISAO_BLOQUEIO", inc, `${id}; ttl=${ttlS ? ttlS + " s" : "até desbloquear"}; ${steps.map((s) => s.kind + ":" + s.target + " -> " + s.result).join(" | ")}${note ? "; nota: " + note : ""}`);
  render();
}
function release(inc, why) {
  const d = inc.decision; if (!d || d.state !== "active") return;
  d.steps.forEach((s) => { if (s.owns) S.contained.delete(s.owns); });
  d.state = why === "expirou" ? "expired" : "released"; d.releasedAt = Date.now();
  audit(why === "expirou" ? "CONTENCAO_EXPIROU" : "CONTENCAO_REVERTIDA", inc, `${d.id}; ${why === "expirou" ? "prazo de " + d.ttlS + " s terminou" : "desbloqueio manual"}; acesso restabelecido (simulado)`);
  render();
}
function reopen(inc) { audit("DECISAO_REABERTA", inc, `${inc.decision.id} reaberta para nova análise`); inc.decision = null; render(); }

/* ---------- contagem regressiva ---------- */
setInterval(() => {
  const now = Date.now(); let changed = false;
  for (const i of S.incs) if (i.decision && i.decision.state === "active" && i.decision.expiresAt && i.decision.expiresAt <= now) { release(i, "expirou"); changed = true; }
  if (changed) return;
  document.querySelectorAll("[data-exp]").forEach((el) => { const s = Math.max(0, Math.ceil((+el.dataset.exp - now) / 1000)); el.textContent = pad(Math.floor(s / 60)) + ":" + pad(s % 60); });
}, 1000);

/* ---------- exportar / toasts ---------- */
let toastT;
function toast(msg) { let el = $("#toast"); if (!el) { el = document.createElement("div"); el.id = "toast"; el.setAttribute("role", "status"); el.style.cssText = "position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:6px;z-index:50;max-width:90vw;font-size:13px"; document.body.appendChild(el); } el.textContent = msg; el.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (el.hidden = true), 4500); }
async function saveFile(name, text, mime='application/json') {
  try { if (dlFn) { await dlFn.save({ filename: name, data: text }); return true; } } catch (e) { if (e && e.code === "declined") return false; }
  try { const a = document.createElement("a"), url=URL.createObjectURL(new Blob([text], { type: mime })); a.href=url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); return true; }
  catch { toast("Não foi possível salvar o arquivo neste ambiente."); return false; }
}
function auditPayload() {
  return { sessao:S.sessionId, tipo_execucao:S.executionKind, versao_app: "soc-web-205k-report-3", relatorio_t2:S.reportDraft, ferramenta: "Autonomous SOC Tier 1", exportado_em: new Date().toISOString(), analista: S.set.analyst, prompt_versao: SOC.PROMPT_VERSION, log: { arquivo: S.file, analise: S.datasetInfo, linhas: S.lines, eventos: S.events.length, amostra: S.sample },
    incidentes: S.incs.map((i) => ({ id: i.id, campanha: i.campaign, titulo: i.title, estagio: i.stage, prioridade_regra: i.sev.level, prioridade_final: effectiveSeverity(i), revisao_severidade: i.manualSeverity || null, historico_severidade: i.severityHistory || [], revisao_humana:i.humanReview || null, historico_revisoes:i.humanHistory || [], mitre: i.mitre, evidencias: i.evCount, ia: i.ai && i.ai.status !== "idle" ? { status: i.ai.status, provedor: i.ai.provider, modelo: i.ai.model, entrada_sha256: i.ai.hash, resposta: i.ai.parsed || null, tempo_ms: i.ai.ms ?? null, erros: i.ai.errors || i.ai.message || null } : null,
      decisao: i.decision ? { tipo: i.decision.type, estado: i.decision.state, id: i.decision.id, por: i.decision.by, nota: i.decision.note || "", ttl_s: i.decision.ttlS, passos: i.decision.steps || [] } : null })), auditoria: S.audit };
}
function exportAudit() { saveFile('auditoria-soc-tier1.json', JSON.stringify(auditPayload(), null, 2)); }

/* ---------- relatório T2: texto editável, separado dos registros de origem ---------- */
let reportSaveTimer;
function reportPayload() {
  const payload=auditPayload();
  delete payload.relatorio_t2;
  payload.incidentes=payload.incidentes.map(row=>{
    const inc=S.incs.find(i=>i.id===row.id), ids=new Set(inc.aiEvidenceIds||[]);
    return {...row,entidades:inc.entities,fatos:Object.fromEntries(Object.entries(inc.facts||{}).map(([k,v])=>[SOC.FACT_LABELS[k]||k,v])),
      evidencias_referencia:inc.evidence.filter(e=>ids.has(SOC.evId(e.n))).map(e=>({id:SOC.evId(e.n),source_id:e.source_id||null,timestamp:e.ts,event:e.event||e.service||e.action}))};
  });
  return payload;
}
function reportOrigin() { return S.reportSource||reportPayload(); }
function reportRevision(source) {
  return JSON.stringify([source.sessao,(source.auditoria||[]).filter(a=>!String(a.type).startsWith('RELATORIO_T2_')).map(a=>a.seq),
    (source.incidentes||[]).map(i=>[i.id,i.prioridade_final,i.ia&&i.ia.status,i.decisao&&i.decisao.id,i.decisao&&i.decisao.estado])]);
}
function reportSavedState(message) { const el=$('#t2-save-state'); if(el)el.textContent=message; }
function persistReportDraft() {
  clearTimeout(reportSaveTimer);
  if(!S.reportDraft)return false;
  try {
    S.reportDraft.saved_at=new Date().toISOString();
    localStorage.setItem(S.reportDraft.storage_key,JSON.stringify({draft:S.reportDraft,previous:S.reportPrevious}));
    queueSessionSave(); reportSavedState('Rascunho salvo neste navegador.'); return true;
  }catch { reportSavedState('Não foi possível salvar no navegador. Você ainda pode baixar o TXT.'); return false; }
}
function generateReport() {
  const source=reportOrigin(), now=new Date().toISOString();
  if(S.reportDraft)S.reportPrevious={...S.reportDraft};
  S.reportDraft={text:SocReport.createReport(source,{generatedAt:now}),generated_at:now,edited_at:null,saved_at:null,
    source_session_id:source.sessao,source_log:source.log&&source.log.arquivo,source_revision:reportRevision(source),storage_key:SocReport.draftKey(source)};
  audit('RELATORIO_T2_GERADO',null,`origem_sessao=${source.sessao}; casos=${source.incidentes.length}`);
  persistReportDraft();
}
function openReport(source=null) {
  S.reportSource=source;
  const origin=reportOrigin(), key=SocReport.draftKey(origin);
  if(!S.reportDraft||S.reportDraft.storage_key!==key||(source&&S.reportDraft.source_session_id!==source.sessao)) {
    S.reportDraft=null;S.reportPrevious=null;
    try {
      const saved=JSON.parse(localStorage.getItem(key)||'null');
      if(saved&&saved.draft&&typeof saved.draft.text==='string'&&(!source||saved.draft.source_session_id===source.sessao)) {
        S.reportDraft=saved.draft;S.reportPrevious=saved.previous&&typeof saved.previous.text==='string'?saved.previous:null;
      }
    }catch {}
    if(!S.reportDraft)generateReport();
  }
  S.showAudit=false;S.showSet=false;S.showReport=true;S.reportMode='edit';render();
}
async function openSavedReport(id) {
  if(!/^[a-f0-9-]{36}$/i.test(id))throw new Error('Identificador de sessão inválido.');
  const response=await fetch('/sessao/'+encodeURIComponent(id));
  if(!response.ok)throw new Error('Não foi possível abrir a sessão salva.');
  const source=await response.json();
  if(source.sessao!==id||!Array.isArray(source.incidentes))throw new Error('Registro da sessão inválido.');
  openReport(source);
}
function reportInput(event) {
  S.reportDraft.text=event.target.value; S.reportDraft.edited_at=new Date().toISOString();
  reportSavedState('Salvando rascunho…');clearTimeout(reportSaveTimer);
  reportSaveTimer=setTimeout(persistReportDraft,400);
}
function saveReport() {
  persistReportDraft();
  audit('RELATORIO_T2_SALVO',null,`origem_sessao=${S.reportDraft.source_session_id}; caracteres=${S.reportDraft.text.length}; texto editável separado dos registros de origem`);
  toast('Rascunho do relatório salvo.');
}
async function downloadReport() {
  persistReportDraft();
  const name='relatorio-t2-'+String(S.reportDraft.source_session_id||S.sessionId).slice(0,8)+'.txt';
  if(await saveFile(name,S.reportDraft.text,'text/plain;charset=utf-8'))
    audit('RELATORIO_T2_BAIXADO',null,`arquivo=${name}; origem_sessao=${S.reportDraft.source_session_id}; nenhum envio ao time foi realizado pelo aplicativo`);
}
function reportHTML() {
  const d=S.reportDraft, origin=reportOrigin();
  if(!d)return '';
  const stale=d.source_revision!==reportRevision(origin);
  return `<div class="overlay" id="ov-report"><section class="panel report-panel" role="dialog" aria-modal="true" aria-labelledby="report-title">
    <h2 id="report-title">Relatório para o T2<button class="btn" id="b-report-close">Fechar</button></h2>
    <p class="muted sm">Edite o resumo, confira a versão para leitura e baixe o TXT para anexar ao chamado ou enviar ao time.</p>
    <p class="sm"><b>Origem:</b> ${esc(d.source_log||'arquivo não informado')} · sessão ${esc(d.source_session_id||'não informada')}${S.reportSource?' · registro salvo':''}</p>
    ${stale?'<p class="note">Há dados diferentes na origem deste rascunho. Suas edições foram preservadas; use “Atualizar dados” para gerar outra versão.</p>':''}
    <div class="report-toolbar"><button class="btn${S.reportMode==='edit'?' primary':''}" id="b-report-edit" aria-pressed="${S.reportMode==='edit'}">Editar</button><button class="btn${S.reportMode==='preview'?' primary':''}" id="b-report-preview" aria-pressed="${S.reportMode==='preview'}">Visualizar</button><button class="btn" id="b-report-save">Salvar rascunho</button><button class="btn primary" id="b-report-download">Baixar TXT</button><button class="btn" id="b-report-refresh">Atualizar dados</button>${S.reportPrevious?'<button class="btn" id="b-report-undo">Restaurar versão anterior</button>':''}</div>
    ${S.reportMode==='edit'?`<label class="report-label" for="t2-editor">Texto do relatório editável</label><textarea id="t2-editor" class="report-editor" spellcheck="true">${esc(d.text)}</textarea>`:`<pre class="report-preview" aria-label="Prévia do relatório">${esc(d.text)}</pre>`}
    <p id="t2-save-state" class="muted sm" role="status">${d.saved_at?'Rascunho salvo neste navegador.':'Rascunho ainda não salvo.'}</p>
    <p class="muted sm">Editar este relatório não altera as evidências, a severidade ou a auditoria original. Para o encaminhamento, anexe também os logs de origem e o JSON da auditoria.</p>
  </section></div>`;
}

/* ---------- render ---------- */
function chipSev(l) { return `<span class="chip ${l}">${l === "media" ? "média" : l}</span>`; }
function chipStatus(i) {
  const d = i.decision;
  if (!d) return `<span class="chip pend">Pendente</span>`;
  if (d.type === "monitoring") return `<span class="chip apr">Acompanhamento</span>`;
  if (d.type === "approved") return `<span class="chip apr">Aprovado</span>`;
  if (d.state === "active") return `<span class="chip blk">Bloqueado</span>`;
  return `<span class="chip rel">${d.state === "expired" ? "Expirou" : "Desbloqueado"}</span>`;
}
function render() {
  const app = $("#app");
  const keepQ = $(".queue") ? $(".queue").scrollTop : 0, keepW = window.scrollY;
  const focusId = document.activeElement && document.activeElement.id;
  const caret = document.activeElement && document.activeElement.selectionStart;
  app.innerHTML = topHTML() + (S.loading ? loadingHTML() : S.incs.length || S.events.length ? mainHTML() : emptyHTML()) + (S.showAudit ? auditHTML() : "") + (S.showSet ? settingsHTML() : "") + (S.showReport ? reportHTML() : "");
  bind();
  const q = $(".queue"); if (q) q.scrollTop = keepQ;
  if (focusId) { const el = document.getElementById(focusId); if (el) { el.focus(); try { if (caret != null && el.setSelectionRange) el.setSelectionRange(caret, caret); } catch {} } }
  window.scrollTo(0, keepW);
}
function topHTML() {
  return `<header class="top"><div class="brand"><b>Autonomous SOC</b><span class="tier">Tier 1</span></div>
  <div class="ctl"><label for="prov">IA de triagem</label><select id="prov" aria-label="IA de triagem"${S.batch || S.loading ? " disabled" : ""}>
    <option value="manual"${S.provider === "manual" ? " selected" : ""}>Manual · sem IA</option>
    <option value="sim"${S.provider === "sim" ? " selected" : ""}>Simulada (fixture)</option>
    <option value="ollama"${S.provider === "ollama" ? " selected" : ""}>Ollama local</option>
    <option value="claude"${S.provider === "claude" ? " selected" : ""}${S.claudeOK ? "" : " disabled"}>Claude${S.claudeOK ? "" : " (indisponível aqui)"}</option></select></div>
  <button class="btn" id="b-set">Ajustes</button><button class="btn" id="b-aud">Auditoria<span class="badge-n">${S.audit.length}</span></button><button class="btn primary" id="b-report"${S.events.length?'':' disabled'}>Relatório T2</button></header>`;
}
function emptyHTML() { return `<div class="empty">${S.error ? `<p class="err">${esc(S.error)}</p>` : ""}<p>Carregue um log para começar.</p><button class="btn primary" id="b-load">Escolher arquivo</button></div>`; }
function loadingHTML() { return `<div class="empty"><p>Lendo <b>${esc(S.loading.name)}</b>…</p><div class="progress"><i id="pg" style="width:${S.loading.pct}%"></i></div></div>`; }
function mainHTML() {
  const cnt = { p: 0, a: 0, b: 0 };
  S.incs.forEach((i) => { if (!i.decision) cnt.p++; else if (["approved","monitoring"].includes(i.decision.type)) cnt.a++; else if (i.decision.state === "active") cnt.b++; });
  const hosts = new Set(S.events.map((e) => e.host)).size;
  const camp = campaignBanner();
  return `<section class="summary">
    <div class="stat src"><div class="l">Log</div><div class="v mono">${esc(S.file)}</div></div>
    <div class="stat"><div class="v">${nf(S.events.length)}</div><div class="l">eventos</div></div>
    <div class="stat"><div class="v">${fD(S.t0)} ${fHM(S.t0)}–${fHM(S.t1)}</div><div class="l">período (horário do log)</div></div>
    <div class="stat"><div class="v">${hosts}</div><div class="l">hosts</div></div>
    <div class="stat"><div class="v">${S.incs.length}</div><div class="l">incidentes</div></div>
    <div class="stat"><div class="v">${cnt.p}<span class="muted sm"> pend.</span> ${cnt.a}<span class="muted sm"> aprov.</span> ${cnt.b}<span class="muted sm"> bloq.</span></div><div class="l">decisões</div></div>
    <div class="sp"><button class="btn primary" id="b-all"${S.batch || !S.incs.length || S.provider === "manual" ? " disabled" : ""}>${S.batch ? `<span class="spin"></span> Analisando ${S.batch.i}/${S.batch.n}` : "Analisar todos com IA"}</button>${S.batch ? `<button class="btn" id="b-stop">Parar</button>` : ""}<button class="btn" id="b-load">Carregar outro log</button></div>
  </section>
  <div class="note">${S.sample ? 'Base completa embutida: ' : 'Arquivo carregado: '}${nf(S.events.length)} eventos analisados. Os fatos e os incidentes são derivados das regras; a triagem é ${S.provider === 'manual' ? 'manual, sem resposta de IA' : S.provider === 'sim' ? 'simulada e identificada como fixture' : S.provider === 'ollama' ? 'enviada ao Ollama local' : 'enviada ao Claude'}. A IA recebe apenas os resumos dos incidentes, não as 205 mil linhas brutas. A resposta é demonstrativa. Você pode alterar a severidade com justificativa e exportar a auditoria.</div>
  ${camp}
  ${S.incs.length ? `<div class="grid"><nav class="queue" aria-label="Fila de incidentes"><div class="qh">Fila · ordem cronológica</div>${S.incs.map(qItem).join("")}</nav><main class="detail">${detailHTML(sel() || S.incs[0])}</main></div>` : `<div class="empty">Nenhum incidente foi detectado pelas regras neste log.</div>`}`;
}
function campaignBanner() {
  const by = new Map(); S.incs.forEach((i) => { if (i.campaign) { if (!by.has(i.campaign)) by.set(i.campaign, []); by.get(i.campaign).push(i); } });
  return [...by].map(([c, list]) => {
    const cnt = new Map(); list.forEach((i) => new Set([...i.entities.ips, ...i.entities.users]).forEach((k) => cnt.set(k, (cnt.get(k) || 0) + 1)));
    const shared = [...cnt].filter(([, n]) => n >= 2).sort((a, b) => b[1] - a[1]).map(([k]) => k);
    return `<div class="banner"><b>${c}</b><span>${list.length} incidentes ligados em ${fHM(list[0].t0)}–${fHM(list[list.length - 1].t1)}:</span><span class="row">${shared.map((k) => `<span class="chip mono neutral">${esc(k)}</span>`).join("")}</span></div>`;
  }).join("");
}
function qItem(i) {
  const span = Math.max(1, S.t1 - S.t0), l = ((i.t0 - S.t0) / span) * 100, w = Math.max(0.8, ((i.t1 - i.t0) / span) * 100);
  return `<button class="q-item sev-${effectiveSeverity(i)}${i.id === S.sel ? " sel" : ""}" data-sel="${i.id}" aria-pressed="${i.id === S.sel}">
    <span class="q-top"><span class="q-id">${i.id}${i.campaign ? " · " + i.campaign : ""}</span>${chipStatus(i)}</span>
    <span class="q-title">${esc(i.title)}</span><span class="q-stage">${esc(i.stage)} · ${chipSevInline(i)}</span>
    <span class="q-track" title="Posição nas 24 h do log"><i style="left:${l.toFixed(2)}%;width:${Math.min(w, 100 - l).toFixed(2)}%"></i></span>
    <span class="q-meta">${fHM(i.t0)}–${fHM(i.t1)} · ${nf(i.evCount)} eventos${i.ai && i.ai.status === "ok" ? " · IA ✓" : ""}</span></button>`;
}
const cdText = (x) => { const s = Math.max(0, Math.ceil((x - Date.now()) / 1000)); return pad(Math.floor(s / 60)) + ":" + pad(s % 60); };
const chipSevInline = (i) => `prioridade ${effectiveSeverity(i) === "media" ? "média" : effectiveSeverity(i)}${i.manualSeverity ? " · revisada" : ""}`;

function detailHTML(i) {
  const fl = Object.entries(i.facts).map(([k, v]) => {
    const yes = v === true, no = v === false;
    return `<div class="fact ${yes ? "yes" : no ? "no" : ""}"><div class="l">${esc(SOC.FACT_LABELS[k] || k)}</div><div class="v">${yes ? "sim" : no ? "não" : nf(v)}</div></div>`;
  }).join("");
  const e = i.entities;
  const ent = (k, arr, cls = "mono") => arr && arr.length ? `<div class="k">${k}</div><div class="row">${arr.map((x) => `<span class="chip ${cls} neutral">${esc(x)}</span>`).join("")}</div>` : "";
  return `<section class="card dhead"><div class="row"><span class="chip mono neutral">${i.id}</span>${i.campaign ? `<span class="chip mono info">${i.campaign}</span>` : ""}<span class="chip tag">${esc(i.stage)}</span>${chipStatus(i)}</div>
    <h2>${esc(i.title)}</h2>
    <div class="row"><span class="muted sm">Prioridade pelas regras</span>${chipSev(i.sev.level)}<span class="muted sm">${fD(i.t0)} ${fT(i.t0)} a ${fT(i.t1)} · ${nf(i.evCount)} eventos</span></div>
    <p class="why">${i.sev.why.map(esc).join(" ")}</p>
    <div class="row"><b>Severidade final:</b>${chipSev(effectiveSeverity(i))}<span class="muted sm">${i.manualSeverity ? 'revisada por ' + esc(i.manualSeverity.by) : 'classificação da regra'}</span></div>
    ${i.manualSeverity ? `<p class="why">Justificativa: ${esc(i.manualSeverity.note)}</p>` : ''}
    <section class="human-review"><h3>Revisão humana guiada</h3>
      <p class="muted sm">Clique em iniciar, confira os fatos e registre a classificação em “Alterar severidade”. O tempo é de revisão guiada; não é MTTD ou MTTR operacional.</p>
      ${!i.humanReview || i.humanReview.completed_at ? `<button class="btn" id="b-human">${i.humanReview ? 'Iniciar outra revisão' : 'Iniciar revisão humana'}</button>` : `<p class="why"><b>Revisão em andamento.</b> Leia as evidências, escolha a severidade e salve a justificativa para concluir a classificação.</p>`}
      ${i.humanReview && i.humanReview.completed_at ? `<p class="why">Classificação registrada em ${(i.humanReview.classification_ms/1000).toFixed(3)} s · ${esc(i.humanReview.kind === 'software_validation' ? 'teste técnico' : 'revisão humana guiada')}.</p>` : ''}
    </section>
    <details><summary>Alterar severidade do incidente</summary>
      <div class="dctl"><div class="f"><label for="severity-review">Severidade final</label><select id="severity-review"><option value="rule"${!i.manualSeverity ? ' selected' : ''}>Usar classificação da regra</option>${SOC.SEV.map((v) => `<option value="${v}"${i.manualSeverity && i.manualSeverity.level === v ? ' selected' : ''}>${v === 'media' ? 'Média' : v === 'alta' ? 'Alta' : 'Baixa'}</option>`).join('')}</select></div>
      <div class="f grow"><label for="severity-note">Justificativa obrigatória</label><input id="severity-note" maxlength="300" placeholder="Explique a evidência que motivou a revisão"></div></div>
      <button class="btn primary" id="b-severity">Salvar severidade</button><p class="muted sm">A regra e a sugestão da IA são preservadas. A decisão de resposta cabe ao analista.</p>
    </details></section>
  <section class="card"><h3>O que o código encontrou<span class="r muted sm">Fatos derivados das regras, sem IA</span></h3><div class="facts">${fl}</div>
    <div class="ents">${ent("Origem (IP)", e.ips)}${ent("Contas", e.users)}${ent("Hosts", e.hosts)}${e.domains && e.domains.length ? ent("Domínio", e.domains) : ""}${ent("Técnicas", i.mitre.map((t) => t + " " + (SOC.MITRE_NAMES[t] || "")), "mono")}</div></section>
  ${aiHTML(i)}${decideHTML(i)}${evidHTML(i)}`;
}
function aiHTML(i) {
  const a = i.ai || { status: "idle" };
  const prov = a.provider === "sim" ? `<span class="prov sim">Simulado</span>` : a.provider === "ollama" ? `<span class="prov">Ollama · ${esc(a.model)}</span>` : a.provider === "claude" ? `<span class="prov">Claude</span>` : "";
  let body = "";
  if (S.provider === 'manual' && a.status === 'idle') body = '<p>Modo manual. Confira os fatos e as evidências e registre sua própria classificação acima. Para chamar o modelo depois, selecione Ollama local.</p>';
  else if (a.status === "idle") body = `<p class="muted" style="margin:0 0 10px">A IA ainda não analisou este incidente. Ela recebe só números e sinais (veja a entrada abaixo), nunca contas, IPs, hosts nem texto bruto.</p><button class="btn primary" id="b-ai">Analisar com ${S.provider === "sim" ? "a IA simulada" : S.provider === "ollama" ? "o Ollama" : "o Claude"}</button>`;
  else if (a.status === "running") body = `<p><span class="spin"></span> Analisando…</p>`;
  else if (a.status === "error") body = `<p class="err" style="margin:0 0 10px">${esc(a.message)}</p><button class="btn" id="b-ai">Tentar de novo</button>`;
  else if (a.status === "invalid") body = `<p class="err" style="margin:0 0 6px"><b>Resposta recusada pela validação.</b> Confira os fatos e decida a resposta manualmente.</p><ul class="err" style="margin:0 0 10px;padding-left:18px">${a.errors.map((x) => `<li>${esc(x)}</li>`).join("")}</ul><button class="btn" id="b-ai">Analisar de novo</button>`;
  else {
    const p = a.parsed, div = p.severity !== i.sev.level;
    body = `<div class="kv"><div class="k">Tipo de ameaça</div><div class="vv mono">${esc(p.threat_type)}</div>
      <div class="k">Prioridade</div><div class="vv row">${chipSev(i.sev.level)}<span class="muted sm">regra</span>${chipSev(p.severity)}<span class="muted sm">sugestão da IA</span>${div ? `<span class="chip media">diverge: vale a regra</span>` : ""}</div>
      <div class="k">Justificativa</div><div class="vv">${esc(p.severity_reason)}</div>
      <div class="k">Impacto possível</div><div class="vv">${esc(p.possible_impact)}</div>
      <div class="k">Incerteza</div><div class="vv">${esc(p.uncertainty)}</div>
      <div class="k">Recomendações</div><div class="vv row">${p.recommendations.map((r) => `<span class="chip info">${REC[r]}</span>`).join("")}<span class="muted sm">Só recomenda. Não executa.</span></div></div>
      <div class="row" style="margin-top:10px"><span class="chip ok" style="background:var(--ok-soft);color:var(--ok)">JSON validado</span><span class="muted sm">${a.ms} ms · prompt ${SOC.PROMPT_VERSION} · entrada sha256 ${a.hash}</span><button class="btn" id="b-ai" style="margin-left:auto;padding:3px 10px">Analisar de novo</button></div>`;
  }
  const det = a.input ? `<details><summary>Entrada enviada à IA</summary><p class="muted sm" style="margin:6px 0 0">Contas, IPs, hosts, sessões e texto bruto dos logs ficam de fora. A IA só recebe contagens, indicadores e IDs.</p><pre>${esc(JSON.stringify(a.input, null, 2))}</pre></details><details><summary>Prompt</summary><pre>${esc(a.prompt)}</pre></details>${a.raw ? `<details><summary>Resposta original</summary><pre>${esc(a.raw)}</pre></details>` : ""}` : "";
  return `<section class="card"><h3>Triagem da IA ${prov}<span class="r">${a.status === "ok" ? `<span class="chip apr">validada</span>` : ""}</span></h3>${body}${det}</section>`;
}
function decideHTML(i) {
  const d = i.decision, p = i.plan;
  const stepsList = (steps, withRes) => `<ul class="steps">${steps.map((s) => { const held = !withRes && S.contained.has(s.kind + ":" + s.target) && S.contained.get(s.kind + ":" + s.target).inc !== i.id; return `<li class="${(withRes && /recusado/.test(s.result)) ? "skip" : ""}"><span class="kind">${KIND[s.kind] || s.kind}</span><span>${esc(s.text)}</span>${s.heavy ? `<span class="chip tag">produção</span>` : ""}${held ? `<span class="chip info">já contido por ${S.contained.get(s.kind + ":" + s.target).inc}</span>` : ""}${withRes ? `<span class="muted sm">${esc(s.result)}</span>` : ""}</li>`; }).join("")}</ul>`;
  if (d) {
    let head;
    if (d.type === 'monitoring') head = `<div class="result"><div class="big">Investigação e acompanhamento registrados</div><div class="muted sm">${esc(d.id)} · por ${esc(d.by)} · sem nova contenção${d.note ? ' · '+esc(d.note) : ''}</div></div><div class="actions"><button class="btn" id="b-reopen">Reabrir para nova decisão</button></div>`;
    else if (d.type === "approved") head = `<div class="result"><div class="big">Aprovado como atividade legítima</div><div class="muted sm">${esc(d.id)} · por ${esc(d.by)} às ${fT(d.at + 0)} · nenhuma contenção foi aplicada${d.note ? " · nota: " + esc(d.note) : ""}</div></div><div class="actions"><button class="btn" id="b-reopen">Reabrir para nova decisão</button></div>`;
    else if (d.state === "active") head = `<div class="result"><div class="big">Bloqueado · ${d.expiresAt ? `libera em <span class="cd" data-exp="${d.expiresAt}">${cdText(d.expiresAt)}</span>` : "até desbloquear"}</div><div class="muted sm">${esc(d.id)} · por ${esc(d.by)} às ${fT(d.at)} · simulação, nada foi alterado em sistemas reais${d.note ? " · nota: " + esc(d.note) : ""}</div></div>${stepsList(d.steps, true)}<div class="actions"><button class="btn" id="b-rel">Desbloquear agora</button></div>`;
    else head = `<div class="result"><div class="big">${d.state === "expired" ? "Bloqueio expirou" : "Bloqueio revertido"}</div><div class="muted sm">${esc(d.id)} · acesso restabelecido (simulado)</div></div>${stepsList(d.steps, true)}<div class="actions"><button class="btn" id="b-reopen">Reabrir para nova decisão</button></div>`;
    return `<section class="card decide"><h3>Decisão do analista</h3>${head}</section>`;
  }
  const why = actionReadiness(i);
  return `<section class="card decide"><h3>O que fazer e decisão do analista<span class="r">${esc(S.set.analyst)}</span></h3>
    <div class="row" style="margin-bottom:8px"><b>${p.steps.length ? 'Resposta proposta:' : 'Orientação: investigar e acompanhar, sem nova contenção.'}</b><span class="chip ${p.impact === "alto" ? "alta" : p.impact === "médio" ? "media" : "baixa"}">impacto ${p.impact}</span><span class="muted sm">simulado, com prazo e reversão</span></div>
    ${stepsList(p.steps, false)}
    <div class="dctl"><div class="f"><label for="ttl">Prazo do bloqueio</label><select id="ttl">${TTLS.map(([s, t]) => `<option value="${s}"${+S.set.ttl === s ? " selected" : ""}>${t}</option>`).join("")}</select></div>
    <div class="f grow"><label for="note">Justificativa (opcional, vai para a auditoria)</label><input type="text" id="note" maxlength="300" autocomplete="off" placeholder="Ex.: confirmado com a Dra. Marina por telefone"></div></div>
    <div class="actions"><button class="btn big" id="b-monitor">Registrar acompanhamento</button><button class="btn ok big" id="b-app">Aprovar atividade</button><button class="btn danger big" id="b-blk"${why ? " disabled" : ""}>Bloquear</button></div>
    <p class="why">${i.contextNote ? esc(i.contextNote) + ' ' : ''}<b>Aprovar</b>: registra a atividade como legítima. <b>Acompanhar</b>: mantém a investigação sem conter. <b>Bloquear</b>: você autoriza a ação simulada acima, independentemente da sugestão da IA ou da classificação da regra.${why ? `<br><span class="err">Bloquear indisponível: ${esc(why)}</span>` : ""}</p></section>`;
}
function evidHTML(i) {
  const n = Math.min(S.evLimit, i.evidence.length);

  const key = new Set(i.aiEvidenceIds);
  const display = i.evidence.filter((e) => key.has(SOC.evId(e.n))).concat(i.evidence.filter((e) => !key.has(SOC.evId(e.n))));
  const rows = display.slice(0,n).map((e) => {
    const summary = ['event','host','user','src','session','status','count','approved','care_assigned','new_role'].filter((k) => e[k] !== undefined).map((k) => k+'='+String(e[k])).join(' ');
    return `<div class="ev"><span class="mono muted">${SOC.evId(e.n)}</span><span class="mono">${fT(e.t)}</span><div class="raw">${esc(summary || e.raw)}<details><summary>Ver linha original ${esc(e.source_id || '')}</summary><pre>${esc(e.raw)}</pre></details></div></div>`;
  }).join('');
  return `<section class="card"><h3>Evidências<span class="r muted sm">${nf(i.evCount)} no total · evidências-chave primeiro · linha original disponível</span></h3><div class="evbox">${rows}</div>${n < i.evidence.length ? `<div class="actions"><button class="btn" id="b-more">Mostrar mais ${Math.min(200, i.evidence.length - n)}</button></div>` : ""}</section>`;
}
function auditHTML() {
  const rows = S.audit.slice().reverse().map((a) => `<div class="au"><span class="t">${a.seq}</span><span class="t">${esc(a.ts.slice(11, 19))} UTC</span><span><b>${esc(a.type)}</b>${a.incident ? " · " + a.incident : ""}<br><span class="muted">${esc(a.actor)}</span></span><span style="overflow-wrap:anywhere">${esc(a.detail)}</span></div>`).join("");
  return `<div class="overlay" id="ov-aud"><div class="panel" role="dialog" aria-label="Auditoria"><h2>Trilha de auditoria<button class="btn" id="b-aud-x">Fechar</button><button class="btn primary" id="b-exp">Exportar JSON</button></h2><p class="muted sm" style="margin:0 0 10px">Cada detecção, triagem, aprovação, bloqueio e reversão fica registrada com horário, ator e identificadores. Não há assinatura digital nem garantia de imutabilidade.</p><div class="audit">${rows || `<div class="empty">Sem registros.</div>`}</div></div></div>`;
}
function settingsHTML() {
  return `<div class="overlay" id="ov-set"><div class="panel" role="dialog" aria-label="Ajustes"><h2>Ajustes<button class="btn" id="b-set-x">Fechar</button></h2>
  <div class="fgrid">
   <div class="f"><label for="s-an">Nome do analista (registrado na auditoria)</label><input type="text" id="s-an" value="${esc(S.set.analyst)}"></div>
   <div class="f"><label for="s-ttl">Prazo padrão do bloqueio</label><select id="s-ttl">${TTLS.map(([s, t]) => `<option value="${s}"${+S.set.ttl === s ? " selected" : ""}>${t}</option>`).join("")}</select></div>
   <div class="f"><label for="s-url">Endereço do Ollama</label><input type="text" id="s-url" value="${esc(S.set.ollamaUrl)}"></div>
   <div class="f"><label for="s-mod">Modelo do Ollama</label><input type="text" id="s-mod" value="${esc(S.set.model)}"></div>
   <div class="f" style="grid-column:1/-1"><label for="s-auth">Referência de contexto autorizado para priorização: contas ou IPs (um por linha)</label><textarea id="s-auth" rows="3" placeholder="dra_marina&#10;10.99.0.14">${esc(S.set.authorized)}</textarea></div>
  </div>
  <div class="actions"><button class="btn" id="b-test">Testar Ollama</button><button class="btn primary" id="b-set-ok">Salvar</button></div>
  <p class="why">${esc(S.ollamaMsg)}</p>
  <p class="muted sm">Ollama local usa temperatura 0, contexto de 4096 tokens e limite de 900 tokens. A análise automática começa depois de carregar o arquivo. Com Claude, a chamada usa a sua conta e recebe só a entrada estruturada.</p></div></div>`;
}

/* ---------- eventos de UI ---------- */
function bind() {
  const on = (id, fn, ev = "click") => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
  on("prov", (e) => { S.provider = e.target.value; render(); }, "change");
  on("b-set", () => { S.showSet = true; S.ollamaMsg = ""; render(); });
  on("b-aud", () => { S.showAudit = true; render(); });
  on("b-aud-x", () => { S.showAudit = false; render(); });
  on("b-set-x", () => { S.showSet = false; render(); });
  on("b-exp", exportAudit);
  on('b-report',()=>openReport());
  on('b-report-close',()=>{persistReportDraft();S.showReport=false;render();});
  on('b-report-edit',()=>{S.reportMode='edit';render();});
  on('b-report-preview',()=>{S.reportMode='preview';render();});
  on('b-report-save',saveReport);
  on('b-report-download',downloadReport);
  on('b-report-refresh',()=>{generateReport();render();});
  on('b-report-undo',()=>{const old=S.reportDraft;S.reportDraft=S.reportPrevious;S.reportPrevious=old;persistReportDraft();render();});
  on('t2-editor',reportInput,'input');
  on('b-human', () => startHumanReview(sel()));
  on('b-severity', () => changeSeverity(sel(), $('#severity-review').value, $('#severity-note').value));
  on("b-load", () => $("#file").click());
  on("b-all", triageAll); on("b-stop", () => ctl && ctl.abort());
  on("b-ai", async () => { const i = sel(); ctl = new AbortController(); try { await triage(i, ctl.signal); } catch {} ctl = null; });
  on("b-more", () => { S.evLimit += 200; render(); });
  on("ttl", (e) => { S.set.ttl = +e.target.value; }, "change");
  on("b-monitor", () => monitor(sel(), ($("#note") || {}).value || ""));
  on("b-app", () => approve(sel(), ($("#note") || {}).value || ""));
  on("b-blk", () => block(sel(), +$("#ttl").value, ($("#note") || {}).value || ""));
  on("b-rel", () => release(sel(), "manual")); on("b-reopen", () => reopen(sel()));
  on("b-test", async () => { S.set.ollamaUrl = $("#s-url").value.trim(); try { const r = await fetch(S.set.ollamaUrl.replace(/\/$/, "") + "/api/tags"); const j = await r.json(); S.ollamaMsg = "Conectado. Modelos: " + (j.models || []).map((m) => m.name).join(", "); } catch { S.ollamaMsg = "Sem conexão. Confira se o Ollama está rodando e se OLLAMA_ORIGINS libera esta página."; } render(); });
  on("b-set-ok", () => {
    S.set.analyst = $("#s-an").value.trim() || "analista-demo"; S.set.ttl = +$("#s-ttl").value; S.set.ollamaUrl = $("#s-url").value.trim(); S.set.model = $("#s-mod").value.trim(); S.set.authorized = $("#s-auth").value;
    const a = authList();
    for (const i of S.incs) { const before = i.sev.level; i.sev = SOC.severityOf(i, S.incs, a); if (i.sev.level !== before && !(i.decision && i.decision.state === "active")) { i.ai = { status: "idle" }; audit("CONTEXTO_ATUALIZADO", i, `prioridade ${before} -> ${i.sev.level}; triagem anterior descartada`); } }
    S.showSet = false; render();
  });
  document.querySelectorAll("[data-sel]").forEach((b) => b.addEventListener("click", () => { S.sel = b.dataset.sel; S.evLimit = 60; render(); if (innerWidth <= 900) { const d = document.querySelector(".detail"); if (d) window.scrollTo({ top: d.getBoundingClientRect().top + scrollY - 8 }); } }));
  ["ov-aud", "ov-set", "ov-report"].forEach((id) => { const o = document.getElementById(id); if (o) o.addEventListener("mousedown", (e) => { if (e.target === o) { if(S.showReport)persistReportDraft();S.showAudit = S.showSet = S.showReport = false; render(); } }); });
}
async function pick(file) {
  if (!file) return;
  if (S.loading || S.batch) { toast('Aguarde a análise atual ou clique em Parar antes de carregar outro log.'); return; }
  try { const r = await loadStream(file); await ingest(r, file.name, false); }
  catch(e) { S.loading = null; S.error = 'Não foi possível ler o arquivo: ' + e.message; render(); toast(S.error); }
}
$("#file").addEventListener("change", (e) => { pick(e.target.files[0]); e.target.value = ""; });
let dz = 0;
addEventListener("dragenter", (e) => { if (e.dataTransfer && [...e.dataTransfer.types].includes("Files")) { dz++; if (!$(".drop")) { const d = document.createElement("div"); d.className = "drop"; d.textContent = "Solte o arquivo de log aqui"; document.body.appendChild(d); } } });
addEventListener("dragleave", () => { dz = Math.max(0, dz - 1); if (!dz) document.querySelector(".drop")?.remove(); });
addEventListener("dragover", (e) => e.preventDefault());
addEventListener("drop", (e) => { e.preventDefault(); dz = 0; document.querySelector(".drop")?.remove(); if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]); });
addEventListener("keydown", (e) => { if (e.key === "Escape" && (S.showAudit || S.showSet || S.showReport)) { if(S.showReport)persistReportDraft();S.showAudit = S.showSet = S.showReport = false; render(); } });

/* ---------- capacidades da plataforma (ausentes fora do Claude) ---------- */
(async () => {
  try { if (window.claude && window.claude.use) { sampleFn = await window.claude.use("sample"); dlFn = await window.claude.use("downloads"); S.claudeOK = !!sampleFn; render(); } } catch {}
})();


/* ---------- início: base histórica completa, 205.000 eventos ---------- */
(async () => {
  try {
    const encoded = document.getElementById('sample-data').textContent.trim();
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const file = new File([bytes], 'clinica-investigacao-205k.jsonl.gz');
    const data = await loadStream(file);
    await ingest(data, file.name, true);
    const reportSession=new URLSearchParams(location.search).get('report_session');
    if(reportSession) {
      try{await openSavedReport(reportSession);}catch(e){toast(e.message);}
    }
  } catch(e) { S.loading = null; S.error = 'Erro ao carregar a base completa: ' + e.message; render(); }
})();
})();
