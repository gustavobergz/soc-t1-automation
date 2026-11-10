const endpoint = 'http://127.0.0.1:11434';
const techniques = ['T1110.001', 'T1078.003'];
const modelPattern = /^(?:[a-z0-9_.-]+\/)?[a-z0-9_.-]+:[a-z0-9_.-]+$/i;
const configuredModel = process.env.SOC_OLLAMA_MODEL?.trim();
const model = configuredModel?.length <= 100 && modelPattern.test(configuredModel) && !/cloud/i.test(configuredModel) ? configuredModel : null;

function inputFor(event) {
  const input = event.input;
  if (!/^SOC-\d{3,24}$/.test(event.run) || !input ||
      !Number.isInteger(input.failure_count) || input.failure_count < 5 || input.failure_count > 30 ||
      input.successful_login !== true || input.privilege_query !== true || input.reputation_simulated !== 92 ||
      !Array.isArray(input.evidence_ids) || input.evidence_ids.length < 7 || input.evidence_ids.length > 30 ||
      new Set(input.evidence_ids).size !== input.evidence_ids.length ||
      !input.evidence_ids.every((id) => typeof id === 'string' && /^SOC-\d{3,24}-\d{2,4}$/.test(id) && id.startsWith(`${event.run}-`))) {
    throw new Error('invalid_triage_input');
  }
  return {
    failure_count: input.failure_count, successful_login: true, privilege_query: true, reputation_simulated: 92,
    evidence_ids: [...input.evidence_ids], mitre: techniques,
  };
}

function schema(input) {
  const text = { type: 'string', minLength: 1, maxLength: 400 };
  const properties = {
    threat_type: { type: 'string', enum: ['possivel_abuso_credenciais', 'inconclusivo'] },
    severity: { type: 'string', enum: ['alta', 'media', 'baixa'] }, severity_reason: text,
    evidence_ids: { type: 'array', items: { type: 'string', enum: input.evidence_ids }, minItems: input.evidence_ids.length, maxItems: input.evidence_ids.length },
    mitre: { type: 'array', items: { type: 'string', enum: techniques }, minItems: 2, maxItems: 2 },
    possible_impact: text, uncertainty: text,
    recommendations: { type: 'array', items: { type: 'string', enum: ['investigar_conta', 'monitorar', 'avaliar_contencao'] }, minItems: 1, maxItems: 3 },
  };
  return { type: 'object', properties, required: Object.keys(properties), additionalProperties: false };
}

async function call(path, signal, body) {
  const response = await fetch(endpoint + path, {
    signal, redirect: 'error', ...(body && { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  });
  if (!response.ok) throw new Error('ollama_http_error');
  return response.json();
}

async function triage(event) {
  const audit = { model: model || '' };
  if (!model) return { ...audit, error: 'llm_unavailable' };
  try {
    const input = inputFor(event);
    if (typeof event.prompt !== 'string' || event.prompt_version !== 'soc-tier1-2' || event.prompt.length > 1000) {
      return { ...audit, error: 'invalid_provider_reply' };
    }
    const signal = AbortSignal.timeout(35000);
    const [catalog, engine] = await Promise.all([call('/api/tags', signal), call('/api/version', signal)]);
    const installed = catalog.models?.find((entry) => entry.name === model && entry.size > 0 && !entry.remote_model && !entry.remote_host);
    if (!installed || !/^[a-f0-9]{64}$/i.test(installed.digest) || !/^\d+\.\d+\.\d+[-.a-z0-9]*$/i.test(engine.version)) {
      return { ...audit, error: 'llm_unavailable' };
    }
    audit.model_version = installed.digest;
    audit.engine_version = engine.version;
    const response = await call('/api/chat', signal, {
      model, stream: false, format: schema(input), options: { temperature: 0, num_predict: 900 },
      messages: [{ role: 'system', content: event.prompt }, { role: 'user', content: JSON.stringify(input) }],
    });
    const output = response.message?.content;
    if (response.done !== true || response.done_reason === 'length' || response.model !== model || typeof output !== 'string' || Buffer.byteLength(output) > 6000 || response.message?.tool_calls?.length) {
      return { ...audit, error: 'invalid_provider_reply' };
    }
    return { ...audit, output };
  } catch {
    return { ...audit, error: 'llm_unavailable' };
  }
}

module.exports = { model, triage };
