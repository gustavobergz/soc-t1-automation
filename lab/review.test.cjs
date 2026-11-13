const { test } = require('node:test');
const assert = require('node:assert/strict');
const review = require('./review.js');

const raw = (id, kind, second, source = '10.77.0.30') => ({
  event: 'siem.raw', event_id: id, kind, source_ip: source, username: 'soclab', host: 'endpoint-01',
  timestamp: new Date(Date.UTC(2026, 10, 10, 0, 0, second)).toISOString(),
});

test('replay uses chronological UTC order and keeps selected evidence distinct', () => {
  const entries = [raw('C', 'sudo.attempt', 5), raw('A', 'ssh.failed', 0), raw('B', 'ssh.accepted', 3), raw('A', 'ssh.failed', 0)];
  assert.deepEqual(review.timeline(entries).map((entry) => entry.event_id), ['A', 'A', 'B', 'C']);
  const facts = review.facts(entries);
  assert.equal(facts.failures, 1);
  assert.deepEqual(facts.sequence, ['failure', 'login', 'privilege']);
  assert.ok(review.gaps(facts).some((gap) => gap.includes('registros de processo ou rede')));
});

test('a protected address is a counterpoint and simulation cannot approve anything', () => {
  const facts = review.facts([raw('A', 'ssh.failed', 0, '10.77.0.10')], 'alta');
  facts.chain = true;
  assert.ok(review.challenge(facts).some((finding) => finding.includes('IP')));
  assert.equal(review.shadow(facts, 'SOC-001').applied, false);
  assert.equal(review.shadow(facts, 'SOC-001').action, 'no_action');
  const preview = review.shadow({ ...facts, source: '10.77.0.30' }, 'SOC-002');
  assert.equal(preview.predicted_source_status, 403);
  assert.equal(preview.predicted_control_status, 204);
  assert.equal(preview.applied, false);
});

test('reviewed memory finds the same sequence across addresses and excludes the active case', () => {
  const context = { source: '10.77.0.30', host: 'endpoint-01', user: 'soclab', sequence: ['failure', 'login', 'privilege'], failures: 8, mitre: ['T1110.001'] };
  const history = [
    { id: 'SOC-001', resolution: 'falso_positivo', context: { ...context, source: '10.77.0.38', failures: 6 } },
    { id: 'SOC-002', resolution: 'confirmado', context },
    { id: 'SOC-003', resolution: '', context },
  ];
  const matches = review.related(context, history, 'SOC-002');
  assert.deepEqual(matches.map((entry) => entry.id), ['SOC-001']);
  assert.match(matches[0].differences[0], /8 falhas agora × 6/);
  assert.equal(matches[0].exact, true);
  assert.notEqual(review.signature(context), review.signature({ ...context, host: 'endpoint-02' }));
});

test('story groups adjacent failures from the same entity and keeps their source records', () => {
  const entries = [raw('C', 'ssh.failed', 3, '10.77.0.31'), raw('A', 'ssh.failed', 0), raw('B', 'ssh.failed', 2), raw('D', 'ssh.accepted', 5)];
  const steps = review.story(review.facts(entries));
  assert.deepEqual(steps.map((step) => step.records.map((record) => record.event_id)), [['A', 'B'], ['C'], ['D']]);
  assert.match(steps[0].label, /2 falhas/);
  assert.equal(steps[0].end - steps[0].time, 2000);
});

test('a receipt records the source evidence and separates triage from the human action', () => {
  const entries = [
    { event: 'siem.correlated', rule_id: 100501, evidence_ids: ['A', 'B'] },
    { event: 'soar.triaged', timestamp: '2026-11-10T00:00:04Z', provider: 'fixture', severity: 'alta', result: {
      evidence_ids: ['B', 'B'], severity_reason: 'Consulta observada', recommendations: ['investigar_conta'],
    } },
    { event: 'soar.approval_rejected', action: 'reject_http_block', actor: 'analista-demo' },
  ];
  const receipt = review.receipt(entries, 'SOC-123', 'sample');
  assert.deepEqual(receipt.evidence_ids, ['B']);
  assert.equal(receipt.rule_id, 100501);
  assert.equal(receipt.reason, 'Consulta observada');
  assert.equal(receipt.human_or_policy_decision.actor, 'analista-demo');
  assert.deepEqual(receipt.recommendations, ['investigar_conta']);
});

test('pulse counts open issues and distinct assets and caps the score', () => {
  const cases = [
    { severity: 'alta', assets: ['endpoint'], pending: true },
    { severity: 'media', assets: ['endpoint', 'server'] },
    { severity: 'alta', assets: ['closed'], closed: true },
  ];
  assert.deepEqual(review.pulse(cases), {
    score: 43, active: 2, assets: 2, pending: 1, points: { severity: 27, assets: 8, approval: 8 },
  });
  assert.equal(review.pulse(Array(12).fill(cases[0])).score, 100);
});

test('a selected clinical export retains its authorization and requests the missing approval record', () => {
  const config = require('./clinic.json').find((item) => item.id === 'authorized_shift');
  const entries = config.steps.slice(1).map((step, index) => ({
    event: step.kind, event_id: `SEL-${index}`, scenario: config.id, clinical: step,
    source_ip: '10.77.0.30', username: config.user, host: config.host, session_id: config.session,
    timestamp: new Date(Date.UTC(2026, 10, 12, 6, 0, index * 12)).toISOString(),
  }));
  const context = review.facts(entries, 'alta');
  assert.equal(context.authorized, false);
  assert.equal(context.authorizationClaimed, true);
  assert.match(review.challenge(context).join(' '), /registro de aprovação/);
  assert.equal(review.shadow({ ...context, chain: true }, 'SOC-200').action, 'no_action');
});
