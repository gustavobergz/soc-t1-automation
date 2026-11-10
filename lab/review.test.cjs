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
});
