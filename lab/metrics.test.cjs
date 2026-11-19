const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { containmentMeans, interval, containmentVerified, historicalSummary } = require('./metrics.js');

test('historical fixture and Ollama containments remain separate; manual has no MTTR', () => {
  const events = fs.readFileSync(path.join(__dirname, '../logs/clinica-demo.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(containmentMeans(events), {
    manual: { count: 0, meanMs: null },
    auto: { count: 4, meanMs: 1343 },
    llm: { count: 1, meanMs: 47795 },
  });
});

test('a containment is verified only after matching approval and every required probe', () => {
  const valid = { scenario: 'stolen_account', verified: true, control: true, legitimate: true,
    approvalId: 'APR-200', requestedApprovalId: 'APR-200', blockApprovalId: 'APR-200' };
  assert.equal(containmentVerified(valid), true);
  for (const field of ['verified', 'control', 'legitimate']) assert.equal(containmentVerified({ ...valid, [field]: false }), false);
  assert.equal(containmentVerified({ ...valid, approvalId: 'APR-OTHER' }), false);
  assert.equal(containmentVerified({ ...valid, requestedApprovalId: undefined }), false);
});

test('missing or reversed timing stages are absent instead of inventing a zero duration', () => {
  assert.equal(interval(20, 35.5), 16);
  assert.equal(interval(20, 19), null);
  assert.equal(interval(undefined, 20), null);
  assert.equal(interval(20, Infinity), null);
  assert.equal(interval(20, 20), 0);
});

test('TCC history is recalculated without adding any new run', () => {
  const records = fs.readFileSync(path.join(__dirname, '../logs/clinica-demo.jsonl'), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const value = historicalSummary(records);
  assert.equal(value.lines, 280); assert.equal(value.rounds, 12);
  assert.equal(value.containments, 5); assert.equal(value.releases, 5);
  assert.deepEqual(value.benchmark.counts, { tp: 3, fp: 1, fn: 3, tn: 1 });
  assert.deepEqual(value.ollamaTriages, [35452, 47128]);
  assert.equal(value.statistics.manual.response_ms.meanMs, null);
  assert.equal(value.statistics.auto.response_ms.meanMs, 1343);
  assert.equal(value.statistics.llm.response_ms.meanMs, 47795);
});

test('monitoring, failed, absent and invalid durations do not become containments', () => {
  const records = [null, NaN, Infinity, -1].map(response_ms =>
    ({ event: 'panel.metrics', mode: 'auto', outcome: 'contained', response_ms }));
  records.push({ event: 'panel.metrics', mode: 'llm', outcome: 'monitoring', response_ms: 900 });
  records.push({ event: 'panel.metrics', mode: 'failure', outcome: 'contained', response_ms: 900 });
  records.push({ event: 'panel.metrics', mode: 'manual', outcome: 'contained', response_ms: 0 });
  assert.deepEqual(containmentMeans(records), {
    manual: { count: 1, meanMs: 0 }, auto: { count: 0, meanMs: null }, llm: { count: 0, meanMs: null },
  });
});
