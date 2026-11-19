'use strict';
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
function provenance(root) {
  const files = {};
  for (const file of ['DEMO SOC.html', 'lab/painel.js', 'lab/metrics.js', 'lab/clinic.json', 'lab/ollama.cjs',
    'lab/virtualbox.cjs', 'lab/journal.cjs', 'lab/runtime/SOC-Tier1.iso', 'lab/runtime/images.js',
    'lab/clinic.go', 'lab/policy.go', 'lab/triage.go', 'lab/historical-results.js']) {
    const target = path.join(root, file);
    if (fs.existsSync(target)) files[file] = sha256(fs.readFileSync(target));
  }
  return { version: 'tcc-validacao-20261119', reference_commit: '0184c785f73ce15a36ffbd93ac8b395d461679a2',
    generated_utc: new Date().toISOString(), files, manifest_sha256: sha256(JSON.stringify(files)),
    historical_data_unchanged: true };
}
function createJournal(root, buildHash) {
  const session = crypto.randomUUID();
  const directory = path.join(root, 'logs', 'novas-execucoes');
  const filename = path.join(directory, `sessao-${session}.jsonl`);
  const seen = new Set();
  let sequence = 0, previous = '0'.repeat(64), queue = Promise.resolve();
  function append(event, source, clientId) {
    const work = queue.then(async () => {
      if (clientId && seen.has(clientId)) return;
      const body = { sequence: sequence + 1, received_utc: new Date().toISOString(), session,
        source, previous_sha256: previous, build_sha256: buildHash, record: event };
      const digest = sha256(JSON.stringify(body));
      await fsp.mkdir(directory, { recursive: true });
      await fsp.appendFile(filename, JSON.stringify({ ...body, sha256: digest }) + '\n', 'utf8');
      previous = digest; sequence++;
      if (clientId) seen.add(clientId);
    });
    queue = work.catch(() => {});
    return work;
  }
  return { append, status: () => ({ session, stored: sequence, last_sha256: previous, filename: path.basename(filename) }) };
}
module.exports = { createJournal, provenance, sha256 };
