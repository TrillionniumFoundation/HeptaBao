import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { PrivateOutboxStore as Candidate } from '../plugin/private-outbox-store.js';

const baseline = process.argv[2];
assert.ok(baseline && path.isAbsolute(baseline), 'provide exact original private-outbox-store.js');
const originalBytes = fs.readFileSync(baseline);
assert.equal(createHash('sha256').update(originalBytes).digest('hex'),
  '24c88b017679b9e61eae7e47d2768e055799f651ab0c0aae76703305e40c7955');
const { PrivateOutboxStore: Original } = await import(pathToFileURL(baseline));
const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'heptabao-outbox-cost-'));
fs.chmodSync(root, 0o700);
const samples = [];
const originalExec = DatabaseSync.prototype.exec;
let observed;
DatabaseSync.prototype.exec = function (sql) {
  const start = performance.now();
  try { return originalExec.call(this, sql); }
  finally { if (observed && sql === 'COMMIT') { observed.commits++; observed.commitMs += performance.now() - start; } }
};
try {
  for (let round = 0; round < 2; round++) {
    const cases = round === 0 ? [['DELETE_FULL', Original], ['WAL_FULL', Candidate]] : [['WAL_FULL', Candidate], ['DELETE_FULL', Original]];
    for (const [mode, Store] of cases) {
      const parent = path.join(root, `${round}-${mode}`); fs.mkdirSync(parent, { mode: 0o700 });
      const store = new Store(path.join(parent, 'state'), { syntheticBenchmark: true });
      store.put('auth', { phase: 'active', observation: 0 });
      const sample = { round, mode, operations: 32, commits: 0, commitMs: 0 };
      const start = performance.now(); observed = sample;
      for (let i = 0; i < sample.operations; i++) {
        // Same six durable barriers as a normal report: preimage bearer clock,
        // prepared intent, dispatched intent, mutation bearer clock, readback
        // bearer clock, and confirmed intent. No batching or skipped commits.
        const auth = phase => { const old = store.loadAuth(); store.saveAuth(old.revision, { phase: 'active', observation: i * 3 + phase }); };
        await store.withLock(async () => {
          auth(0); store.put('report:main', { sequence: i + 1, phase: 'prepared' });
          store.put('report:main', { sequence: i + 1, phase: 'dispatched' });
          auth(1); auth(2); store.put('report:main', { sequence: i + 1, phase: 'confirmed' });
        });
      }
      observed = undefined; sample.elapsedMs = performance.now() - start;
      assert.equal(sample.commits, sample.operations * 6);
      assert.equal(store.get('report:main').value.sequence, sample.operations);
      assert.equal(store.get('report:main').value.phase, 'confirmed');
      store.close();
      const reopened = new Store(path.join(parent, 'state'), { syntheticBenchmark: true });
      assert.equal(reopened.get('report:main').value.sequence, sample.operations);
      reopened.close(); samples.push(sample);
    }
  }
} finally {
  DatabaseSync.prototype.exec = originalExec;
  fs.rmSync(root, { recursive: true, force: true });
}
const total = mode => samples.filter(row => row.mode === mode).reduce((sum, row) => sum + row.elapsedMs, 0);
console.log(JSON.stringify({ schema: 'heptabao.authbus-wal-full-cost.v1', ok: true,
  syntheticOnly: true, providerCalled: false, productionModified: false, durabilityRelaxed: false,
  durableCommitsPerReport: 6, nodeVersion: process.version, platform: process.platform,
  baselineSha256: createHash('sha256').update(originalBytes).digest('hex'),
  candidateSha256: createHash('sha256').update(fs.readFileSync(new URL('../plugin/private-outbox-store.js', import.meta.url))).digest('hex'),
  samples, aggregateSpeedup: total('DELETE_FULL') / total('WAL_FULL') }));
