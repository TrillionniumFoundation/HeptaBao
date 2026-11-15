import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { PrivateOutboxStore } from '../plugin/private-outbox-store.js';
import { hashText } from '../plugin/bounded-outbox.js';

const childPath = fileURLToPath(new URL('./durability-child.mjs', import.meta.url));
const binding = { schema: 'synthetic-durability-test', epoch: '11111111-1111-4111-8111-111111111111' };
const record = 'report:' + hashText('main');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'heptabao-wal-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
async function start(t, root) {
  const child = fork(childPath, [root], { execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  const exit = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  const guard = setTimeout(() => child.kill('SIGKILL'), 15000);
  exit.then(() => clearTimeout(guard));
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit; });
  const first = await Promise.race([once(child, 'message').then(([message]) => message), exit.then(() => ({ exited: true }))]);
  assert.deepEqual(first, { ready: true }, stderr);
  return { child, exit, stderr: () => stderr };
}
async function action(t, root, command, killed = false) {
  const owner = await start(t, root);
  let result;
  owner.child.on('message', message => { result = message; });
  owner.child.send(command);
  const status = await owner.exit;
  if (killed) { assert.equal(status.signal, 'SIGKILL'); return; }
  assert.equal(status.code, 0, owner.stderr());
  assert.ok(result && typeof result.ok === 'boolean');
  return result;
}
function snapshot(root) {
  const store = new PrivateOutboxStore(path.join(root, 'state'), binding);
  try { return store.get(record); } finally { store.close(); }
}
function remote(root) { return JSON.parse(fs.readFileSync(path.join(root, 'remote.json'))); }

test('existing DELETE state migrates without changing binding or revision; WAL keeps FULL and lock keeps DELETE', t => {
  const root = fixture(t); const directory = path.join(root, 'state'); fs.mkdirSync(directory, { mode: 0o700 });
  const file = path.join(directory, 'state.sqlite');
  const database = new DatabaseSync(file);
  database.exec('PRAGMA journal_mode=DELETE; CREATE TABLE records (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL)');
  database.prepare('INSERT INTO records VALUES (?,?,?)').run('binding', JSON.stringify(binding), 1);
  database.prepare('INSERT INTO records VALUES (?,?,?)').run('test', JSON.stringify({ retained: true }), 7);
  database.close(); fs.chmodSync(file, 0o600);
  const store = new PrivateOutboxStore(directory, binding);
  assert.deepEqual(store.get('test'), { revision: 7, value: { retained: true } });
  const observer = new DatabaseSync(file);
  assert.equal(observer.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
  // synchronous is connection local; constructor also verifies its own value.
  observer.exec('PRAGMA synchronous=FULL');
  assert.equal(observer.prepare('PRAGMA synchronous').get().synchronous, 2);
  const lock = new DatabaseSync(path.join(directory, 'operation.sqlite'));
  assert.equal(lock.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
  lock.close(); observer.close(); store.close();
});

for (const mode of ['prepared', 'dispatched', 'server_confirmed', 'confirmed']) {
  test(`SIGKILL at ${mode} preserves durable intent and never repeats an uncertain write`, async t => {
    const root = fixture(t);
    await action(t, root, { action: 'publish', mode }, true);
    assert.ok(fs.statSync(path.join(root, 'state/state.sqlite-wal')).size > 0);
    const before = snapshot(root);
    assert.equal(before.value.phase, mode === 'prepared' ? 'prepared' : mode === 'confirmed' ? 'confirmed' : 'dispatched');
    const result = await action(t, root, { action: 'reconcile' });
    if (mode === 'dispatched') {
      assert.equal(result.ok, false); assert.equal(result.error, 'outbox_mutation_outcome_unknown');
      assert.equal(result.unknown, true); assert.equal(remote(root).writes, 0);
      assert.equal(snapshot(root).value.phase, 'dispatched');
    } else {
      assert.equal(result.ok, true); assert.equal(remote(root).writes, 1);
      assert.equal(snapshot(root).value.phase, 'confirmed');
      const second = await action(t, root, { action: 'reconcile' });
      assert.equal(second.ok, true); assert.equal(remote(root).writes, 1);
    }
  });
}

test('quiescent backup after SIGKILL includes uncheckpointed WAL and restores exact confirmation without replay', async t => {
  const root = fixture(t); const restored = fixture(t);
  await action(t, root, { action: 'publish', mode: 'server_confirmed' }, true);
  const sourceWal = fs.readFileSync(path.join(root, 'state/state.sqlite-wal'));
  assert.ok(sourceWal.length > 0);
  for (const name of fs.readdirSync(root)) fs.cpSync(path.join(root, name), path.join(restored, name), { recursive: true, preserveTimestamps: true });
  assert.deepEqual(fs.readFileSync(path.join(restored, 'state/state.sqlite-wal')), sourceWal);
  const result = await action(t, restored, { action: 'reconcile' });
  assert.equal(result.ok, true); assert.equal(remote(restored).writes, 1);
  assert.equal(snapshot(restored).value.phase, 'confirmed');
  assert.equal(snapshot(root).value.phase, 'dispatched');
});

test('two actual processes competing at the same local CAS revision produce one winner', async t => {
  const root = fixture(t); const a = await start(t, root); const b = await start(t, root);
  let ra, rb; a.child.on('message', message => { ra = message; }); b.child.on('message', message => { rb = message; });
  a.child.send({ action: 'cas', writer: 'a' }); b.child.send({ action: 'cas', writer: 'b' });
  assert.deepEqual(await a.exit, { code: 0, signal: null }); assert.deepEqual(await b.exit, { code: 0, signal: null });
  assert.equal([ra, rb].filter(r => r.ok).length, 1);
  const loser = [ra, rb].find(r => !r.ok);
  assert.ok(['outbox_local_cas_conflict', 'outbox_record_commit_failed'].includes(loser.error));
  const store = new PrivateOutboxStore(path.join(root, 'state'), binding);
  assert.equal(store.get('race').revision, 1); store.close();
});

test('OS-held operation lock excludes another process and releases after SIGKILL', async t => {
  const root = fixture(t); const owner = await start(t, root);
  const held = once(owner.child, 'message'); owner.child.send({ action: 'hold' });
  assert.deepEqual((await held)[0], { held: true });
  const denied = await action(t, root, { action: 'lock' });
  assert.equal(denied.ok, false); assert.equal(denied.error, 'outbox_other_process_operation_busy');
  owner.child.kill('SIGKILL'); assert.equal((await owner.exit).signal, 'SIGKILL');
  assert.equal((await action(t, root, { action: 'lock' })).ok, true);
});

test('known remote CAS rejection is durable and never retried after reopen', async t => {
  const root = fixture(t); const result = await action(t, root, { action: 'publish', mode: 'conflict' });
  assert.equal(result.ok, false); assert.equal(snapshot(root).value.phase, 'conflict');
  const resumed = await action(t, root, { action: 'reconcile' });
  assert.equal(resumed.ok, false); assert.equal(resumed.error, 'outbox_known_cas_conflict_requires_review');
  assert.equal(resumed.unknown, false); assert.equal(remote(root).writes, 0);
});
