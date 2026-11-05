import fs from 'node:fs';
import path from 'node:path';
import { PrivateOutboxStore } from '../plugin/private-outbox-store.js';
import { BoundedOutbox, TRANSPORT, digest, reportKey } from '../plugin/bounded-outbox.js';

const root = process.argv[2];
const source = { hostId: 'fixture-host', epoch: '11111111-1111-4111-8111-111111111111', slots: 1,
  agents: ['main'], controlDigest: '', serverCertificateSha256: '0'.repeat(64) };
const ownerId = '22222222-2222-4222-8222-222222222222';
const control = { schema: `${TRANSPORT}.control`, ownerId, retainedSlotVersions: 2, bootstrapProfileCount: 1,
  topology: [{ host_id: source.hostId, epoch: source.epoch, slots: 1, agents: ['main'] }] };
source.controlDigest = digest(control);
const binding = { schema: 'synthetic-durability-test', epoch: source.epoch };
const stateDir = path.join(root, 'state');
const remoteFile = path.join(root, 'remote.json');
function durableRemote(value) {
  const temporary = remoteFile + '.pending';
  const fd = fs.openSync(temporary, 'w', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, remoteFile);
  const directory = fs.openSync(root, 'r');
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
if (!fs.existsSync(remoteFile)) durableRemote({ writes: 0, version: 1, data: {
  schema: `${TRANSPORT}.report`, sourceHost: source.hostId, epoch: source.epoch,
  agentId: 'main', sequence: 0, event: null } });
const store = new PrivateOutboxStore(stateDir, binding);
let mode;
const client = {
  async readSecret(key) {
    if (key === 'transport-v1/control') return { version: 1, data: control };
    if (key === 'manifest') return { version: 1, data: {
      schemaVersion: 1, profiles: [{ profileId: 'synthetic' }], coordinator: { ownerId } } };
    if (key !== reportKey(source, 'main')) throw new Error('unexpected_fixture_route');
    const value = JSON.parse(fs.readFileSync(remoteFile));
    return { version: value.version, data: value.data };
  },
  async writeSecret(key, data, cas) {
    const value = JSON.parse(fs.readFileSync(remoteFile));
    // Independently opening SQLite at the point of dispatch proves that the
    // intent committed before the remote mutation, rather than remaining only
    // in the writer's transaction or JavaScript heap.
    const observer = new PrivateOutboxStore(stateDir, binding);
    const row = observer.get('report:' + (await import('node:crypto')).createHash('sha256').update('main').digest('hex'));
    observer.close();
    if (row?.value.phase !== 'dispatched') throw new Error('intent_not_durable_before_dispatch');
    if (mode === 'conflict') {
      const error = new Error('cas_conflict'); error.conflict = true; error.unknown = false; throw error;
    }
    if (cas !== value.version) throw new Error('fixture_version_mismatch');
    durableRemote({ writes: value.writes + 1, version: cas + 1, data });
    return cas + 1;
  }
};
const hooks = { prepared: 'intent_prepared', dispatched: 'intent_dispatched',
  server_confirmed: 'server_write_confirmed_before_local_receipt' };
const outbox = new BoundedOutbox(client, store, source, phase => {
  if (phase === hooks[mode]) process.kill(process.pid, 'SIGKILL');
});
process.send({ ready: true });
process.once('message', async command => {
  mode = command.mode;
  try {
    let value;
    if (command.action === 'publish') {
      value = await outbox.publish({ schemaVersion: 2, kind: 'agent-report', sourceHost: source.hostId,
        agentId: 'main', eventId: '33333333-3333-4333-8333-333333333333', observation: 'synthetic-only' });
      if (mode === 'confirmed') process.kill(process.pid, 'SIGKILL');
    } else if (command.action === 'reconcile') value = await outbox.reconcile();
    else if (command.action === 'cas') value = store.cas('race', 0, { writer: command.writer });
    else if (command.action === 'hold') {
      await store.withLock(() => new Promise(resolve => {
        process.send({ held: true }); process.once('message', resolve);
      }));
      value = 'released';
    } else if (command.action === 'lock') value = await store.withLock(() => 'acquired');
    else if (command.action === 'snapshot') value = store.get(command.record);
    else throw new Error('unknown_test_action');
    store.close(); process.send({ ok: true, value });
  } catch (error) {
    try { store.close(); } catch {}
    process.send({ ok: false, error: error.message, unknown: error.unknown === true });
  }
  process.disconnect();
});
