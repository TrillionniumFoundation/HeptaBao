import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { PrivateOutboxStore, productionStateDirectory } from '../plugin/private-outbox-store.js';
import { StrictBaoClient } from '../plugin/strict-bao-client.js';
import { ProductionTransportClient, renewProductionBearerIfDue } from '../plugin/production-client.js';
import { BoundedOutbox, TRANSPORT, digest, stable } from '../plugin/bounded-outbox.js';

// These generated credentials are confined to an actual loopback TLS listener.
// No installed service, production identity, or external provider is accessed.
const certificates = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'heptabao-auth-lifecycle-cert-'));
fs.chmodSync(certificates, 0o700);
const keyFile = path.join(certificates, 'tls.key');
const certFile = path.join(certificates, 'tls.crt');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
const key = fs.readFileSync(keyFile);
const certificate = fs.readFileSync(certFile);
const certificatePin = new X509Certificate(certificate).fingerprint256.replaceAll(':', '').toLowerCase();
after(() => { key.fill(0); fs.rmSync(certificates, { recursive: true, force: true }); });

async function fixture(t, { renewDelayMs = 0 } = {}) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'heptabao-auth-lifecycle-'));
  fs.chmodSync(root, 0o700);
  const privateDir = path.join(root, 'credentials'); fs.mkdirSync(privateDir, { mode: 0o700 });
  const caFile = path.join(root, 'ca.crt'); fs.writeFileSync(caFile, certificate, { mode: 0o600 });
  const roleIdFile = path.join(privateDir, 'role_id');
  const secretIdFile = path.join(privateDir, 'secret_id');
  fs.writeFileSync(roleIdFile, 'synthetic-role-0001', { mode: 0o600 });
  fs.writeFileSync(secretIdFile, 'synthetic-secret-0001', { mode: 0o600 });
  const ownerId = '22222222-2222-4222-8222-222222222222';
  const epoch = '11111111-1111-4111-8111-111111111111';
  const control = { schema: `${TRANSPORT}.control`, ownerId, retainedSlotVersions: 2, bootstrapProfileCount: 1,
    topology: [{ host_id: 'fixture-host', epoch, slots: 1, agents: ['main'] }] };
  const productionTransport = { schema: TRANSPORT, production: true, epoch, slots: 1, agents: ['main'],
    controlDigest: digest(control), serverCertificateSha256: certificatePin };
  const requests = []; const cleanup = []; const timers = new Set();
  let revoked = false;
  const token = 'synthetic-current-bearer-0001';
  const server = https.createServer({ key, cert: certificate, minVersion: 'TLSv1.2' }, (request, response) => {
    const chunks = [];
    request.on('data', bytes => chunks.push(bytes));
    request.on('end', () => {
      const row = { method: request.method, path: request.url };
      requests.push(row);
      const reply = (status, body) => {
        if (response.destroyed) return;
        response.writeHead(status, { 'Content-Type': 'application/json' });
        response.end(body === undefined ? undefined : JSON.stringify(body));
      };
      if (request.method === 'POST' && request.url === '/v1/auth/approle/login') {
        const payload = JSON.parse(Buffer.concat(chunks));
        if (payload.role_id !== 'synthetic-role-0001' || payload.secret_id !== 'synthetic-secret-0001') {
          reply(403, { errors: ['denied'] }); return;
        }
        revoked = false;
        reply(200, { auth: { client_token: token, lease_duration: 300, renewable: true } }); return;
      }
      if (request.headers['x-vault-token'] !== token || revoked) { reply(403, { errors: ['denied'] }); return; }
      if (request.url === '/v1/auth/token/renew-self') {
        const send = () => reply(200, { auth: { client_token: token, lease_duration: 300, renewable: true } });
        if (renewDelayMs) {
          const timer = setTimeout(() => { timers.delete(timer); send(); }, renewDelayMs); timers.add(timer);
        } else send();
        return;
      }
      if (request.url === '/v1/auth/token/revoke-self') { revoked = true; reply(204); return; }
      if (request.url === '/v1/auth/token/lookup-self') { reply(200, { data: {} }); return; }
      const prefix = '/v1/openclaw-auth/data/';
      if (request.method === 'GET' && request.url.startsWith(prefix)) {
        const name = request.url.slice(prefix.length).split('/').map(decodeURIComponent).join('/');
        const data = name === 'transport-v1/control' ? control : name === 'manifest'
          ? { schemaVersion: 1, profiles: [{ profileId: 'synthetic' }], coordinator: { ownerId } }
          : { value: 'synthetic-only' };
        reply(200, { data: { data, metadata: { version: 1 } } }); return;
      }
      reply(404, { errors: ['absent'] });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = `https://127.0.0.1:${server.address().port}`;
  const config = { address, caFile, roleIdFile, secretIdFile, serverCertificateSha256: certificatePin,
    hostId: 'fixture-host', productionTransport };
  t.after(async () => {
    for (const close of cleanup.reverse()) await close();
    for (const timer of timers) clearTimeout(timer);
    server.closeAllConnections();
    const closed = once(server, 'close'); server.close(); await closed;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, config, requests, cleanup, token, productionTransport };
}

function active(bindingSha256, token, { expired = false, renewable = true } = {}) {
  const wall = Date.now();
  const issuedAtUnixMs = wall - (expired ? 2000 : 1000);
  const leaseSeconds = expired ? 1 : 30;
  return { schema: 'heptabao.authbus-bearer-state.v1', bindingSha256, phase: 'active', token,
    issuedAtUnixMs, leaseSeconds, expiresAtUnixMs: issuedAtUnixMs + leaseSeconds * 1000,
    lastObservedAtUnixMs: issuedAtUnixMs + 100, renewable };
}

async function strict(f, { expired = false, mutate = value => value } = {}) {
  const directory = path.join(f.root, 'state'); const binding = { schema: 'synthetic-lifecycle' };
  let store = new PrivateOutboxStore(directory, binding);
  let client = new StrictBaoClient(f.config, store);
  const value = mutate(active(client.bindingSha256, f.token, { expired }));
  store.saveAuth(0, value);
  // Exercise the persisted startup state, not only an in-memory token cache.
  await client.close({ revoke: false }); store.close();
  store = new PrivateOutboxStore(directory, binding); client = new StrictBaoClient(f.config, store);
  f.cleanup.push(async () => { await client.close({ revoke: false }); store.close(); });
  return { client, store, value };
}

async function production(f, { expired = false } = {}) {
  const transport = { ...f.productionTransport, hostId: f.config.hostId };
  const binding = stable({ schema: 'heptabao-authbus-local-outbox-v1', address: f.config.address, transport });
  const directory = productionStateDirectory(f.root);
  const store = new PrivateOutboxStore(directory, binding);
  const initial = new StrictBaoClient(f.config, store);
  store.saveAuth(0, active(initial.bindingSha256, f.token, { expired }));
  await initial.close({ revoke: false }); store.close();
  const client = new ProductionTransportClient(f.config, f.root);
  f.cleanup.push(async () => { try { await client.close(); } catch {} });
  return { client, auth() {
    const observer = new PrivateOutboxStore(directory, binding);
    try { return observer.loadAuth(); } finally { observer.close(); }
  } };
}

test('expired persisted active lease performs one fresh AppRole login and a real TLS KV read', async t => {
  const f = await fixture(t); const { client, store, value } = await strict(f, { expired: true });
  const result = await client.readSecret('example');
  assert.equal(result.data.value, 'synthetic-only');
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/approle/login').length, 1);
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/token/renew-self').length, 0);
  assert.equal(f.requests.filter(r => r.method === 'GET').length, 1);
  const restored = store.loadAuth();
  assert.equal(restored.value.phase, 'active');
  assert.ok(restored.value.issuedAtUnixMs > value.expiresAtUnixMs);
  assert.equal(restored.value.leaseSeconds, 300);
});

test('valid active lease is reused by explicit login without dispatching another authentication', async t => {
  const f = await fixture(t); const { client, store, value } = await strict(f);
  await client.login();
  assert.equal(f.requests.length, 0);
  assert.equal(store.loadAuth().value.expiresAtUnixMs, value.expiresAtUnixMs);
});

for (const phase of ['login-dispatched', 'renew-dispatched', 'revoke-dispatched']) {
  test(`expired metadata never permits clearing an unresolved ${phase}`, async t => {
    const f = await fixture(t); const { client, store } = await strict(f, { expired: true, mutate: v => ({ ...v, phase }) });
    const before = store.loadAuth();
    await assert.rejects(client.readSecret('example'), e => e.code === 'authentication_intent_unresolved' && e.unknown);
    await assert.rejects(client.login(), e => e.code === 'authentication_intent_unresolved' && e.unknown);
    assert.equal(f.requests.length, 0);
    assert.deepEqual(store.loadAuth(), before);
  });
}

test('known rejected authentication intent and invalid active lease remain unchanged', async t => {
  const f = await fixture(t); const { client, store } = await strict(f, { expired: true,
    mutate: v => ({ ...v, phase: 'login-dispatched', outcome: 'rejected', knownResponseStatus: 403 }) });
  const before = store.loadAuth();
  await assert.rejects(client.login(), e => e.code === 'authentication_intent_rejected' && !e.unknown && e.status === 403);
  assert.deepEqual(store.loadAuth(), before); assert.equal(f.requests.length, 0);
  const malformed = { ...active(client.bindingSha256, f.token, { expired: true }), leaseSeconds: 0 };
  store.saveAuth(before.revision, malformed);
  const invalid = store.loadAuth();
  await assert.rejects(client.login(), e => e.code === 'active_lease_shape');
  assert.deepEqual(store.loadAuth(), invalid); assert.equal(f.requests.length, 0);
});

test('persisted clock high-water failure cannot be recast as expired-lease recovery', async t => {
  const f = await fixture(t); const { client, store } = await strict(f, { expired: true,
    mutate: v => ({ ...v, lastObservedAtUnixMs: Date.now() + 60000 }) });
  const before = store.loadAuth();
  await assert.rejects(client.login(), e => e.code === 'wall_clock_moved_backwards');
  assert.deepEqual(store.loadAuth(), before); assert.equal(f.requests.length, 0);
});

test('production read restarts an expired bearer before actual control and KV reads', async t => {
  const f = await fixture(t); const { client, auth } = await production(f, { expired: true });
  const result = await client.readSecret('example', { deadlineMs: Date.now() + 5000 });
  assert.equal(result.data.value, 'synthetic-only');
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/approle/login').length, 1);
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/token/renew-self').length, 0);
  assert.equal(f.requests.filter(r => r.method === 'GET').length, 3);
  assert.equal(auth().value.phase, 'active');
});

test('expired caller deadline dispatches no renewal, reauthentication, read, or publication', async t => {
  const f = await fixture(t); const { client, auth } = await production(f);
  const before = auth(); const options = { deadlineMs: Date.now() - 1 };
  await assert.rejects(client.readSecret('example', options), /deadline/);
  assert.equal(f.requests.length, 0); assert.deepEqual(auth(), before);
  await assert.rejects(client.reconcile(options), /deadline/);
  const event = { schemaVersion: 2, kind: 'agent-report', sourceHost: f.config.hostId, agentId: 'main',
    eventId: '33333333-3333-4333-8333-333333333333' };
  await assert.rejects(client.writeInbox(f.config.hostId, event.eventId, event, options), /deadline/);
  assert.equal(f.requests.length, 0); assert.deepEqual(auth(), before);
});

test('renewal reply beyond the caller deadline leaves one unresolved attempt and performs no later reads', async t => {
  const f = await fixture(t, { renewDelayMs: 2000 }); const { client, auth } = await production(f);
  const deadlineMs = Date.now() + 500;
  await assert.rejects(client.readSecret('example', { deadlineMs }), e => e.unknown === true);
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/token/renew-self').length, 1);
  assert.equal(f.requests.filter(r => r.path === '/v1/auth/approle/login').length, 0);
  assert.equal(f.requests.filter(r => r.method === 'GET').length, 0);
  const unresolved = auth(); assert.equal(unresolved.value.phase, 'renew-dispatched');
  await assert.rejects(client.readSecret('example'), e => e.code === 'authentication_intent_unresolved' && e.unknown);
  assert.deepEqual(auth(), unresolved); assert.equal(f.requests.length, 1);
});

test('renewal and expiry recovery receive the exact original absolute deadline', async () => {
  const calls = []; const now = Date.now(); const deadlineMs = now + 5000;
  let value = { phase: 'active', expiresAtUnixMs: now + 10000, renewable: true };
  const store = { withLock: fn => fn(), loadAuth: () => ({ value }) };
  const client = { renew: options => calls.push(['renew', options]), login: options => calls.push(['login', options]) };
  await renewProductionBearerIfDue(client, store, () => now, { deadlineMs });
  assert.deepEqual(calls, [['renew', { deadlineMs }]]);
  value = { phase: 'active', expiresAtUnixMs: now - 1, renewable: false };
  await renewProductionBearerIfDue(client, store, () => now, { deadlineMs });
  assert.deepEqual(calls, [['renew', { deadlineMs }], ['login', { deadlineMs }]]);
});

test('fixed-slot outbox rejects the caller deadline before taking an operation lock', async () => {
  let locks = 0;
  const source = { hostId: 'fixture-host' };
  const outbox = new BoundedOutbox({}, { withLock() { locks++; throw new Error('unexpected_lock'); } }, source);
  const event = { schemaVersion: 2, kind: 'agent-report', sourceHost: source.hostId, agentId: 'main',
    eventId: '33333333-3333-4333-8333-333333333333' };
  const options = { deadlineMs: Date.now() - 1 };
  await assert.rejects(outbox.publish(event, options), /outbox_operation_deadline/);
  await assert.rejects(outbox.reconcile(options), /outbox_operation_deadline/);
  assert.equal(locks, 0);
});
