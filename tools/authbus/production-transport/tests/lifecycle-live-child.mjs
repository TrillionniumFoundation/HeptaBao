/** One isolated client phase against an actual HeptaBao HTTPS listener.
 * The only injected failure drops a successful real renewal response before
 * the production client can observe it. No server response is fabricated.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { PrivateOutboxStore, productionStateDirectory } from '../plugin/private-outbox-store.js';
import { StrictBaoClient } from '../plugin/strict-bao-client.js';
import { ProductionTransportClient } from '../plugin/production-client.js';
import { normalizeTransport, stable } from '../plugin/bounded-outbox.js';

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const phase = process.argv[3];
const trace = [];
const sensitive = [config.syntheticValue];
const checks = [];
const report = { schema: 'heptabao.authbus-lifecycle-live-child.v1', phase, ok: false, checks,
  realHeptaBaoServer: true, externalProviderCalled: false, productionModified: false };
let dropRenewal = false;
const droppedStatuses = [];
const actualRequest = https.request;
https.request = function (options, callback) {
  trace.push({ method: options.method ?? 'GET', path: options.path });
  return actualRequest.call(https, options, incoming => {
    if (dropRenewal && options.path === '/v1/auth/token/renew-self') {
      dropRenewal = false;
      droppedStatuses.push(incoming.statusCode);
      incoming.resume();
      return;
    }
    callback(incoming);
  });
};

function check(name, condition) {
  checks.push({ case: name, passed: condition === true });
  if (!condition) throw Object.assign(new Error(name), { code: name });
}
function stateBinding() {
  return stable({ schema: 'heptabao-authbus-local-outbox-v1', address: config.address,
    transport: normalizeTransport(config.productionTransport, config.hostId) });
}
function open(stateRoot = config.stateRoot) {
  const store = new PrivateOutboxStore(productionStateDirectory(stateRoot), stateBinding());
  return { store, client: new StrictBaoClient(config, store) };
}
function snapshot(stateRoot = config.stateRoot) {
  const store = new PrivateOutboxStore(productionStateDirectory(stateRoot), stateBinding());
  try { return store.loadAuth(); } finally { store.close(); }
}
function count(route) { return trace.filter(item => item.path === route).length; }
function options() { return { deadlineMs: Date.now() + 30000 }; }
function statusWithBearer(route, token) {
  sensitive.push(token);
  return new Promise((resolve, reject) => {
    const request = https.request({ protocol: 'https:', hostname: new URL(config.address).hostname,
      port: new URL(config.address).port, path: '/v1/' + route, method: 'GET', agent: false,
      ca: fs.readFileSync(config.caFile), minVersion: 'TLSv1.2', rejectUnauthorized: true,
      headers: { 'X-Vault-Token': token },
      checkServerIdentity(host, certificate) {
        const error = tls.checkServerIdentity(host, certificate);
        if (error) return error;
        if (createHash('sha256').update(certificate.raw).digest('hex') !== config.serverCertificateSha256)
          return new Error('fixture_leaf_pin_mismatch');
      } }, response => {
        response.resume(); response.once('end', () => resolve(response.statusCode));
      });
    request.setTimeout(10000, () => request.destroy(new Error('fixture_request_timeout')));
    request.on('error', reject); request.end();
  });
}

try {
  if (phase === 'initial') {
    const { client, store } = open();
    try {
      await client.login(options());
      const first = store.loadAuth().value; sensitive.push(first.token);
      check('actual_short_ttl_issued', first.leaseSeconds === config.tokenTtlSeconds);
      check('actual_approle_login_once', count('/v1/auth/approle/login') === 1);
      const version = await client.writeSecret('lifecycle/value', { value: config.syntheticValue }, 0, options());
      check('actual_kv_write', version === 1);
      const value = await client.readSecret('lifecycle/value', options());
      check('actual_kv_read_exact', value.version === 1 && value.data.value === config.syntheticValue);
      const previous = client.token;
      await client.renew(options());
      check('actual_renew_same_bearer', client.token === previous && count('/v1/auth/token/renew-self') === 1);
      report.expiresAtUnixMs = store.loadAuth().value.expiresAtUnixMs;
      check('lease_still_active_before_client_exit', report.expiresAtUnixMs > Date.now());
    } finally { await client.close({ revoke: false }); store.close(); }
  } else if (phase === 'resume') {
    const before = snapshot(); sensitive.push(before.value.token);
    check('persisted_actual_lease_expired', before.value.phase === 'active' && Date.now() >= before.value.expiresAtUnixMs);
    check('actual_expired_bearer_denied_after_server_restart',
      await statusWithBearer('openclaw-auth/data/lifecycle/value', before.value.token) === 403);
    const client = new ProductionTransportClient(config, config.stateRoot);
    let closed = false;
    try {
      const requests = trace.length;
      await assert.rejects(client.readSecret('lifecycle/value', { deadlineMs: Date.now() - 1 }), /deadline/);
      check('expired_caller_deadline_has_no_new_wire_request', trace.length === requests);
      check('expired_caller_deadline_preserves_state', JSON.stringify(snapshot()) === JSON.stringify(before));
      const value = await client.readSecret('lifecycle/value', options());
      const after = snapshot(); sensitive.push(after.value.token);
      check('cold_restart_kv_exact', value.version === 1 && value.data.value === config.syntheticValue);
      check('expired_startup_uses_one_fresh_approle_login', count('/v1/auth/approle/login') === 1);
      check('expired_startup_never_renews_old_bearer', count('/v1/auth/token/renew-self') === 0);
      check('fresh_actual_bearer_and_lifetime', after.value.token !== before.value.token
        && after.value.issuedAtUnixMs > before.value.expiresAtUnixMs);
      check('actual_control_and_manifest_admitted', count('/v1/openclaw-auth/data/transport-v1/control') === 1
        && count('/v1/openclaw-auth/data/manifest') === 1);
      check('actual_acl_denies_unenrolled_path',
        await statusWithBearer('openclaw-auth/data/forbidden', after.value.token) === 403);
      fs.writeFileSync(config.revokedWitnessFile, JSON.stringify({ token: after.value.token }), { mode: 0o600, flag: 'wx' });
      const revoked = await client.close(); closed = true;
      check('actual_revoke_self_and_lookup_denial', revoked.revoked === true && revoked.originalBearerLookupStatus === 403);
      check('actual_revoked_kv_read_denied', await statusWithBearer('openclaw-auth/data/lifecycle/value', after.value.token) === 403);
      check('revoked_phase_persisted', snapshot().value.phase === 'revoked');
    } finally { if (!closed) { try { await client.close(); } catch {} } }
  } else if (phase === 'after-revoke') {
    const witness = JSON.parse(fs.readFileSync(config.revokedWitnessFile, 'utf8'));
    check('revoked_phase_survives_client_restart', snapshot().value.phase === 'revoked');
    check('revoked_bearer_denied_after_cold_server_restart',
      await statusWithBearer('openclaw-auth/data/lifecycle/value', witness.token) === 403);
  } else if (phase === 'unknown-renewal') {
    let { client, store } = open(config.unknownStateRoot);
    let firstClosed = false;
    try {
      await client.login(options()); sensitive.push(client.token);
      dropRenewal = true;
      await assert.rejects(client.renew({ deadlineMs: Date.now() + 3000 }), error => error.unknown === true);
      check('dropped_reply_was_actual_heptabao_success', droppedStatuses.length === 1 && droppedStatuses[0] === 200);
      check('actual_renewal_sent_exactly_once', count('/v1/auth/token/renew-self') === 1);
      const pending = store.loadAuth();
      check('real_response_loss_retains_dispatched_intent', pending.value.phase === 'renew-dispatched');
      await client.close({ revoke: false }); store.close(); firstClosed = true;
      ({ client, store } = open(config.unknownStateRoot)); firstClosed = false;
      const requests = trace.length;
      await assert.rejects(client.readSecret('lifecycle/value', options()),
        error => error.code === 'authentication_intent_unresolved' && error.unknown === true);
      await assert.rejects(client.login(options()),
        error => error.code === 'authentication_intent_unresolved' && error.unknown === true);
      check('reopened_client_never_replays_or_reauthenticates_unknown', trace.length === requests);
      check('unknown_record_unchanged_after_reopen', JSON.stringify(store.loadAuth()) === JSON.stringify(pending));
      await client.close({ revoke: false }); store.close(); firstClosed = true;
      const production = new ProductionTransportClient(config, config.unknownStateRoot);
      try {
        await assert.rejects(production.readSecret('lifecycle/value', options()),
          error => error.code === 'authentication_intent_unresolved' && error.unknown === true);
        check('production_wrapper_never_replays_unknown', trace.length === requests);
      } finally { try { await production.close(); } catch {} }
      check('unknown_record_unchanged_after_production_wrapper',
        JSON.stringify(snapshot(config.unknownStateRoot)) === JSON.stringify(pending));
    } finally { if (!firstClosed) { try { await client.close({ revoke: false }); } finally { store.close(); } } }
  } else throw Object.assign(new Error('invalid_phase'), { code: 'invalid_phase' });
  report.wireRequests = trace;
  const publicText = JSON.stringify(report) + fs.readFileSync(config.serverLog, 'utf8');
  check('diagnostics_do_not_publish_bearers_or_payload', sensitive.every(secret => !publicText.includes(secret)));
  report.ok = true;
} catch (error) { report.error = error.code ?? error.name ?? 'live_child_failed'; }
finally { https.request = actualRequest; }
process.stdout.write(JSON.stringify(report) + '\n');
process.exitCode = report.ok ? 0 : 1;
