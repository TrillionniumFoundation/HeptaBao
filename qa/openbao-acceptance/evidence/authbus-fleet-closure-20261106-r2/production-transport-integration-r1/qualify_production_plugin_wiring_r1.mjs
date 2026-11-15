import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Load each complete prepared, source-bound installed-plugin variant. Only its
// SDK boundary and transport network boundary are substituted. This verifies
// lifecycle wiring, not provider validity, SQLite durability or real TLS.
const here = path.dirname(fileURLToPath(import.meta.url));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const transport = {
  schema: 'heptabao-authbus-fixed-slots-v1', production: true,
  epoch: '00000000-0000-4000-8000-000000000001', slots: 2, agents: ['main'],
  controlDigest: '0'.repeat(64), serverCertificateSha256: '1'.repeat(64),
};
const config = { address: 'https://127.0.0.1:31080', caFile: '/synthetic/ca.crt',
  roleIdFile: '/synthetic/role-id', secretIdFile: '/synthetic/secret-id', hostId: 'synthetic-host',
  productionTransport: transport, leader: false, publishNew: false, manageOrder: false };

async function fixture(variant, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'authbus-plugin-wiring-'));
  fs.mkdirSync(path.join(root, 'agents/main/agent'), { recursive: true });
  const trace = [], constructed = [], intervals = [];
  const entry = path.join(here, 'production-plugin-r1', variant, 'index.js');
  let service, event;
  const stamp = Date.now();
  const credential = { provider: 'openai', type: 'oauth', access: 'synthetic-access-never-sent',
    refresh: 'synthetic-refresh-never-sent', expires: stamp + 86400000 };
  class TransportBoundary {
    constructor(value, stateDir) { constructed.push({ value, stateDir }); trace.push('construct'); }
    async reconcile() {
      trace.push('reconcile:start'); options.reconcileEntered?.resolve();
      if (options.reconcileGate) await options.reconcileGate.promise;
      if (options.reconcileError) throw options.reconcileError;
      trace.push('reconcile:end');
    }
    async readSecret(key) {
      trace.push('read:' + key);
      if (key === 'manifest') {
        options.manifestEntered?.resolve();
        if (options.manifestGate) await options.manifestGate.promise;
        return { version: 1, data: { schemaVersion: 1, generation: 1, profiles: [] } };
      }
      return null;
    }
    async writeInbox(host, id, value) { trace.push('publish:' + (value.kind ?? value.reason)); }
    async close() {
      trace.push('close:start'); options.closeEntered?.resolve();
      if (options.closeGate) await options.closeGate.promise;
      if (options.closeError) throw options.closeError;
      trace.push('close:end');
    }
  }
  const sdk = {
    clearRuntimeAuthProfileStoreSnapshots() { trace.push('sdk:clear'); },
    loadAuthProfileStoreWithoutExternalProfiles() {
      trace.push('sdk:load');
      return { version: 1, profiles: { 'openai:synthetic': { ...credential } },
        usageStats: { 'openai:synthetic': { lastFailureAt: stamp } }, order: {} };
    },
    refreshOAuthCredentialForRuntime() { throw new Error('provider_call_forbidden_in_wiring_fixture'); },
    resolveProviderIdForAuth(value) { return value; },
    saveAuthProfileStore() { throw new Error('credential_write_forbidden_in_wiring_fixture'); },
    setAuthProfileOrder() { throw new Error('credential_write_forbidden_in_wiring_fixture'); },
    upsertAuthProfileWithLock() { throw new Error('credential_write_forbidden_in_wiring_fixture'); },
  };
  const context = vm.createContext({ Buffer, URL, console,
    setInterval(fn) { const timer = { fn, cleared: false, unref() {} }; intervals.push(timer); trace.push('interval'); return timer; },
    clearInterval(timer) { timer.cleared = true; trace.push('clearInterval'); },
    setTimeout, clearTimeout });
  const cache = new Map();
  function synthetic(key, value) {
    if (cache.has(key)) return cache.get(key);
    const module = new vm.SyntheticModule(Object.keys(value), function () {
      for (const [name, item] of Object.entries(value)) this.setExport(name, item);
    }, { context, identifier: key });
    cache.set(key, module); return module;
  }
  async function load(filename) {
    if (cache.has(filename)) return cache.get(filename);
    const module = new vm.SourceTextModule(fs.readFileSync(filename, 'utf8'), {
      context, identifier: filename,
      initializeImportMeta(meta) { meta.url = pathToFileURL(filename).href; },
    });
    cache.set(filename, module);
    await module.link(async (specifier, parent) => {
      if (specifier === 'openclaw/plugin-sdk/plugin-entry') return synthetic(specifier, { definePluginEntry: value => value });
      if (specifier === 'openclaw/plugin-sdk/agent-runtime') return synthetic(specifier, sdk);
      if (specifier.endsWith('/production-client.js')) return synthetic('transport-boundary', { ProductionTransportClient: TransportBoundary });
      if (specifier.startsWith('node:')) return synthetic(specifier, await import(specifier));
      assert.ok(specifier.startsWith('./'), 'only known local imports');
      return load(path.resolve(path.dirname(parent.identifier), specifier));
    });
    return module;
  }
  try {
    const module = await load(entry); await module.evaluate();
    const plugin = module.namespace.default;
    const api = { registrationMode: options.mode ?? 'full', pluginConfig: options.config ?? config,
      agent: { events: { registerAgentEventSubscription(value) { event = value; } } },
      registerService(value) { service = value; } };
    const ctx = { stateDir: root, logger: Object.fromEntries(['info', 'warn', 'error'].map(name =>
      [name, message => { trace.push('log:' + name); if (options.failLogErrors && name === 'error') throw new Error(message); }])) };
    const invoke = () => plugin.register(api);
    if (!options.deferRegister) invoke();
    return { root, trace, constructed, intervals, ctx, invoke,
      get service() { return service; }, get event() { return event; },
      healthEvent: { ts: stamp, agentId: 'main', data: { phase: 'error', message: '429 provider=openai' } },
      dispose() { fs.rmSync(root, { recursive: true, force: false }); } };
  } catch (error) { fs.rmSync(root, { recursive: true, force: false }); throw error; }
}

const checks = [];
async function check(variant, name, fn) {
  await fn(); checks.push({ variant, name, passed: true });
}
for (const variant of ['mac-rog', 'pocket4']) {
  await check(variant, 'missing_production_enrollment_refused_before_client', async () => {
    const f = await fixture(variant, { deferRegister: true, config: { ...config, productionTransport: undefined } });
    try { assert.throws(f.invoke, /production_transport_configuration/); assert.equal(f.constructed.length, 0); }
    finally { f.dispose(); }
  });
  await check(variant, 'nonfull_registration_does_not_create_transport', async () => {
    const f = await fixture(variant, { mode: 'inspect', config: {} });
    try { assert.equal(f.service, undefined); assert.equal(f.constructed.length, 0); }
    finally { f.dispose(); }
  });
  await check(variant, 'reconcile_before_cycle_and_shared_event_client', async () => {
    const f = await fixture(variant);
    try {
      await f.service.start(f.ctx);
      assert.equal(f.constructed.length, 1);
      assert.equal(f.constructed[0].stateDir, f.ctx.stateDir);
      assert.equal(f.constructed[0].value.productionTransport.controlDigest, transport.controlDigest);
      assert.ok(f.trace.indexOf('reconcile:end') < f.trace.indexOf('read:manifest'));
      assert.equal(f.intervals.length, 1);
      await f.event.handle(f.healthEvent);
      assert.equal(f.trace.filter(v => v === 'publish:health-observation').length, 1);
      assert.equal(f.constructed.length, 1);
      await Promise.all([f.service.stop(), f.service.stop()]);
      assert.equal(f.trace.filter(v => v === 'close:start').length, 1);
      assert.equal(f.trace.filter(v => v === 'close:end').length, 1);
      assert.equal(f.intervals[0].cleared, true);
      const end = f.trace.length; await f.intervals[0].fn(); await f.event.handle(f.healthEvent);
      assert.equal(f.trace.length, end);
      await assert.rejects(() => f.service.start(f.ctx), /new registration/);
    } finally { f.dispose(); }
  });
  await check(variant, 'stop_during_startup_reconciliation_closes_after_original_work', async () => {
    const entered = deferred(), gate = deferred();
    const f = await fixture(variant, { reconcileEntered: entered, reconcileGate: gate });
    try {
      const starting = f.service.start(f.ctx); await entered.promise;
      const stopping = f.service.stop(); assert.ok(!f.trace.includes('close:start'));
      gate.resolve(); await Promise.all([starting, stopping]);
      assert.ok(f.trace.indexOf('reconcile:end') < f.trace.indexOf('close:start'));
      assert.ok(!f.trace.includes('read:manifest')); assert.equal(f.intervals.length, 0);
    } finally { f.dispose(); }
  });
  await check(variant, 'queued_health_callback_refuses_after_stop_and_cycle_drains', async () => {
    const entered = deferred(), gate = deferred();
    const f = await fixture(variant, { manifestEntered: entered, manifestGate: gate });
    try {
      const starting = f.service.start(f.ctx); await entered.promise;
      const queuedEvent = f.event.handle(f.healthEvent);
      const stopping = f.service.stop(); assert.ok(!f.trace.includes('close:start'));
      gate.resolve(); await Promise.all([starting, queuedEvent, stopping]);
      assert.equal(f.trace.filter(v => v === 'publish:health-observation').length, 0);
      assert.equal(f.trace.filter(v => v === 'close:start').length, 1);
      assert.equal(f.intervals.length, 0);
      assert.ok(f.trace.indexOf('close:start') > f.trace.lastIndexOf('read:manifest'));
    } finally { f.dispose(); }
  });
  await check(variant, 'startup_unknown_propagates_and_closes_once', async () => {
    const f = await fixture(variant, { reconcileError: new Error('outbox_mutation_outcome_unknown') });
    try {
      await assert.rejects(() => f.service.start(f.ctx), /outbox_mutation_outcome_unknown/);
      await f.service.stop();
      assert.equal(f.trace.filter(v => v === 'close:start').length, 1);
      assert.ok(!f.trace.includes('read:manifest')); assert.equal(f.intervals.length, 0);
    } finally { f.dispose(); }
  });
  await check(variant, 'unknown_close_is_propagated_without_second_revoke', async () => {
    const f = await fixture(variant, { closeError: new Error('original_revoke_outcome_unknown') });
    try {
      await f.service.start(f.ctx);
      await assert.rejects(() => f.service.stop(), /original_revoke_outcome_unknown/);
      await assert.rejects(() => f.service.stop(), /original_revoke_outcome_unknown/);
      assert.equal(f.trace.filter(v => v === 'close:start').length, 1);
      assert.equal(f.trace.filter(v => v === 'close:end').length, 0);
      assert.equal(f.constructed.length, 1);
    } finally { f.dispose(); }
  });
}
console.log(JSON.stringify({ schema: 'heptabao.production-plugin-wiring-fixture.r1', ok: true,
  checks, passed: checks.length, actualCompletePreparedPluginSourceLoaded: true,
  sdkBoundarySubstituted: true, transportNetworkBoundarySubstituted: true,
  originalLocalHelperSourcesLoaded: true, actualProviderCalls: 0, productionServiceActions: 0,
  actualTlsOrRenewRevokeQualified: false, productionCutoverQualified: false }, null, 2));
