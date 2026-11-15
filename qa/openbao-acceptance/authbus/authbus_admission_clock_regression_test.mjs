#!/usr/bin/env node
/** Synthetic credential, real durable filesystem, public-API clock regressions. */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const moduleArg = process.argv.indexOf("--authority");
const moduleUrl = moduleArg >= 0 ? pathToFileURL(path.resolve(process.argv[moduleArg + 1])) :
  new URL("./authbus_admission_authority_candidate.mjs", import.meta.url);
const { AdmissionAuthority, digest } = await import(moduleUrl.href);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-admission-clock-r3-"));
fs.chmodSync(root, 0o700);
const cases = [];
const credential = { type: "api_key", provider: "synthetic", key: "synthetic-clock-test-only" };

async function check(name, run) {
  const directory = path.join(root, String(cases.length));
  fs.mkdirSync(directory, { mode: 0o700 });
  const clock = { wall: 1000, mono: 0 };
  const scope = { hostId: "synthetic-clock-host", agentId: "main",
    agentDir: path.join(directory, "agent"), provider: "synthetic" };
  const create = () => new AdmissionAuthority({ directory, scope,
    wallNow: () => clock.wall, monotonicNow: () => clock.mono });
  const authority = create();
  const lease = { epoch: 11, status: "ASSIGNED", mode: "enforce", expiresAt: 11000,
    model: "synthetic-clock-model", profileId: "synthetic:owned", digest: digest(credential),
    leaseId: "synthetic-clock-lease-11" };
  let mutations = 0;
  const apply = (grant = lease) => authority.apply(grant, {
    updateStore: () => { mutations += 1; return true; }, verifyStore: () => true,
  });
  const record = () => JSON.parse(fs.readFileSync(authority.filename, "utf8"));
  try {
    await run({ authority, create, clock, lease, apply, record, mutations: () => mutations });
    cases.push({ case: name, passed: true });
  } catch (error) {
    cases.push({ case: name, passed: false, error: String(error.diagnosticCode ?? error.message).slice(0, 1000) });
  }
}

try {
  await check("same_epoch_apply_cannot_reopen_after_observed_wall_rollback", async t => {
    await t.apply();
    Object.assign(t.clock, { wall: 9000, mono: 8000 });
    assert.equal(t.authority.inspect().allowed, true);
    const before = t.mutations();
    Object.assign(t.clock, { wall: 6000, mono: 9000 });
    await assert.rejects(() => t.apply(), /clock_rollback/);
    assert.equal(t.mutations(), before, "SDK store must not be touched after detected rollback");
    assert.equal(t.record().phase, "expired");
    Object.assign(t.clock, { wall: 10000, mono: 10000 });
    await assert.rejects(() => t.authority.reconcileCommitted(t.lease, { verifyStore: () => true }));
    assert.equal(t.authority.inspect().allowed, false);
    assert.equal(t.create().inspect().allowed, false);
  });
  await check("same_epoch_reconciliation_rejects_observed_wall_rollback_before_store_verification", async t => {
    await t.apply();
    Object.assign(t.clock, { wall: 9000, mono: 8000 });
    assert.equal(t.authority.inspect().allowed, true);
    Object.assign(t.clock, { wall: 6000, mono: 9000 });
    let verified = false;
    await assert.rejects(() => t.authority.reconcileCommitted(t.lease,
      { verifyStore: () => { verified = true; return true; } }), /clock_rollback/);
    assert.equal(verified, false);
    assert.equal(t.record().phase, "expired");
    assert.equal(t.authority.inspect().allowed, false);
  });
  await check("same_epoch_apply_does_not_extend_deadline_when_wall_clock_stalls", async t => {
    await t.apply();
    t.clock.mono = 9000;
    await t.apply();
    assert.equal(t.authority.inspect().allowed, true);
    t.clock.mono = 10001;
    assert.equal(t.authority.inspect().allowed, false, "original 10000 ms monotonic deadline must remain binding");
    assert.equal(t.record().phase, "expired");
  });
  await check("same_epoch_reconciliation_does_not_extend_deadline_when_wall_clock_stalls", async t => {
    await t.apply();
    t.clock.mono = 9000;
    await t.authority.reconcileCommitted(t.lease, { verifyStore: () => true });
    assert.equal(t.authority.inspect().allowed, true);
    t.clock.mono = 10001;
    assert.equal(t.authority.inspect().allowed, false, "reconciliation must retain the original deadline");
    assert.equal(t.record().phase, "expired");
  });
  await check("failed_reconciliation_does_not_erase_consumed_lease_time", async t => {
    await t.apply();
    t.clock.mono = 9000;
    await assert.rejects(() => t.authority.reconcileCommitted(t.lease,
      { verifyStore: () => false }), /store_verification_failed/);
    assert.equal(t.authority.inspect().allowed, false);
    t.clock.mono = 9500;
    await t.authority.reconcileCommitted(t.lease, { verifyStore: () => true });
    assert.equal(t.authority.inspect().allowed, true);
    t.clock.mono = 10001;
    assert.equal(t.authority.inspect().allowed, false, "closing and reopening admission must not refresh lease time");
  });
  await check("initial_awaited_store_transaction_counts_against_original_deadline", async t => {
    await t.authority.apply(t.lease, {
      updateStore: async () => { await Promise.resolve(); t.clock.mono = 11000; return true; },
      verifyStore: () => true,
    });
    assert.equal(t.authority.inspect().allowed, false, "an expired SDK transaction must commit a closed result");
    assert.equal(t.record().phase, "expired");
    assert.equal(t.record().acceptedEpoch, t.lease.epoch);
    assert.equal(t.record().authorized, false);
  });
  await check("awaited_reconciliation_verification_cannot_refresh_deadline", async t => {
    await t.apply();
    t.clock.mono = 1000;
    await t.authority.reconcileCommitted(t.lease, { verifyStore: async () => {
      await Promise.resolve(); t.clock.mono = 11000; return true;
    } });
    assert.equal(t.authority.inspect().allowed, false);
    assert.equal(t.record().phase, "expired");
  });
  await check("higher_epoch_with_forward_clocks_can_authorize_a_new_lease", async t => {
    await t.apply();
    Object.assign(t.clock, { wall: 9000, mono: 8000 });
    assert.equal(t.authority.inspect().allowed, true);
    const next = { ...t.lease, epoch: 12, leaseId: "synthetic-clock-lease-12", expiresAt: 19000 };
    await t.apply(next);
    Object.assign(t.clock, { wall: 12000, mono: 11000 });
    const permit = t.authority.inspect();
    assert.equal(permit.allowed, true);
    assert.equal(permit.epoch, 12);
    assert.equal(permit.leaseId, next.leaseId);
    Object.assign(t.clock, { wall: 19000, mono: 18000 });
    assert.equal(t.authority.inspect().allowed, false);
    assert.equal(t.record().phase, "expired");
  });
  await check("monotonic_clock_rollback_is_closed_before_same_epoch_store_mutation", async t => {
    await t.apply();
    Object.assign(t.clock, { wall: 9000, mono: 8000 });
    assert.equal(t.authority.inspect().allowed, true);
    Object.assign(t.clock, { wall: 9500, mono: 7000 });
    const before = t.mutations();
    await assert.rejects(() => t.apply(), /clock_rollback/);
    assert.equal(t.mutations(), before);
    assert.equal(t.record().phase, "expired");
  });
  const ok = cases.every(c => c.passed);
  console.log(JSON.stringify({ schema: "authbus-admission-clock-regression-r3", ok,
    authorityModule: moduleUrl.pathname, checks: cases, syntheticCredential: true, realDurableFilesystem: true,
    fakeClocks: true, coldProcessQualified: false, actualOpenclawSdk: false,
    finalProviderDispatchQualified: false, productionMutation: false }));
  if (!ok) process.exitCode = 1;
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
