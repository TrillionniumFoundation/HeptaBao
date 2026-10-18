#!/usr/bin/env node
/** Local contract only: real files, synthetic credentials, simulated dispatch. */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AdmissionAuthority, digest } from "./authbus_admission_authority_candidate.mjs";
import { DispatchAdmissionRegistry, AUTH_CAPABILITY_SYMBOL, MODEL_CAPABILITY_SYMBOL } from "./authbus_dispatch_registry_candidate.mjs";

const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-dispatch-contract-"));
fs.chmodSync(root, 0o700);
const cases = [];
async function check(name, run) {
  const directory = path.join(root, String(cases.length));
  fs.mkdirSync(directory, { mode: 0o700 });
  const clock = { wall: 1000, mono: 0 };
  const scope = { hostId: "synthetic-dispatch-host", agentId: "main", agentDir: path.join(directory, "agent"), provider: "google" };
  const credential = { type: "api_key", provider: "google", key: "synthetic-dispatch-key-only" };
  const profile = "google:synthetic-dispatch-owned";
  const store = { profiles: { [profile]: credential } };
  const authority = new AdmissionAuthority({ directory, scope, wallNow: () => clock.wall, monotonicNow: () => clock.mono });
  const registry = new DispatchAdmissionRegistry({ authorities: [authority],
    resolveDefaultAgentDir: () => scope.agentDir, resolveProviderIdForAuth: value => value, readStore: () => store });
  const uninstall = registry.install();
  const params = { provider: scope.provider, agentDir: scope.agentDir };
  const lease = { epoch: 11, status: "ASSIGNED", mode: "enforce", model: "synthetic-model", profileId: profile,
    digest: digest(credential), expiresAt: 11000, leaseId: "synthetic-dispatch-lease-11" };
  const model = { provider: "google", id: "synthetic-model", api: "google-generative-ai" };
  const apply = grant => authority.apply(grant ?? lease, { updateStore: () => true, verifyStore: () => true });
  const auth = () => registry.bindCredentialResult(params, authority.inspect(), profile,
    { apiKey: credential.key, profileId: profile }, credential.key);
  const prepare = () => registry.bindModelForDispatch(model, auth());
  const request = token => ({ token, args: { provider: "google", model: "synthetic-model",
    url: "https://synthetic.invalid/request", init: { headers: { Authorization: "Bearer " + credential.key } } } });
  const dispatch = (token, extra) => {
    const r = request(token);
    registry.assertTransportDispatch(r.token, { ...r.args, ...extra });
  };
  try {
    await apply();
    await run({ clock, scope, credential, profile, store, authority, registry, params, lease, model,
      apply, auth, prepare, request, dispatch, uninstall });
    cases.push({ case: name, passed: true });
  } catch (error) {
    cases.push({ case: name, passed: false, error: String(error.diagnosticCode ?? error.message).slice(0, 1000) });
  } finally { uninstall(); }
}

try {
  await check("opaque_capability_survives_auth_and_model_spreads", t => {
    const auth = { ...t.auth() };
    const model = { ...t.registry.bindModelForDispatch(t.model, auth) };
    t.dispatch(t.registry.captureModelDispatch(model));
    assert.equal(t.registry.dispatchObservations.allowed, 1);
    assert.equal(JSON.stringify(auth).includes("capability"), false);
  });
  await check("missing_forged_and_serialized_capabilities_cannot_authorize_managed_model", t => {
    assert.throws(() => t.registry.captureModelDispatch(t.model), /capability_required/);
    assert.throws(() => t.registry.bindModelForDispatch(t.model,
      { apiKey: t.credential.key, [AUTH_CAPABILITY_SYMBOL]: {} }), /capability_invalid/);
    assert.throws(() => t.registry.captureModelDispatch({ ...t.model, [MODEL_CAPABILITY_SYMBOL]: {} }), /capability_invalid/);
    assert.throws(() => t.registry.bindModelForDispatch(t.model, JSON.parse(JSON.stringify(t.auth()))), /capability_required/);
    assert.throws(() => t.dispatch(null), /capability_required/);
  });
  await check("expiry_after_credential_resolution_denies_before_dispatch", async t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    await Promise.resolve();
    t.clock.mono = 10001;
    assert.throws(() => t.dispatch(token), /admission_denied/);
    assert.equal(t.registry.dispatchObservations.allowed, 0);
    assert.equal(JSON.parse(fs.readFileSync(t.authority.filename)).phase, "expired");
  });
  await check("failed_revocation_keeps_old_store_but_closes_captured_request", async t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    const before = digest(t.store);
    await assert.rejects(() => t.authority.apply({ ...t.lease, epoch: 12, status: "UNASSIGNED" }, {
      updateStore: () => { throw new Error("synthetic-store-abort"); }, verifyStore: () => true,
    }), /synthetic-store-abort/);
    assert.equal(digest(t.store), before);
    assert.equal(JSON.parse(fs.readFileSync(t.authority.filename)).phase, "pending");
    assert.throws(() => t.dispatch(token), /admission_denied/);
    assert.equal(t.registry.dispatchObservations.allowed, 0);
  });
  await check("higher_epoch_invalidates_old_request_even_when_credential_is_identical", async t => {
    const oldToken = t.registry.captureModelDispatch(t.prepare());
    await t.apply({ ...t.lease, epoch: 12, leaseId: "synthetic-dispatch-lease-12" });
    assert.throws(() => t.dispatch(oldToken), /admission_denied/);
    t.dispatch(t.registry.captureModelDispatch(t.prepare()));
    assert.equal(t.registry.dispatchObservations.allowed, 1);
  });
  await check("fresh_store_credential_digest_is_checked_at_dispatch", t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    t.store.profiles[t.profile] = { ...t.credential, key: "synthetic-changed-store-key" };
    assert.throws(() => t.dispatch(token), /admission_denied/);
    assert.equal(t.registry.dispatchObservations.allowed, 0);
  });
  await check("capability_cannot_be_reused_for_another_model_or_provider", t => {
    const auth = t.auth();
    assert.throws(() => t.registry.bindModelForDispatch({ ...t.model, id: "another-model" }, auth), /lease_model_mismatch/);
    assert.throws(() => t.registry.bindModelForDispatch({ ...t.model, provider: "anthropic" }, auth), /provider_mismatch/);
    const token = t.registry.captureModelDispatch(t.prepare());
    assert.throws(() => t.dispatch(token, { provider: "anthropic" }), /model_capability_invalid/);
    assert.throws(() => t.dispatch(token, { model: "another-model" }), /model_capability_invalid/);
  });
  await check("wrong_missing_and_unsupported_wire_auth_are_denied", t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    assert.throws(() => t.dispatch(token, { init: { headers: { authorization: "Bearer synthetic-wrong-key" } } }), /wire_credential_mismatch/);
    assert.throws(() => t.dispatch(token, { init: {} }), /credential_missing/);
    assert.throws(() => t.dispatch(token, { init: { headers: { authorization: "Basic synthetic" } } }), /auth_header_unsupported/);
  });
  await check("matching_api_key_header_or_query_is_allowed_but_conflicting_auth_is_denied", t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    t.dispatch(token, { init: { headers: { "x-goog-api-key": t.credential.key } } });
    t.dispatch(token, { url: "https://synthetic.invalid/request?key=" + t.credential.key, init: {} });
    assert.throws(() => t.dispatch(token, { url: "https://synthetic.invalid/request?key=synthetic-conflict" }), /wire_credential_mismatch/);
    assert.equal(t.registry.dispatchObservations.allowed, 2);
  });
  await check("unbound_runtime_credential_derivation_is_closed", t => {
    const auth = { ...t.auth(), apiKey: "synthetic-derived-runtime-token" };
    assert.throws(() => t.registry.bindModelForDispatch(t.model, auth), /derived_credential_unbound/);
  });
  await check("redirect_iteration_rechecks_deadline", t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    t.dispatch(token);
    t.clock.mono = 10001;
    assert.throws(() => t.dispatch(token, { url: "https://synthetic.invalid/redirected" }), /admission_denied/);
    assert.equal(t.registry.dispatchObservations.allowed, 1);
  });
  await check("unmanaged_provider_stays_available_and_registry_removal_closes_existing_capability", t => {
    const token = t.registry.captureModelDispatch(t.prepare());
    const unmanaged = { provider: "anthropic", id: "synthetic-unmanaged" };
    assert.equal(t.registry.bindModelForDispatch(unmanaged, null), unmanaged);
    assert.equal(t.registry.captureModelDispatch(unmanaged), null);
    t.registry.assertTransportDispatch(null, { provider: "anthropic", model: "synthetic-unmanaged" });
    t.uninstall();
    assert.throws(() => t.dispatch(token), /authority_unavailable/);
  });
  const ok = cases.every(item => item.passed);
  console.log(JSON.stringify({ schema: "authbus-dispatch-local-contract-r1", ok, checks: cases,
    realDurableFilesystem: true, fakeClocks: true, syntheticCredentials: true, simulatedDispatch: true,
    actualOpenclawSdk: false, actualHttpReceiver: false, productionMutation: false,
    allProductDispatchCoverageQualified: false, oauthRefreshOwnershipQualified: false }));
  if (!ok) process.exitCode = 1;
} finally { fs.rmSync(root, { recursive: true, force: true }); }
