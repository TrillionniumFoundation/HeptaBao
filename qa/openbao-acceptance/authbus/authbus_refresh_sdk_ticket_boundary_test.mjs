import assert from "node:assert/strict";
import { SdkOAuthRefreshAdmissionRegistry } from "./authbus_refresh_sdk_registry_candidate.mjs";
import { digest } from "./authbus_admission_authority_candidate.mjs";

// Exact registry unit boundary only. No SDK, SQLite, control authority, or
// provider round trip is claimed by this inert constructor fixture.
const scope = { hostId: "unit", agentId: "unit", agentDir: "/tmp/authbus-guard-ticket-unit", provider: "openai" };
const authority = { scope, inspect: () => ({ allowed: false }) };
const readOwnedStore = () => ({ version: 1, profiles: {} });
const registry = new SdkOAuthRefreshAdmissionRegistry({ authorities: [authority],
  resolveDefaultAgentDir: () => scope.agentDir,
  resolveProviderIdForAuth: provider => provider,
  readStore: readOwnedStore,
  sdkRefreshQualification: { readOwnedStore, providerOf: () => null, supportedProviders: () => ["openai"] },
  refreshBindings: [{ scope, controlSource: {}, coordinator: {}, commitCredential: () => false }] });
const uninstall = registry.install();
const init = () => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "unit-token", client_id: "app_EMoamEEZ73f0CkXaXp7hrann" }) });
const checks = [];
const check = (name, action) => { action(); checks.push(name); };
const denied = (action, code) => assert.throws(action, error => error.diagnosticCode === code);
try {
  for (const [name, url] of [
    ["canonical", "https://auth.openai.com/oauth/token"],
    ["default-port", "https://auth.openai.com:443/oauth/token"],
    ["host-case", "https://AUTH.OPENAI.COM/oauth/token"],
    ["trailing-host-dot", "https://auth.openai.com./oauth/token"],
    ["query", "https://auth.openai.com/oauth/token?unit=unbound"],
    ["encoded-path", "https://auth.openai.com/oauth/%74oken"],
    ["url-object", new URL("https://auth.openai.com/oauth/token")],
    ["request-object", new Request("https://auth.openai.com/oauth/token", init())],
  ]) {
    check("guard_context_required:" + name, () => denied(() => registry.prepareGuardedOAuthTransport({ url, init: init() }), "trusted_refresh_guarded_request_context_required"));
    check("runtime_ticket_required:" + name, () => denied(() => registry.enterGuardedOAuthRuntimeTransport(null, { url, init: init() }), "trusted_refresh_guarded_runtime_ticket_required"));
  }
  check("unknown_grant_cannot_look_unmanaged", () => denied(() => registry.enterGuardedOAuthRuntimeTransport(null, {
    url: "https://auth.openai.com/oauth/token", init: { ...init(), body: "refresh_token=unit-token" } }), "trusted_refresh_guarded_runtime_ticket_required"));
  check("unknown_guard_grant_cannot_look_unmanaged", () => denied(() => registry.prepareGuardedOAuthTransport({
    url: "https://auth.openai.com/oauth/token", init: { ...init(), body: "refresh_token=unit-token" } }), "trusted_refresh_guarded_request_context_required"));
  check("caller_created_ticket_rejected", () => denied(() => registry.enterGuardedOAuthRuntimeTransport(Object.freeze({}), {
    url: "https://auth.openai.com/oauth/token", init: init() }), "trusted_refresh_guarded_runtime_ticket_invalid"));
  let sends = 0;
  check("caller_created_ticket_cannot_send", () => denied(() => registry.dispatchGuardedOAuthTransport(Object.freeze({}), {
    url: "https://auth.openai.com/oauth/token", init: init() }, () => { sends++; }), "trusted_refresh_guarded_dispatch_ticket_invalid"));
  check("no_dispatch_side_effect", () => assert.equal(sends, 0));
  check("explicit_authorization_code_not_a_refresh_ticket", () => assert.equal(registry.prepareGuardedOAuthTransport({
    url: "https://auth.openai.com/oauth/token", init: { ...init(), body: "grant_type=authorization_code&code=unit-code" } }), null));
  check("unrelated_request_not_qualified_as_refresh", () => assert.equal(registry.enterGuardedOAuthRuntimeTransport(null, {
    url: "https://unrelated.invalid/resource", init: { method: "GET" } }), null));
} finally { uninstall(); }

// Exercise the real registry's private AsyncLocalStorage/ticket path with an
// explicitly inert owner/coordinator. The coordinator never issues a grant,
// writes a credential or publishes a result; it throws after the callback.
// This is a request-byte/affine-ticket unit test, not durable or SDK evidence.
async function withinUnitContext(action, after = async () => {}) {
  const credential = { type: "oauth", provider: "openai", access: "unit-original-access", refresh: "unit-token", expires: 1 };
  const profileId = "openai:unit";
  let allowed = true, record = { phase: "committed", grant: { model: "unit-model" }, authorized: true };
  const localStore = { version: 1, profiles: { [profileId]: credential }, order: { openai: [profileId] } };
  const readStore = () => structuredClone(localStore);
  const unitAuthority = { scope,
    inspect: () => ({ allowed, epoch: 1, leaseId: "unit-lease", profileId, credentialDigest: digest(credential) }),
    _read: () => structuredClone(record),
    closeUnresolved: () => { allowed = false; record = { ...record, authorized: false, phase: "closed" }; },
  };
  const contextClosed = Object.assign(new Error("unit-stopped-before-publish"), { diagnosticCode: "unit_no_publication" });
  const coordinator = { async refreshOnce(_request, callbacks) {
    assert.equal(callbacks.closeAdmission(), true);
    let consumed = false;
    await callbacks.refreshCredential(callbacks.readCredential(), send => {
      assert.equal(consumed, false, "unit one-shot dispatcher"); consumed = true; return send();
    });
    throw contextClosed;
  } };
  const local = new SdkOAuthRefreshAdmissionRegistry({ authorities: [unitAuthority],
    resolveDefaultAgentDir: () => scope.agentDir, resolveProviderIdForAuth: provider => provider,
    readStore, sdkRefreshQualification: { readOwnedStore: readStore, providerOf: () => null, supportedProviders: () => ["openai"] },
    refreshBindings: [{ scope, controlSource: { bootstrapRequest: () => ({ inertUnit: true }) }, coordinator,
      commitCredential: () => { throw new Error("unit must never commit"); } }] });
  const remove = local.install();
  try {
    await assert.rejects(() => local.resolveManagedOAuthAccess({ provider: "openai", profileId, agentDir: scope.agentDir, credential }, {
      needsRefresh: true, buildApiKey: () => { throw new Error("unit must never publish"); },
      refreshCredential: async () => { await action(local, unitAuthority, localStore); return null; },
    }), error => error === contextClosed);
    await after(local);
    assert.equal(local.refreshObservations.published, 0);
  } finally { remove(); }
}
const asyncCheck = async (name, action) => { await action(); checks.push(name); };
const url = "https://auth.openai.com/oauth/token";
await asyncCheck("final_request_body_getter_is_read_once", () => withinUnitContext(local => {
  let bodyReads = 0, sends = 0;
  const request = { method: "POST", headers: init().headers,
    get body() { bodyReads++; return bodyReads === 1 ? init().body : "grant_type=refresh_token&refresh_token=unvalidated&client_id=app_EMoamEEZ73f0CkXaXp7hrann"; } };
  local.dispatchManagedOAuthTransport({ provider: "openai", operation: "openai-token-refresh", url, init: request }, (target, actual) => {
    sends++; assert.equal(target, url); assert.equal(typeof actual.body, "string");
    assert.equal(new URLSearchParams(actual.body).get("refresh_token"), "unit-token");
  });
  assert.equal(sends, 1); assert.equal(bodyReads, 1);
}));
await asyncCheck("final_request_owns_mutable_form_and_headers", () => withinUnitContext(local => {
  const request = init(); request.headers = new Headers(request.headers);
  local.dispatchManagedOAuthTransport({ provider: "openai", operation: "openai-token-refresh", url, init: request }, (_target, actual) => {
    request.body.set("refresh_token", "caller-mutated-after-validation");
    request.headers.set("content-type", "application/json");
    assert.equal(typeof actual.body, "string");
    assert.equal(new URLSearchParams(actual.body).get("refresh_token"), "unit-token");
    assert.equal(actual.headers.get("content-type"), "application/x-www-form-urlencoded");
    assert.equal(actual.method, "POST"); assert.equal(actual.redirect, "error");
  });
}));
await asyncCheck("final_request_rejects_changed_token_before_send", () => withinUnitContext(local => {
  const request = init(); request.body.set("refresh_token", "not-the-owned-token"); let sends = 0;
  denied(() => local.dispatchManagedOAuthTransport({ provider: "openai", operation: "openai-token-refresh", url, init: request }, () => { sends++; }), "trusted_refresh_transport_credential_mismatch");
  assert.equal(sends, 0);
}));
await asyncCheck("ticket_revalidates_request_after_await", () => withinUnitContext(async local => {
  const request = init(), ticket = local.prepareGuardedOAuthTransport({ url, init: request });
  await Promise.resolve(); request.body.set("refresh_token", "changed-during-await"); let sends = 0;
  denied(() => local.dispatchGuardedOAuthTransport(ticket, { url, init: request }, () => { sends++; }), "trusted_refresh_transport_credential_mismatch");
  assert.equal(sends, 0);
  denied(() => local.dispatchGuardedOAuthTransport(ticket, { url, init: init() }, () => { sends++; }), "trusted_refresh_guarded_dispatch_ticket_invalid");
  assert.equal(sends, 0);
}));
await asyncCheck("ticket_revalidates_owner_after_await", () => withinUnitContext(async (local, _authority, store) => {
  const request = init(), ticket = local.prepareGuardedOAuthTransport({ url, init: request });
  await Promise.resolve(); store.profiles["openai:unit"].access = "changed-concurrent-owner"; let sends = 0;
  denied(() => local.dispatchGuardedOAuthTransport(ticket, { url, init: request }, () => { sends++; }), "trusted_refresh_sdk_changed_before_final_send");
  assert.equal(sends, 0);
}));
await asyncCheck("ticket_one_runtime_entry_and_one_final_send", () => withinUnitContext(local => {
  const request = init(), ticket = local.prepareGuardedOAuthTransport({ url, init: request }); let sends = 0;
  assert.equal(local.enterGuardedOAuthRuntimeTransport(ticket, { url, init: request }), ticket);
  denied(() => local.enterGuardedOAuthRuntimeTransport(ticket, { url, init: request }), "trusted_refresh_guarded_runtime_ticket_invalid");
  local.dispatchGuardedOAuthTransport(ticket, { url, init: request }, () => { sends++; });
  denied(() => local.dispatchGuardedOAuthTransport(ticket, { url, init: request }, () => { sends++; }), "trusted_refresh_guarded_dispatch_ticket_invalid");
  assert.equal(sends, 1); assert.equal(local.oauthSdkObservations.guardedRuntimeEntries, 1);
}));
await asyncCheck("ticket_continuation_closes_when_owner_callback_returns", async () => {
  let resume, continuation;
  await withinUnitContext(local => {
    const request = init(), ticket = local.prepareGuardedOAuthTransport({ url, init: request });
    const gate = new Promise(resolve => { resume = resolve; });
    // This continuation is created inside the private ALS owner context and
    // therefore retains that context after its enclosing callback returns.
    continuation = gate.then(() => local.dispatchGuardedOAuthTransport(ticket, { url, init: request }, () => { throw new Error("must not send"); }));
  }, async () => {
    resume();
    await assert.rejects(continuation, error => error.diagnosticCode === "trusted_refresh_guarded_dispatch_ticket_invalid");
  });
});
process.stdout.write(JSON.stringify({ schema: "authbus-openai-guard-ticket-unit", actualSdkExecution: false,
  actualNativeHeptaBao: false, actualProvider: false, checksPassed: checks.length, checks }, null, 2) + "\n");
