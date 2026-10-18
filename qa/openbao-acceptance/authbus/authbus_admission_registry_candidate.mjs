/**
 * Review-only adapter registry. The real SDK source candidate invokes decision()
 * inside order/eligibility and provider credential resolution, not in a test
 * replacement for those functions. Only explicitly configured scopes are covered.
 */
import path from "node:path";
import { digest } from "./authbus_admission_authority_candidate.mjs";
export const ADMISSION_SYMBOL = Symbol.for("heptabao.authbus.admission.candidate.v1");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
export class AdmissionRegistry {
  constructor({ authorities, resolveDefaultAgentDir, resolveProviderIdForAuth, readStore }) {
    if (!Array.isArray(authorities) || authorities.length === 0) fail("admission_bindings_required");
    this.authorities = new Map();
    this.providers = new Set();
    for (const authority of authorities) {
      const scope = authority.scope;
      const key = path.resolve(scope.agentDir) + "\u0000" + scope.provider;
      if (this.authorities.has(key)) fail("admission_duplicate_binding");
      this.authorities.set(key, authority);
      this.providers.add(scope.provider);
    }
    this.resolveDefaultAgentDir = resolveDefaultAgentDir;
    this.resolveProviderIdForAuth = resolveProviderIdForAuth;
    this.readStore = readStore;
    this.observations = { decisions: 0, covered: 0, denied: 0, allowed: 0, unmanaged: 0 };
  }
  owner(params) {
    const provider = params.providerAuthKey ?? this.resolveProviderIdForAuth(params.provider, { config: params.cfg });
    if (!this.providers.has(provider)) return null;
    const agentDir = params.agentDir ?? this.resolveDefaultAgentDir(params.cfg ?? {});
    if (typeof agentDir !== "string" || !path.isAbsolute(agentDir)) fail("admission_agent_scope_missing");
    const authority = this.authorities.get(path.resolve(agentDir) + "\u0000" + provider);
    if (!authority) fail("admission_agent_scope_unconfigured");
    return authority;
  }
  decision(params) {
    this.observations.decisions += 1;
    let authority;
    try { authority = this.owner(params); }
    catch (error) { this.observations.denied += 1; return { allowed: false, reason: error.diagnosticCode ?? "admission_scope_unavailable" }; }
    if (!authority) { this.observations.unmanaged += 1; return null; }
    this.observations.covered += 1;
    const permit = authority.inspect();
    if (!permit.allowed || !params.store?.profiles?.[permit.profileId] ||
        digest(params.store.profiles[permit.profileId]) !== permit.credentialDigest) {
      this.observations.denied += 1;
      return { allowed: false, reason: permit.reason ?? "admission_credential_mismatch" };
    }
    this.observations.allowed += 1;
    return permit;
  }
  requireOwner(params) {
    const authority = this.owner(params);
    if (!authority) fail("admission_enforced_scope_unconfigured");
    return authority;
  }
  async saveAssignment(params, updateStore, verifyStore) {
    const authority = this.requireOwner(params);
    if (!params.grant || !Number.isSafeInteger(params.grant.epoch)) {
      authority.closeUnresolved();
      const result = await updateStore();
      if (await verifyStore() !== true) fail("admission_store_verification_failed");
      return result;
    }
    return authority.apply(params.grant, { updateStore, verifyStore, authorize: Boolean(params.profileId) });
  }
  closeExpired(params) {
    this.requireOwner(params).closeUnresolved({ expired: true });
  }
  assertCurrent(params, previousPermit, selectedProfileId) {
    const owner = this.owner(params);
    if (!owner) return;
    const permit = this.decision({ ...params, store: this.readStore(owner.scope.agentDir) });
    if (!permit?.allowed || permit.profileId !== selectedProfileId ||
        previousPermit && (permit.epoch !== previousPermit.epoch || permit.leaseId !== previousPermit.leaseId ||
          permit.credentialDigest !== previousPermit.credentialDigest)) fail("authbus_request_admission_denied");
  }
  install() {
    if (globalThis[ADMISSION_SYMBOL]) fail("admission_registry_already_installed");
    Object.defineProperty(globalThis, ADMISSION_SYMBOL, { value: this, writable: false, configurable: true });
    return () => { if (globalThis[ADMISSION_SYMBOL] === this) delete globalThis[ADMISSION_SYMBOL]; };
  }
}


