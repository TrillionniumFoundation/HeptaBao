/**
 * R5 owned SDK adapter. The issuer, control source and SDK read/write functions
 * are configured by bootstrap, never passed by a product request. Refresh runs
 * only through the SDK's exact shared OAuth manager/transport overlay.
 */
import crypto from "node:crypto";
import path from "node:path";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { DispatchAdmissionRegistry } from "./authbus_dispatch_registry_candidate.mjs";
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const check = (condition, code) => { if (!condition) fail(code); };
const scopeKey = value => path.resolve(value.agentDir) + "\u0000" + value.provider;
const permitKey = permit => digest({ epoch: permit.epoch, leaseId: permit.leaseId, profileId: permit.profileId, digest: permit.credentialDigest });
export class TrustedRefreshAdmissionRegistry extends DispatchAdmissionRegistry {
  #refreshBindings = new Map(); #successors = new Map(); #fingerprintKey = crypto.randomBytes(32);
  constructor({ refreshBindings, ...options }) {
    super(options);
    check(Array.isArray(refreshBindings) && refreshBindings.length > 0, "trusted_refresh_bindings_required");
    for (const binding of refreshBindings) {
      const authority = this.requireOwner(binding.scope), key = scopeKey(authority.scope);
      check(!this.#refreshBindings.has(key) && binding.controlSource && binding.coordinator &&
        typeof binding.commitCredential === "function", "trusted_refresh_binding_invalid");
      this.#refreshBindings.set(key, Object.freeze({ ...binding, authority }));
    }
    this.refreshObservations = { attempts: 0, published: 0, failed: 0, successorResolutions: 0 };
  }
  #fingerprint(value) {
    check(typeof value === "string" && value.length > 0, "trusted_refresh_wire_credential_invalid");
    return crypto.createHmac("sha256", this.#fingerprintKey).update(value).digest("hex");
  }
  /** Called only at the exact SDK OAuth refresh boundary. */
  async refreshManagedOAuth(params, runProviderRefresh) {
    const authority = this.owner(params);
    if (!authority) return { managed: false };
    const binding = this.#refreshBindings.get(scopeKey(authority.scope));
    check(binding && typeof runProviderRefresh === "function", "trusted_refresh_owner_unconfigured");
    const readCredential = () => this.readStore(authority.scope.agentDir).profiles[params.profileId];
    const permit = this.decision({ ...params, store: this.readStore(authority.scope.agentDir) });
    check(permit?.allowed && permit.profileId === params.profileId &&
      digest(readCredential()) === permit.credentialDigest &&
      (!params.credential || digest(params.credential) === permit.credentialDigest), "trusted_refresh_admission_denied");
    const current = authority._read();
    const request = binding.controlSource.bootstrapRequest(authority.scope, { model: current.grant.model,
      profileId: params.profileId, credentialDigest: permit.credentialDigest });
    this.refreshObservations.attempts++;
    try {
      const receipt = await binding.coordinator.refreshOnce(request, {
        readCredential,
        closeAdmission: () => { authority.closeUnresolved(); return !authority.inspect().allowed; },
        refreshCredential: runProviderRefresh,
        writeCredential: credential => binding.commitCredential({
          agentDir: authority.scope.agentDir, profileId: params.profileId, credential, expectedCredentialDigest: permit.credentialDigest,
        }),
      });
      const nextRequest = binding.controlSource.bootstrapRequest(authority.scope, { model: current.grant.model,
        profileId: params.profileId, credentialDigest: receipt.credentialDigest });
      await binding.coordinator.issue(nextRequest, { leaseMs: binding.leaseMs ?? 5000, epochFloor: receipt.publishedEpoch });
      await applyFromTrustedControl({ authority, controlSource: binding.controlSource,
        // The real SDK transaction has already committed and was independently
        // reread above. This publishes the fresh local authorization envelope.
        updateStore: () => true,
        verifyStore: grant => {
          const store = this.readStore(authority.scope.agentDir);
          return grant.profileId === params.profileId && digest(store.profiles[params.profileId]) === receipt.credentialDigest &&
            store.order?.[authority.scope.provider]?.length === 1 && store.order[authority.scope.provider][0] === params.profileId;
        },
      });
      const nextPermit = authority.inspect(), credential = readCredential();
      check(nextPermit.allowed && nextPermit.epoch > receipt.publishedEpoch &&
        nextPermit.credentialDigest === receipt.credentialDigest, "trusted_refresh_successor_admission_missing");
      const successorPrefix = scopeKey(authority.scope) + "\u0000";
      for (const key of this.#successors.keys()) if (key.startsWith(successorPrefix)) this.#successors.delete(key);
      this.#successors.set(successorPrefix + permitKey(permit), {
        permit: Object.freeze({ ...nextPermit }), wireFingerprint: this.#fingerprint(credential.access),
      });
      this.refreshObservations.published++;
      return { managed: true, credential, receipt };
    } catch (error) {
      this.refreshObservations.failed++;
      // A coordinator failure never falls through to SDK refresh retries,
      // parent-store sync, external CLI credential sync or ambient auth.
      throw error;
    }
  }
  /** A resolver may cross an epoch only through this registry's own successful
   * refresh and only while returning its exact newly published wire secret. */
  advanceAfterRefresh(params, previousPermit, profileId, rawApiKey) {
    try { super.assertCurrent(params, previousPermit, profileId); return previousPermit; }
    catch (error) { if (error.diagnosticCode !== "authbus_request_admission_denied") throw error; }
    const authority = this.requireOwner(params);
    const successor = this.#successors.get(scopeKey(authority.scope) + "\u0000" + permitKey(previousPermit));
    check(successor && successor.permit.profileId === profileId &&
      successor.wireFingerprint === this.#fingerprint(rawApiKey), "trusted_refresh_successor_result_unbound");
    super.assertCurrent(params, successor.permit, profileId);
    this.refreshObservations.successorResolutions++;
    return successor.permit;
  }
  bindCredentialResult(params, previousPermit, profileId, result, rawApiKey) {
    const permit = this.advanceAfterRefresh(params, previousPermit, profileId, rawApiKey);
    return super.bindCredentialResult(params, permit, profileId, result, rawApiKey);
  }
}
