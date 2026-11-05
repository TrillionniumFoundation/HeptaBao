/**
 * Review-only final HTTP dispatch adapter for explicitly managed LLM scopes.
 * Carries a resolver-issued opaque capability through model preparation. No
 * credential material, capabilities, or full URLs belong in public receipts.
 */
import crypto from "node:crypto";
import { AdmissionRegistry, ADMISSION_SYMBOL } from "./authbus_admission_registry_candidate.mjs";

export const AUTH_CAPABILITY_SYMBOL = Symbol.for("heptabao.authbus.auth-capability.candidate.v1");
export const MODEL_CAPABILITY_SYMBOL = Symbol.for("heptabao.authbus.model-capability.candidate.v1");
export const REQUEST_CAPABILITY_SYMBOL = Symbol.for("heptabao.authbus.request-capability.candidate.v1");
const failure = code => Object.assign(new Error(code), { diagnosticCode: code });
const check = (condition, code) => { if (!condition) throw failure(code); };
const AUTH_HEADERS = ["authorization", "x-api-key", "x-goog-api-key", "api-key", "x-auth-token", "ocp-apim-subscription-key"];
const AUTH_QUERY_KEYS = new Set(["key", "api_key", "api-key", "access_token", "token"]);

export class DispatchAdmissionRegistry extends AdmissionRegistry {
  #authCapabilities = new WeakMap();
  #modelCapabilities = new WeakMap();
  #fingerprintKey = crypto.randomBytes(32);
  constructor(options) {
    super(options);
    this.dispatchObservations = { boundCredentials: 0, boundModels: 0, attempts: 0, allowed: 0, denied: 0, unmanaged: 0 };
  }
  #fingerprint(value) {
    check(typeof value === "string" && value.length > 0, "authbus_dispatch_credential_invalid");
    return crypto.createHmac("sha256", this.#fingerprintKey).update(value).digest("hex");
  }
  #installed() {
    check(globalThis[ADMISSION_SYMBOL] === this, "authbus_dispatch_authority_unavailable");
  }
  #current(entry) {
    this.#installed();
    this.assertCurrent(entry.params, entry.permit, entry.permit.profileId);
  }
  #managedProvider(provider, cfg) {
    if (typeof provider !== "string" || provider.length === 0) return false;
    return this.providers.has(this.resolveProviderIdForAuth(provider, { config: cfg }));
  }
  bindCredentialResult(params, previousPermit, selectedProfileId, result, rawApiKey) {
    this.#installed();
    const authority = this.owner(params);
    if (!authority) return result;
    this.assertCurrent(params, previousPermit, selectedProfileId);
    const record = authority._read();
    check(record.phase === "committed" && record.authorized && record.grant.epoch === previousPermit.epoch &&
      record.grant.leaseId === previousPermit.leaseId && record.grant.profileId === selectedProfileId &&
      record.grant.digest === previousPermit.credentialDigest, "authbus_dispatch_control_changed");
    check(result && typeof result === "object" && typeof result.apiKey === "string", "authbus_dispatch_auth_result_invalid");
    const token = Object.freeze(Object.create(null));
    this.#authCapabilities.set(token, {
      params: { agentDir: authority.scope.agentDir, providerAuthKey: authority.scope.provider },
      provider: authority.scope.provider, cfg: params.cfg,
      permit: Object.freeze({ ...previousPermit }), leaseModel: record.grant.model,
      resultFingerprint: this.#fingerprint(result.apiKey), wireFingerprint: this.#fingerprint(rawApiKey),
    });
    Object.defineProperty(result, AUTH_CAPABILITY_SYMBOL, { value: token, enumerable: true });
    this.dispatchObservations.boundCredentials += 1;
    return result;
  }
  bindModelForDispatch(model, auth) {
    this.#installed();
    check(model && typeof model === "object", "authbus_dispatch_model_invalid");
    const authToken = auth?.[AUTH_CAPABILITY_SYMBOL];
    if (!authToken) {
      const existing = model[MODEL_CAPABILITY_SYMBOL];
      if (existing && this.#modelCapabilities.has(existing)) {
        this.#validateModel(model, existing);
        return model;
      }
      check(!this.#managedProvider(model.provider), "authbus_dispatch_auth_capability_required");
      return model;
    }
    const entry = this.#authCapabilities.get(authToken);
    check(entry, "authbus_dispatch_auth_capability_invalid");
    this.#current(entry);
    check(this.resolveProviderIdForAuth(model.provider, { config: entry.cfg }) === entry.provider,
      "authbus_dispatch_provider_mismatch");
    check(this.#fingerprint(auth.apiKey) === entry.resultFingerprint,
      "authbus_dispatch_derived_credential_unbound");
    check(typeof model.id === "string" && model.id.length > 0 &&
      (entry.leaseModel === model.id || entry.leaseModel === entry.provider + "/" + model.id),
      "authbus_dispatch_lease_model_mismatch");
    const token = Object.freeze(Object.create(null));
    this.#modelCapabilities.set(token, { authToken, provider: model.provider, modelId: model.id });
    this.dispatchObservations.boundModels += 1;
    return { ...model, [MODEL_CAPABILITY_SYMBOL]: token };
  }
  #validateModel(model, token) {
    const bound = this.#modelCapabilities.get(token);
    check(bound && model.provider === bound.provider && model.id === bound.modelId,
      "authbus_dispatch_model_capability_invalid");
    const entry = this.#authCapabilities.get(bound.authToken);
    check(entry, "authbus_dispatch_auth_capability_invalid");
    this.#current(entry);
    return { bound, entry };
  }
  captureModelDispatch(model) {
    this.#installed();
    const token = model?.[MODEL_CAPABILITY_SYMBOL];
    if (!token) {
      check(!this.#managedProvider(model?.provider), "authbus_dispatch_model_capability_required");
      return null;
    }
    this.#validateModel(model, token);
    return token;
  }
  assertTransportDispatch(token, { provider, model, url, init } = {}) {
    this.dispatchObservations.attempts += 1;
    try {
      this.#installed();
      if (!token) {
        check(!this.#managedProvider(provider), "authbus_dispatch_model_capability_required");
        this.dispatchObservations.unmanaged += 1;
        return;
      }
      const { entry } = this.#validateModel({ provider, id: model }, token);
      const credentials = [];
      const headers = new Headers(init?.headers);
      for (const name of AUTH_HEADERS) {
        const value = headers.get(name);
        if (value === null) continue;
        if (name === "authorization") {
          const match = /^Bearer\s+(.+)$/i.exec(value);
          check(match, "authbus_dispatch_auth_header_unsupported");
          credentials.push(match[1]);
        } else credentials.push(value);
      }
      for (const [name, value] of new URL(url).searchParams) if (AUTH_QUERY_KEYS.has(name.toLowerCase())) credentials.push(value);
      check(credentials.length > 0, "authbus_dispatch_credential_missing");
      check(credentials.every(value => this.#fingerprint(value) === entry.wireFingerprint),
        "authbus_dispatch_wire_credential_mismatch");
      // This call is synchronous and must be immediately followed by transport
      // dispatch. Every redirect iteration passes through this method again.
      this.#current(entry);
      this.dispatchObservations.allowed += 1;
    } catch (error) {
      this.dispatchObservations.denied += 1;
      throw error;
    }
  }
}
