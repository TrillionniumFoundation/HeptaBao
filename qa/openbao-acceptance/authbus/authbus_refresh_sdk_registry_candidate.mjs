/** Owned SDK OAuth refresh boundary. Contexts are private and exist only after
 * the trusted coordinator has acknowledged the durable UNKNOWN intent. They
 * survive awaited SDK/plugin work but close on return or rejection, including
 * a timeout whose underlying provider promise continues in the background. */
import crypto from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { ADMISSION_SYMBOL } from "./authbus_admission_registry_candidate.mjs";
import { TrustedRefreshAdmissionRegistry } from "./authbus_refresh_registry_candidate.mjs";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const check = (condition, code) => { if (!condition) fail(code); };
const MAX_TOKEN_BODY_BYTES = 65536;

function formFields(body) {
  check(body instanceof URLSearchParams || typeof body === "string", "trusted_refresh_transport_form_invalid");
  const text = String(body);
  check(Buffer.byteLength(text) <= MAX_TOKEN_BODY_BYTES, "trusted_refresh_transport_body_excessive");
  const fields = new URLSearchParams(text), seen = new Set();
  for (const [name] of fields) {
    check(!seen.has(name), "trusted_refresh_transport_duplicate_field");
    seen.add(name);
  }
  return Object.fromEntries(fields);
}
function jsonFields(body) {
  check(typeof body === "string" && Buffer.byteLength(body) <= MAX_TOKEN_BODY_BYTES,
    "trusted_refresh_transport_json_invalid");
  let fields;
  try { fields = JSON.parse(body); } catch { fail("trusted_refresh_transport_json_invalid"); }
  // Exact bound SDK callers use JSON.stringify. Requiring its round trip also
  // rejects duplicate JSON keys whose first/last token interpretation differs.
  check(fields && typeof fields === "object" && !Array.isArray(fields) && JSON.stringify(fields) === body,
    "trusted_refresh_transport_json_ambiguous");
  return fields;
}

export class SdkOAuthRefreshAdmissionRegistry extends TrustedRefreshAdmissionRegistry {
  #contexts = new AsyncLocalStorage();
  #fingerprintKey = crypto.randomBytes(32);
  #qualification;
  constructor({ sdkRefreshQualification, ...options }) {
    super(options);
    check(sdkRefreshQualification && typeof sdkRefreshQualification.providerOf === "function" &&
      typeof sdkRefreshQualification.supportedProviders === "function" &&
      typeof sdkRefreshQualification.readOwnedStore === "function" && options.readStore === sdkRefreshQualification.readOwnedStore,
      "trusted_refresh_sdk_qualification_required");
    this.#qualification = sdkRefreshQualification;
    this.oauthSdkObservations = { managedResolutions: 0, usableResolutions: 0,
      refreshContexts: 0, entryChecks: 0, dispatchAttempts: 0, allowedDispatches: 0,
      deniedDispatches: 0, unmanagedDispatches: 0 };
  }
  #installed() {
    check(globalThis[ADMISSION_SYMBOL] === this, "trusted_refresh_sdk_registry_unavailable");
  }
  #fingerprint(value) {
    check(typeof value === "string" && value.length > 0, "trusted_refresh_sdk_token_missing");
    return crypto.createHmac("sha256", this.#fingerprintKey).update(value).digest("hex");
  }
  #canonical(provider, cfg) {
    check(typeof provider === "string" && provider.length > 0, "trusted_refresh_sdk_provider_missing");
    return this.resolveProviderIdForAuth(provider, { config: cfg });
  }
  isManagedOAuthProvider(provider, cfg) {
    this.#installed();
    return this.providers.has(this.#canonical(provider, cfg));
  }
  /** This is a query about configured custody, not an authorization grant. */
  isManagedOAuthScope(params) {
    this.#installed();
    return Boolean(this.owner(params));
  }
  #context(provider, refreshToken, cfg) {
    this.#installed();
    const context = this.#contexts.getStore();
    const canonical = this.#canonical(provider, context?.cfg ?? cfg);
    if (!this.providers.has(canonical)) {
      check(!context, "trusted_refresh_cross_provider_entry_denied");
      return null;
    }
    check(context && context.open && context.registry === this && context.provider === canonical,
      "trusted_refresh_sdk_context_required");
    check(this.#fingerprint(refreshToken) === context.refreshFingerprint,
      "trusted_refresh_sdk_credential_changed");
    return context;
  }
  /** Guard all observed refresh entry points, including public low-level APIs
   * that carry a credential but have no agent/profile owner with which to mint
   * a trusted request. Such callers cannot start a managed refresh themselves. */
  assertManagedRefreshEntry({ provider, credential, refreshToken, cfg } = {}) {
    this.oauthSdkObservations.entryChecks++;
    return Boolean(this.#context(provider, refreshToken ?? credential?.refresh, cfg));
  }
  /** The bootstrap loader records exact owned SDK function identities. A
   * custom registry/facade replacement cannot inherit that qualification. */
  assertQualifiedRefreshFunction(provider, callback) {
    this.#installed();
    const context = this.#contexts.getStore();
    const canonical = this.#canonical(provider, context?.cfg);
    if (!this.providers.has(canonical)) {
      check(!context, "trusted_refresh_cross_provider_function_denied");
      return false;
    }
    check(context && context.open && context.provider === canonical,
      "trusted_refresh_sdk_context_required");
    const qualifiedProvider = this.#qualification.providerOf(callback);
    check(typeof qualifiedProvider === "string" && this.#canonical(qualifiedProvider, context.cfg) === canonical,
      "trusted_refresh_sdk_function_not_qualified");
    return true;
  }
  /** Runs before the SDK manager can read/adopt main-store or external CLI
   * credentials. The only owner read/write functions are bootstrap bindings. */
  async resolveManagedOAuthAccess(params, adapter) {
    this.#installed();
    const scopeParams = { ...params, provider: params.credential?.provider };
    const authority = this.owner(scopeParams);
    if (!authority) return { managed: false };
    check(!this.#contexts.getStore(), "trusted_refresh_nested_owner_resolution_denied");
    check(adapter && typeof adapter.needsRefresh === "boolean" && typeof adapter.refreshCredential === "function" &&
      typeof adapter.buildApiKey === "function", "trusted_refresh_sdk_adapter_invalid");
    const store = this.readStore(authority.scope.agentDir);
    const original = store.profiles?.[params.profileId];
    const permit = this.decision({ ...scopeParams, agentDir: authority.scope.agentDir, store });
    check(original?.type === "oauth" && permit?.allowed && permit.profileId === params.profileId &&
      digest(original) === permit.credentialDigest && digest(params.credential) === permit.credentialDigest,
      "trusted_refresh_sdk_owner_admission_denied");
    this.oauthSdkObservations.managedResolutions++;
    let credential;
    if (!adapter.needsRefresh) {
      check(Number.isSafeInteger(original.expires) && original.expires > Date.now(),
        "trusted_refresh_sdk_expired_credential_denied");
      credential = structuredClone(original);
      this.oauthSdkObservations.usableResolutions++;
    } else {
      check(original.provider === authority.scope.provider, "trusted_refresh_sdk_provider_normalization_required");
      check(this.#qualification.supportedProviders().some(provider => this.#canonical(provider, params.cfg) === authority.scope.provider),
        "trusted_refresh_sdk_provider_not_qualified");
      const result = await super.refreshManagedOAuth({ ...scopeParams, agentDir: authority.scope.agentDir },
        async (boundCredential, dispatch) => {
          const context = { registry: this, provider: authority.scope.provider, cfg: params.cfg,
            credential: structuredClone(boundCredential), refreshFingerprint: this.#fingerprint(boundCredential.refresh),
            credentialDigest: digest(boundCredential), profileId: params.profileId, authority,
            closedRecordDigest: digest(authority._read()),
            dispatch, open: true };
          this.oauthSdkObservations.refreshContexts++;
          try {
            return await this.#contexts.run(context, async () => {
              const refreshed = await adapter.refreshCredential(boundCredential);
              return refreshed ? { ...boundCredential, ...refreshed, type: "oauth" } : null;
            });
          } finally { context.open = false; }
        });
      check(result.managed, "trusted_refresh_sdk_owner_lost");
      credential = result.credential;
    }
    const apiKey = await adapter.buildApiKey(credential);
    check(typeof apiKey === "string" && apiKey.length > 0, "trusted_refresh_sdk_api_key_invalid");
    // No positive delivery from a stale/changed store or a superseded epoch.
    // A successful refresh may cross only this registry's private successor.
    this.advanceAfterRefresh(scopeParams, permit, params.profileId, apiKey);
    return { managed: true, value: { apiKey, credential } };
  }
  /** The exact SDK fetch call invokes this synchronously immediately before
   * its transport. No await is allowed between dispatch() and send(). */
  dispatchManagedOAuthTransport({ provider, url, init, operation } = {}, send) {
    this.oauthSdkObservations.dispatchAttempts++;
    try {
      this.#installed();
      check(typeof send === "function", "trusted_refresh_sdk_transport_missing");
      const current = this.#contexts.getStore();
      const canonical = this.#canonical(provider, current?.cfg);
      if (!this.providers.has(canonical)) {
        check(!current, "trusted_refresh_cross_provider_transport_denied");
        this.oauthSdkObservations.unmanagedDispatches++;
        return send(url, init);
      }
      const context = current;
      check(context && context.open && context.registry === this && context.provider === canonical,
        "trusted_refresh_sdk_context_required");
      const parsed = new URL(url);
      check(parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
        (!parsed.port || parsed.port === "443"), "trusted_refresh_transport_origin_invalid");
      const method = String(init?.method ?? "GET").toUpperCase(), headers = new Headers(init?.headers);
      let fields, token;
      if (operation === "anthropic-token-refresh") {
        check(canonical === this.#canonical("anthropic", context.cfg) &&
          parsed.href === "https://platform.claude.com/v1/oauth/token" && method === "POST" &&
          headers.get("content-type") === "application/json", "trusted_refresh_transport_route_mismatch");
        fields = jsonFields(init?.body); token = fields.refresh_token;
        check(Object.keys(fields).every(key => ["grant_type", "client_id", "refresh_token"].includes(key)) &&
          typeof fields.client_id === "string" && fields.client_id.length > 0,
          "trusted_refresh_transport_fields_invalid");
      } else if (operation === "chutes-token-refresh") {
        check(canonical === this.#canonical("chutes", context.cfg) &&
          parsed.href === "https://api.chutes.ai/idp/token" && method === "POST" &&
          headers.get("content-type") === "application/x-www-form-urlencoded", "trusted_refresh_transport_route_mismatch");
        fields = formFields(init?.body); token = fields.refresh_token;
        check(Object.keys(fields).every(key => ["grant_type", "client_id", "client_secret", "refresh_token"].includes(key)) &&
          typeof context.credential.clientId === "string" && fields.client_id === context.credential.clientId.trim(),
          "trusted_refresh_transport_client_unbound");
        check(fields.client_secret === undefined || typeof context.credential.clientSecret === "string" &&
          fields.client_secret === context.credential.clientSecret,
          "trusted_refresh_transport_client_secret_unbound");
      } else if (operation === "github-copilot-token-refresh") {
        const domain = context.credential.enterpriseUrl || "github.com";
        check(typeof domain === "string" && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(domain) &&
          canonical === this.#canonical("github-copilot", context.cfg) &&
          parsed.href === `https://api.${domain}/copilot_internal/v2/token` && method === "GET" && !init?.body,
          "trusted_refresh_transport_route_mismatch");
        const match = /^Bearer (.+)$/.exec(headers.get("authorization") ?? "");
        check(match, "trusted_refresh_transport_authorization_missing"); token = match[1];
      } else fail("trusted_refresh_sdk_transport_not_qualified");
      if (fields) check(fields.grant_type === "refresh_token", "trusted_refresh_transport_grant_invalid");
      check(this.#fingerprint(token) === context.refreshFingerprint, "trusted_refresh_transport_credential_mismatch");
      // Redirects could otherwise replay the refresh secret without another
      // one-shot boundary. All managed token endpoints must answer directly.
      const constrained = { ...init, headers, redirect: "error" };
      check(digest(this.readStore(context.authority.scope.agentDir).profiles?.[context.profileId]) === context.credentialDigest,
        "trusted_refresh_sdk_changed_before_final_send");
      check(digest(context.authority._read()) === context.closedRecordDigest,
        "trusted_refresh_local_fence_changed_before_final_send");
      return context.dispatch(() => {
        check(context.open, "trusted_refresh_sdk_context_closed");
        this.#installed();
        this.oauthSdkObservations.allowedDispatches++;
        return send(parsed.href, constrained);
      });
    } catch (error) {
      this.oauthSdkObservations.deniedDispatches++;
      throw error;
    }
  }
}
