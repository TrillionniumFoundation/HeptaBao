/**
 * Scoped TLS/AppRole control transport and CAS coordinator candidate.
 * Only this module can mint an in-memory proof. JSON documents and verifier
 * callbacks cannot manufacture one. The bootstrap owns the pinned endpoint,
 * CA, roles, and control path; arbitrary in-process code is not a sandbox.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import { performance } from "node:perf_hooks";
import { digest } from "./authbus_admission_authority_candidate.mjs";

export const CONTROL_PROTOCOL = "heptabao-authbus-trusted-bootstrap-r5";
const MAX_BYTES = 2 * 1024 * 1024;
const SOURCE = new WeakMap(), PROOF = new WeakMap();
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const check = (condition, code) => { if (!condition) fail(code); };
const own = value => value !== null && typeof value === "object" && !Array.isArray(value);
const field = (value, name, max = 256) => {
  check(typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value), "trusted_control_invalid_" + name);
  return value;
};
const integer = (value, name, min = 0) => { check(Number.isSafeInteger(value) && value >= min, "trusted_control_invalid_" + name); return value; };
const freezeCopy = value => JSON.parse(JSON.stringify(value));
const grantFields = value => ({ epoch: value.epoch, status: value.status, mode: value.mode,
  profileId: value.status === "ASSIGNED" ? value.profileId : null,
  digest: value.status === "ASSIGNED" ? value.digest : null,
  leaseId: value.status === "ASSIGNED" ? value.leaseId : null,
  expiresAt: value.status === "ASSIGNED" ? value.expiresAt : 0, model: value.model });
const scopeFields = value => ({ hostId: field(value.hostId, "host"), agentId: field(value.agentId, "agent"),
  agentDir: path.resolve(field(value.agentDir, "agent_directory", 4096)), provider: field(value.provider, "provider", 128) });

export function readCustodiedFile(filename, { secret = true, maxBytes = 65536 } = {}) {
  check(path.isAbsolute(filename), "trusted_control_absolute_file_required");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    check(stat.isFile() && stat.uid === process.getuid() && (stat.mode & (secret ? 0o077 : 0o022)) === 0 &&
      stat.size > 0 && stat.size <= maxBytes, "trusted_control_file_custody_invalid");
    const bytes = fs.readFileSync(fd);
    check(bytes.length === stat.size && bytes.length <= maxBytes, "trusted_control_file_changed");
    return bytes;
  } finally { fs.closeSync(fd); }
}

function configOf(config, role) {
  check(own(config) && config.schemaVersion === 1 && own(config[role]), "trusted_control_config_invalid");
  const url = new URL(config.address);
  check(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && url.pathname === "/", "trusted_control_https_origin_required");
  const mount = field(config.kvMount, "mount"), key = field(config.controlPath, "control_path", 512);
  check(/^[A-Za-z0-9_-]+$/.test(mount) && key.split("/").every(part => /^[A-Za-z0-9_-]+$/.test(part)), "trusted_control_path_invalid");
  const ca = readCustodiedFile(config.caFile, { secret: false });
  const result = { origin: url.origin, ca, caSha256: crypto.createHash("sha256").update(ca).digest("hex"),
    kvMount: mount, controlPath: key, issuerId: field(config.issuerId, "issuer_id"),
    roleIdFile: field(config[role].roleIdFile, "role_id_file", 4096), secretIdFile: field(config[role].secretIdFile, "secret_id_file", 4096),
    maxLeaseMs: integer(config.maxLeaseMs ?? 30000, "max_lease_ms", 2000) };
  check(result.maxLeaseMs <= 300000, "trusted_control_max_lease_too_long");
  result.sourceDigest = digest({ origin: result.origin, caSha256: result.caSha256, kvMount: mount, controlPath: key, issuerId: result.issuerId, protocol: CONTROL_PROTOCOL });
  return result;
}

class BaoTransport {
  #config; #token = null; #tokenDeadline = 0; #lastServerDate = null;
  constructor(config, role) {
    this.#config = configOf(config, role);
    this.public = Object.freeze({ sourceDigest: this.#config.sourceDigest, origin: this.#config.origin,
      kvMount: this.#config.kvMount, controlPath: this.#config.controlPath, issuerId: this.#config.issuerId, maxLeaseMs: this.#config.maxLeaseMs });
    this.counts = { tlsVerified: 0, logins: 0, reads: 0, writes: 0, renewals: 0, revocations: 0, deniedWrites: 0 };
  }
  async #request(method, suffix, body, token = null) {
    const config = this.#config, startedMono = performance.now();
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    check(!payload || payload.length <= MAX_BYTES, "trusted_control_request_too_large");
    return await new Promise((resolve, reject) => {
      const rejectCode = code => reject(Object.assign(new Error(code), { diagnosticCode: code }));
      const request = https.request(new URL(suffix, config.origin), { method, ca: config.ca, rejectUnauthorized: true,
        agent: false, timeout: 10000, headers: { accept: "application/json", "cache-control": "no-cache, no-store",
          ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}), ...(token ? { "x-vault-token": token } : {}) } }, response => {
        if (!response.socket.authorized) { response.destroy(); rejectCode("trusted_control_tls_unverified"); return; }
        this.counts.tlsVerified += 1;
        const chunks = []; let length = 0;
        response.on("data", chunk => { length += chunk.length; if (length > MAX_BYTES) { response.destroy(); rejectCode("trusted_control_response_too_large"); } else chunks.push(chunk); });
        response.on("error", () => rejectCode("trusted_control_response_io_failed"));
        response.on("end", () => {
          try {
            const serverDate = Date.parse(response.headers.date ?? "");
            check(Number.isSafeInteger(serverDate) && serverDate > 0, "trusted_control_server_date_required");
            check(this.#lastServerDate === null || serverDate >= this.#lastServerDate, "trusted_control_server_clock_rollback");
            this.#lastServerDate = serverDate;
            let data = null;
            if (length > 0) { try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { fail("trusted_control_response_json_invalid"); } }
            resolve({ status: response.statusCode, data, serverDate, serverUpper: serverDate + 1000, startedMono, completedMono: performance.now() });
          } catch (error) { reject(error); }
        });
      });
      request.on("timeout", () => request.destroy());
      request.on("error", () => rejectCode("trusted_control_request_io_failed"));
      if (payload) request.write(payload); request.end();
    });
  }
  async #login() {
    const roleId = readCustodiedFile(this.#config.roleIdFile, { maxBytes: 4096 }).toString("utf8").trim();
    const secretId = readCustodiedFile(this.#config.secretIdFile, { maxBytes: 4096 }).toString("utf8").trim();
    check(roleId.length > 0 && secretId.length > 0, "trusted_control_empty_binding");
    const response = await this.#request("POST", "/v1/auth/approle/login", { role_id: roleId, secret_id: secretId });
    check(response.status === 200 && own(response.data?.auth), "trusted_control_approle_login_denied");
    this.#token = field(response.data.auth.client_token, "bearer", 4096);
    const duration = integer(response.data.auth.lease_duration, "token_duration", 1);
    this.#tokenDeadline = response.startedMono + duration * 1000;
    this.counts.logins += 1;
  }
  async #authorized(method, suffix, body) {
    if (!this.#token) await this.#login();
    check(performance.now() < this.#tokenDeadline, "trusted_control_token_expired");
    return this.#request(method, suffix, body, this.#token);
  }
  async read() {
    const response = await this.#authorized("GET", `/v1/${this.#config.kvMount}/data/${this.#config.controlPath}`);
    this.counts.reads += 1;
    if (response.status === 404) return { ...response, document: null, version: 0 };
    check(response.status === 200, "trusted_control_read_denied");
    check(own(response.data?.data?.data) && own(response.data?.data?.metadata), "trusted_control_kv2_response_invalid");
    const version = integer(response.data.data.metadata.version, "kv_version", 1);
    check(version < 1e12 && !response.data.data.metadata.destroyed && !response.data.data.metadata.deletion_time, "trusted_control_kv2_not_live");
    return { ...response, document: response.data.data.data, version };
  }
  async cas(document, version) {
    const response = await this.#authorized("POST", `/v1/${this.#config.kvMount}/data/${this.#config.controlPath}`, { options: { cas: version }, data: document });
    this.counts.writes += 1;
    if (response.status === 400 || response.status === 409) fail("trusted_control_cas_conflict");
    check(response.status === 200, "trusted_control_write_denied");
    check(response.data?.data?.version === version + 1, "trusted_control_cas_version_invalid");
    return { version: response.data.data.version, serverUpper: response.serverUpper };
  }
  async probeWriteDenial() {
    // Impossible current version ensures even a misconfigured writer cannot
    // mutate the document during this permission probe.
    const response = await this.#authorized("POST", `/v1/${this.#config.kvMount}/data/${this.#config.controlPath}`,
      { options: { cas: Number.MAX_SAFE_INTEGER }, data: { permissionProbe: CONTROL_PROTOCOL } });
    check(response.status === 403, "trusted_control_reader_write_permission_present");
    this.counts.deniedWrites += 1; return true;
  }
  async renew() {
    const response = await this.#authorized("POST", "/v1/auth/token/renew-self", { increment: 60 });
    check(response.status === 200 && response.data?.auth?.client_token === this.#token,
      "trusted_control_token_renewal_failed");
    this.#tokenDeadline = response.startedMono + integer(response.data.auth.lease_duration, "renew_duration", 1) * 1000;
    this.counts.renewals += 1; return true;
  }
  async close() {
    if (!this.#token) return { revoked: false, coldDenied: false };
    const token = this.#token; this.#token = null;
    const revoked = await this.#request("POST", "/v1/auth/token/revoke-self", {}, token);
    check([200, 204].includes(revoked.status), "trusted_control_token_revocation_failed");
    const cold = await this.#request("GET", "/v1/auth/token/lookup-self", undefined, token);
    check(cold.status === 403, "trusted_control_revoked_token_reaccepted");
    this.counts.revocations += 1; return { revoked: true, coldDenied: true };
  }
}

function validateDocument(document, source) {
  check(own(document) && document.schemaVersion === 1 && document.protocol === CONTROL_PROTOCOL &&
    document.issuerId === source.issuerId && document.sourceDigest === source.sourceDigest,
  "trusted_control_document_provenance_invalid");
  integer(document.generation, "generation", 1);
  check(Array.isArray(document.scopes) && Array.isArray(document.assignments) && Array.isArray(document.refreshLeases) &&
    document.scopes.length <= 256 && document.assignments.length <= 256 && document.refreshLeases.length <= 256 &&
    Array.isArray(document.refreshAttempts) && document.refreshAttempts.length <= 256,
  "trusted_control_document_shape_invalid");
  return document;
}

export class TrustedBaoControlSource {
  constructor(config) {
    const transport = new BaoTransport(config, "reader");
    const data = { transport, bootId: crypto.randomUUID(), refreshBusy: false };
    SOURCE.set(this, data);
    Object.defineProperty(this, "identity", { value: Object.freeze({ ...transport.public, bootId: data.bootId }), enumerable: true });
    Object.freeze(this);
  }
  bootstrapRequest(scope, { model, profileId, credentialDigest }) {
    check(path.isAbsolute(scope?.agentDir ?? ""), "trusted_control_absolute_scope_required");
    check(/^[a-f0-9]{64}$/.test(credentialDigest), "trusted_control_credential_digest_invalid");
    return Object.freeze({ protocol: CONTROL_PROTOCOL, sourceDigest: this.identity.sourceDigest, bootId: this.identity.bootId,
      scope: Object.freeze(scopeFields(scope)), model: field(model, "model"), profileId: field(profileId, "profile"), credentialDigest });
  }
  async readGrant(scope) {
    const state = SOURCE.get(this), response = await state.transport.read();
    const document = validateDocument(response.document, this.identity), normalizedScope = scopeFields(scope);
    const matches = document.assignments.filter(item => item.hostId === normalizedScope.hostId && item.agentId === normalizedScope.agentId && item.provider === normalizedScope.provider);
    check(matches.length === 1, "trusted_control_assignment_ambiguous");
    const assignment = matches[0];
    check(assignment.scopeDigest === digest(normalizedScope) && assignment.bootId === state.bootId &&
      assignment.mode === "enforce" && assignment.status === "ASSIGNED" && Number.isSafeInteger(assignment.epoch) &&
      assignment.epoch > 0 && assignment.epoch <= document.generation &&
      Number.isSafeInteger(assignment.expiresAt) && typeof assignment.digest === "string" && /^[a-f0-9]{64}$/.test(assignment.digest),
    "trusted_control_bootstrap_assignment_mismatch");
    field(assignment.model, "model"); field(assignment.profileId, "profile"); field(assignment.leaseId, "lease_id");
    check(document.scopes.some(item => item.hostId === normalizedScope.hostId && item.provider === normalizedScope.provider &&
      item.model === assignment.model && item.strict === true && item.agentIds?.includes(normalizedScope.agentId)), "trusted_control_scope_not_enforced");
    const owners = document.refreshLeases.filter(item => item.provider === normalizedScope.provider && item.profileId === assignment.profileId);
    check(owners.length === 1, "trusted_control_refresh_owner_ambiguous");
    const owner = owners[0];
    check(owner.holderHost === normalizedScope.hostId && owner.bootId === state.bootId && owner.digest === assignment.digest &&
      owner.leaseId === assignment.leaseId && owner.epoch === assignment.epoch && owner.expiresAt === assignment.expiresAt,
    "trusted_control_refresh_owner_mismatch");
    const remaining = Math.min(this.identity.maxLeaseMs, assignment.expiresAt - response.serverUpper);
    const deadlineMono = response.startedMono + remaining;
    check(remaining > 0 && performance.now() < deadlineMono, "trusted_control_lease_expired");
    const grant = Object.freeze(grantFields(assignment)), proof = Object.freeze({});
    PROOF.set(proof, { source: this, scopeDigest: digest(normalizedScope), grantDigest: digest(grant),
      bootId: state.bootId, version: response.version, epoch: grant.epoch, deadlineMono,
      serverUpper: response.serverUpper, startedMono: response.startedMono, used: false,
      sourceDigest: this.identity.sourceDigest, refreshOwnerBound: true });
    return { grant, proof, public: { epoch: grant.epoch, version: response.version, bootId: state.bootId,
      sourceDigest: this.identity.sourceDigest, refreshOwnerBound: true, conservativeRemainingMs: Math.max(0, Math.floor(deadlineMono - performance.now())) } };
  }
  async probeWriteDenial() { return SOURCE.get(this).transport.probeWriteDenial(); }
  async renew() { return SOURCE.get(this).transport.renew(); }
  async close() { return SOURCE.get(this).transport.close(); }
  publicCounts() { return { ...SOURCE.get(this).transport.counts }; }
}

/** Check-and-consume; there is deliberately no public proof issuer. */
export function consumeTrustedProof(source, proof, scope, grant) {
  const state = SOURCE.get(source), value = PROOF.get(proof);
  check(state && value && value.source === source && !value.used, "trusted_control_fresh_proof_required");
  check(value.scopeDigest === digest(scopeFields(scope)) && value.grantDigest === digest(grantFields(grant)), "trusted_control_proof_binding_mismatch");
  check(performance.now() < value.deadlineMono, "trusted_control_proof_expired");
  value.used = true;
  return Object.freeze({ ...value, source: undefined, used: undefined });
}

/** A distinct AppRole performs the actual control-document compare-and-set. */
export class TrustedBaoCoordinator {
  #transport; #bindings;
  constructor(config, { bindings }) {
    check(Array.isArray(bindings) && bindings.length > 0 && bindings.length <= 256, "trusted_control_issuer_bindings_required");
    this.#bindings = bindings.map(binding => ({ scope: scopeFields(binding.scope), model: field(binding.model, "model"),
      profileId: field(binding.profileId, "profile"), credentialDigest: field(binding.credentialDigest, "credential_digest") }));
    this.#transport = new BaoTransport(config, "issuer"); this.identity = this.#transport.public;
  }
  async issue(request, { leaseMs = 5000, epochFloor = -1 } = {}) {
    check(own(request) && request.protocol === CONTROL_PROTOCOL && request.sourceDigest === this.identity.sourceDigest,
      "trusted_control_bootstrap_request_source_mismatch");
    field(request.bootId, "bootstrap_id"); field(request.model, "model"); field(request.profileId, "profile");
    const scope = scopeFields(request.scope);
    check(/^[a-f0-9]{64}$/.test(request.credentialDigest), "trusted_control_credential_digest_invalid");
    check(this.#bindings.some(binding => digest(binding.scope) === digest(scope) && binding.model === request.model &&
      binding.profileId === request.profileId && binding.credentialDigest === request.credentialDigest), "trusted_control_issuer_scope_not_authorized");
    integer(leaseMs, "lease_ms", 2000); check(leaseMs <= this.identity.maxLeaseMs, "trusted_control_lease_too_long");
    integer(epochFloor, "epoch_floor", -1);
    const response = await this.#transport.read();
    let document = response.document ? freezeCopy(validateDocument(response.document, this.identity)) : {
      schemaVersion: 1, protocol: CONTROL_PROTOCOL, issuerId: this.identity.issuerId, sourceDigest: this.identity.sourceDigest,
      generation: 0, scopes: [], assignments: [], refreshLeases: [], refreshAttempts: [] };
    const owners = document.refreshLeases.filter(item => item.provider === scope.provider && item.profileId === request.profileId);
    check(owners.length <= 1, "trusted_control_refresh_owner_ambiguous");
    const attempts = document.refreshAttempts.filter(item => item.provider === scope.provider && item.profileId === request.profileId);
    check(attempts.length <= 1, "trusted_refresh_attempt_ambiguous");
    if (attempts.length) {
      check(attempts[0].status === "PUBLISHED", "trusted_refresh_outcome_unknown");
      check(attempts[0].publishedDigest === request.credentialDigest, "trusted_refresh_old_credential_fenced");
    }
    const previousOwner = owners[0];
    // A different process/host cannot preempt an unexpired refresh owner. Use
    // Date's lower bound here (opposite to admission's conservative upper bound).
    check(!previousOwner || previousOwner.expiresAt <= response.serverDate ||
      previousOwner.bootId === request.bootId && previousOwner.holderHost === scope.hostId && previousOwner.digest === request.credentialDigest,
    "trusted_control_refresh_owner_busy");
    const epoch = Math.max(document.generation, epochFloor,
      ...document.assignments.map(item => integer(item.epoch, "stored_assignment_epoch")),
      ...document.refreshLeases.map(item => integer(item.epoch, "stored_refresh_epoch"))) + 1;
    check(Number.isSafeInteger(epoch), "trusted_control_epoch_exhausted");
    const expiresAt = response.serverDate + leaseMs, leaseId = crypto.randomUUID();
    const assignment = { ...scope, scopeDigest: digest(scope), bootId: request.bootId, provider: scope.provider, model: request.model,
      epoch, status: "ASSIGNED", mode: "enforce", profileId: request.profileId, digest: request.credentialDigest, leaseId, expiresAt };
    delete assignment.agentDir;
    document.assignments = document.assignments.filter(item => !(item.hostId === scope.hostId && item.agentId === scope.agentId && item.provider === scope.provider));
    document.assignments.push(assignment);
    document.refreshLeases = document.refreshLeases.filter(item => !(item.provider === scope.provider && item.profileId === request.profileId));
    document.refreshLeases.push({ provider: scope.provider, profileId: request.profileId, digest: request.credentialDigest,
      holderHost: scope.hostId, bootId: request.bootId, epoch, leaseId, expiresAt });
    const previousScopes = document.scopes.filter(item => item.hostId === scope.hostId && item.provider === scope.provider && item.model === request.model);
    document.scopes = document.scopes.filter(item => !(item.hostId === scope.hostId && item.provider === scope.provider && item.model === request.model));
    document.scopes.push({ hostId: scope.hostId, provider: scope.provider, model: request.model,
      agentIds: [...new Set([...previousScopes.flatMap(item => item.agentIds ?? []), scope.agentId])], strict: true,
      managedProfileIds: [...new Set([...previousScopes.flatMap(item => item.managedProfileIds ?? []), request.profileId])] });
    document.generation = epoch;
    const committed = await this.#transport.cas(document, response.version);
    return { grant: grantFields(assignment), version: committed.version, bootId: request.bootId,
      sourceDigest: this.identity.sourceDigest, refreshOwnerBound: true };
  }
  /**
   * The caller must be the configured SDK credential owner. All callbacks are
   * bootstrap-owned adapter functions, never supplied by provider responses.
   * No code here retries a provider request. Even a failed/ambiguous CAS leaves
   * I/O unsent; every failure after committed intent retains UNKNOWN forever.
   */
  async refreshOnce(request, { readCredential, refreshCredential, writeCredential, closeAdmission }) {
    check(own(request) && request.protocol === CONTROL_PROTOCOL && request.sourceDigest === this.identity.sourceDigest,
      "trusted_control_bootstrap_request_source_mismatch");
    check([readCredential, refreshCredential, writeCredential, closeAdmission].every(value => typeof value === "function"),
      "trusted_refresh_sdk_adapter_required");
    const scope = scopeFields(request.scope);
    field(request.bootId, "bootstrap_id"); field(request.profileId, "profile");
    check(this.#bindings.some(binding => digest(binding.scope) === digest(scope) && binding.model === request.model &&
      binding.profileId === request.profileId && binding.credentialDigest === request.credentialDigest),
      "trusted_control_issuer_scope_not_authorized");
    const original = await readCredential();
    check(own(original) && original.type === "oauth" && original.provider === scope.provider &&
      digest(original) === request.credentialDigest, "trusted_refresh_sdk_credential_mismatch");
    // This fsync-backed negative admission publication precedes remote intent.
    // If it throws, no CAS and no refresh provider I/O have occurred.
    check(closeAdmission() === true, "trusted_refresh_admission_close_failed");
    const response = await this.#transport.read();
    const document = freezeCopy(validateDocument(response.document, this.identity));
    const matches = document.assignments.filter(item => item.hostId === scope.hostId && item.agentId === scope.agentId && item.provider === scope.provider);
    check(matches.length === 1, "trusted_control_assignment_ambiguous");
    const assignment = matches[0];
    check(assignment.scopeDigest === digest(scope) && assignment.bootId === request.bootId && assignment.status === "ASSIGNED" &&
      assignment.profileId === request.profileId && assignment.digest === request.credentialDigest && assignment.model === request.model,
      "trusted_refresh_assignment_changed");
    const owners = document.refreshLeases.filter(item => item.provider === scope.provider && item.profileId === request.profileId);
    check(owners.length === 1 && owners[0].holderHost === scope.hostId && owners[0].bootId === request.bootId &&
      owners[0].digest === request.credentialDigest && owners[0].epoch === assignment.epoch &&
      owners[0].leaseId === assignment.leaseId && owners[0].expiresAt === assignment.expiresAt,
      "trusted_control_refresh_owner_mismatch");
    const remaining = Math.min(this.identity.maxLeaseMs, assignment.expiresAt - response.serverUpper);
    const deadlineMono = response.startedMono + remaining;
    check(remaining > 0 && performance.now() < deadlineMono, "trusted_control_lease_expired");
    const previous = document.refreshAttempts.filter(item => item.provider === scope.provider && item.profileId === request.profileId);
    check(previous.length <= 1, "trusted_refresh_attempt_ambiguous");
    if (previous.length) {
      check(previous[0].status === "PUBLISHED", "trusted_refresh_outcome_unknown");
      check(previous[0].publishedDigest === request.credentialDigest, "trusted_refresh_old_credential_fenced");
    }
    const epoch = Math.max(document.generation, ...document.assignments.map(item => integer(item.epoch, "stored_assignment_epoch")),
      ...document.refreshLeases.map(item => integer(item.epoch, "stored_refresh_epoch"))) + 1;
    check(Number.isSafeInteger(epoch), "trusted_control_epoch_exhausted");
    const attempt = { provider: scope.provider, profileId: request.profileId, attemptId: crypto.randomUUID(),
      holderHost: scope.hostId, bootId: request.bootId, credentialDigest: request.credentialDigest,
      scopeDigest: digest(scope), sourceEpoch: assignment.epoch, fenceEpoch: epoch, status: "UNKNOWN",
      startedAt: response.serverDate, parentAttemptId: previous[0]?.attemptId ?? null };
    document.refreshAttempts = document.refreshAttempts.filter(item => !(item.provider === scope.provider && item.profileId === request.profileId));
    document.refreshAttempts.push(attempt);
    for (const item of document.assignments) if (item.provider === scope.provider && item.profileId === request.profileId) {
      item.status = "REFRESH_PENDING"; item.epoch = epoch;
    }
    document.generation = epoch;
    // A lost response is not success. A new owner must inspect the persistent
    // attempt, and is forbidden to infer that lease expiry permits a retry.
    const intent = await this.#transport.cas(document, response.version);
    check(performance.now() < deadlineMono, "trusted_refresh_dispatch_deadline_expired");
    check(digest(await readCredential()) === request.credentialDigest, "trusted_refresh_sdk_changed_before_dispatch");
    check(performance.now() < deadlineMono, "trusted_refresh_dispatch_deadline_expired");
    // Single call, with UNKNOWN already durably acknowledged. Provider errors,
    // socket losses and process death never enter a retry/finally-clear path.
    let dispatchOpen = true, dispatches = 0;
    const dispatch = send => {
      check(dispatchOpen && dispatches === 0, "trusted_refresh_dispatch_already_consumed");
      check(typeof send === "function", "trusted_refresh_transport_callback_required");
      check(performance.now() < deadlineMono, "trusted_refresh_dispatch_deadline_expired");
      dispatches += 1;
      return send();
    };
    let refreshed;
    try { refreshed = await refreshCredential(freezeCopy(original), dispatch); }
    finally { dispatchOpen = false; }
    check(dispatches === 1, "trusted_refresh_final_dispatch_not_observed");
    check(own(refreshed) && refreshed.type === "oauth" && refreshed.provider === scope.provider &&
      typeof refreshed.access === "string" && refreshed.access.length > 0 &&
      typeof refreshed.refresh === "string" && refreshed.refresh.length > 0 &&
      Number.isSafeInteger(refreshed.expires) &&
      refreshed.expires > response.serverUpper + Math.max(0, performance.now() - response.startedMono),
      "trusted_refresh_provider_result_invalid");
    const publishedDigest = digest(refreshed);
    check(publishedDigest !== request.credentialDigest, "trusted_refresh_unchanged_credential");
    check(await writeCredential(freezeCopy(refreshed)) === true, "trusted_refresh_sdk_write_failed");
    check(digest(await readCredential()) === publishedDigest, "trusted_refresh_sdk_publication_not_verified");
    const completion = await this.#transport.read();
    const current = freezeCopy(validateDocument(completion.document, this.identity));
    const active = current.refreshAttempts.filter(item => item.provider === scope.provider && item.profileId === request.profileId);
    check(active.length === 1 && digest(active[0]) === digest(attempt), "trusted_refresh_attempt_changed");
    const publishedEpoch = Math.max(current.generation, attempt.fenceEpoch) + 1;
    check(Number.isSafeInteger(publishedEpoch), "trusted_control_epoch_exhausted");
    active[0].status = "PUBLISHED"; active[0].publishedDigest = publishedDigest;
    active[0].publishedEpoch = publishedEpoch; active[0].sdkVerified = true;
    current.refreshLeases = current.refreshLeases.filter(item => !(item.provider === scope.provider && item.profileId === request.profileId));
    current.generation = publishedEpoch;
    const committed = await this.#transport.cas(current, completion.version);
    // Authorization still needs a fresh trusted grant. Updating the binding is
    // permitted only after provider result -> actual SDK write/read -> CAS.
    this.#bindings = this.#bindings.map(binding => binding.scope.provider === scope.provider &&
      binding.profileId === request.profileId && binding.credentialDigest === request.credentialDigest
      ? { ...binding, credentialDigest: publishedDigest } : binding);
    return Object.freeze({ attemptId: attempt.attemptId, fenceEpoch: epoch, publishedEpoch,
      intentVersion: intent.version, publishedVersion: committed.version, credentialDigest: publishedDigest, sdkVerified: true });
  }
  async renew() { return this.#transport.renew(); }
  async close() { return this.#transport.close(); }
  publicCounts() { return { ...this.#transport.counts }; }
}
