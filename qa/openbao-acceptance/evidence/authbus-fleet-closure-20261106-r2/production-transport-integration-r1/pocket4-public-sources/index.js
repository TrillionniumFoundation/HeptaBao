import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  clearRuntimeAuthProfileStoreSnapshots,
  loadAuthProfileStoreWithoutExternalProfiles,
  refreshOAuthCredentialForRuntime,
  resolveProviderIdForAuth,
  saveAuthProfileStore,
  setAuthProfileOrder,
  upsertAuthProfileWithLock,
} from "openclaw/plugin-sdk/agent-runtime";

import {
  mergeManagedOrder,
  normalizeOrderPolicy,
  resolveScheduledAssignments,
  schedulerReportProfileRequirements,
  sameOrder,
} from "./order-policy.js";
import { expectedCredentialDigest, selectPendingRuntimeRefreshes } from "./runtime-refresh-policy.js";
import { retireSharedCodexAppServerClients } from "./codex-client-recycler.js";
import { hasRefreshLease, leaseAssignmentForAgent, normalizeLeaseAssignments } from "./lease-assignments.js";
import {
  classifyProviderFailure,
  lifecycleAgentId,
  lifecycleErrorText,
  lifecycleModel,
  selectRecentlyFailedProfile,
} from "./provider-error-classifier.js";
import {
  classifyPermanentRefreshFailure,
  isDigestQuarantined,
  reconcileQuarantineWithManifest,
  removeProfileAndReferences,
  selectRecentlyFailedOAuthProfile,
} from "./bad-refresh-quarantine.js";

const PLUGIN_ID = "openclaw-authbus";
const KV_MOUNT = "openclaw-auth";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stableValue(value[key])]),
  );
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function credentialDigest(credential) {
  return sha256(stableStringify(credential));
}

function identityDigest(credential) {
  return sha256(
    stableStringify({
      provider: credential.provider ?? null,
      type: credential.type ?? null,
      email: credential.email ?? null,
      accountId: credential.accountId ?? null,
      projectId: credential.projectId ?? null,
    }),
  );
}

function profileLogId(profileId) {
  return sha256(profileId).slice(0, 10);
}

function validCredential(profileId, credential) {
  if (typeof profileId !== "string" || profileId.length < 1 || profileId.length > 240) return false;
  if (!isRecord(credential)) return false;
  if (typeof credential.provider !== "string" || credential.provider.length > 100) return false;
  if (!["oauth", "token", "api_key"].includes(credential.type)) return false;
  if (credential.type === "oauth") {
    if (typeof credential.access !== "string" || credential.access.length < 8) return false;
    if (typeof credential.refresh !== "string" || credential.refresh.length < 8) return false;
    if (!Number.isFinite(credential.expires) || credential.expires < 1) return false;
  }
  if (credential.type === "api_key") {
    if (typeof credential.key !== "string" || credential.key.length < 8 || credential.keyRef !== undefined) return false;
  }
  if (credential.type === "token") {
    if (typeof credential.token !== "string" || credential.token.length < 8 || credential.tokenRef !== undefined) return false;
  }
  return Buffer.byteLength(stableStringify(credential), "utf8") <= 128 * 1024;
}

class BaoClient {
  constructor(config) {
    this.base = new URL(config.address);
    this.ca = fs.readFileSync(config.caFile);
    this.roleIdFile = config.roleIdFile;
    this.secretIdFile = config.secretIdFile;
    this.token = null;
    this.tokenExpiresAt = 0;
  }

  async request(method, requestPath, body, token = this.token) {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const options = {
      protocol: this.base.protocol,
      hostname: this.base.hostname,
      port: this.base.port || 443,
      path: requestPath,
      method,
      ca: this.ca,
      rejectUnauthorized: true,
      timeout: 15000,
      headers: {
        Accept: "application/json",
      },
    };
    if (payload) {
      options.headers["Content-Type"] = "application/json";
      options.headers["Content-Length"] = String(payload.length);
    }
    if (token) options.headers["X-Vault-Token"] = token;

    return await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let parsed = null;
          if (raw) {
            try {
              parsed = JSON.parse(raw);
            } catch {
              return reject(new Error(`OpenBao returned non-JSON status ${res.statusCode}`));
            }
          }
          if (res.statusCode === 404) return resolve(null);
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`OpenBao request failed with status ${res.statusCode}`));
          }
          resolve(parsed);
        });
      });
      req.on("timeout", () => req.destroy(new Error("OpenBao request timed out")));
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async login() {
    if (this.token && Date.now() < this.tokenExpiresAt - 60_000) return;
    const roleId = fs.readFileSync(this.roleIdFile, "utf8").trim();
    const secretId = fs.readFileSync(this.secretIdFile, "utf8").trim();
    const result = await this.request("POST", "/v1/auth/approle/login", {
      role_id: roleId,
      secret_id: secretId,
    }, null);
    const token = result?.auth?.client_token;
    if (typeof token !== "string" || token.length < 8) throw new Error("OpenBao AppRole login returned no token");
    const leaseSeconds = Number(result?.auth?.lease_duration) || 3600;
    this.token = token;
    this.tokenExpiresAt = Date.now() + leaseSeconds * 1000;
  }

  async readSecret(secretPath) {
    await this.login();
    const result = await this.request("GET", `/v1/${KV_MOUNT}/data/${secretPath}`);
    if (!result) return null;
    return {
      data: result?.data?.data ?? null,
      version: Number(result?.data?.metadata?.version) || 0,
    };
  }

  async writeInbox(hostId, eventId, event) {
    await this.login();
    await this.request(
      "POST",
      `/v1/${KV_MOUNT}/data/inbox/${encodeURIComponent(hostId)}/${encodeURIComponent(eventId)}`,
      { data: event, options: { cas: 0 } },
    );
  }
}

function discoverAgentDirs(stateDir) {
  const root = path.join(stateDir, "agents");
  let entries = [];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(root, entry.name, "agent"))
    .filter((agentDir) => fs.existsSync(path.join(agentDir, "openclaw-agent.sqlite")));
}

function writeStatus(stateDir, status) {
  const dir = path.join(stateDir, "authbus");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = path.join(dir, "status.json");
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, target);
}

function authBusStatePath(stateDir, name) {
  return path.join(stateDir, "authbus", name);
}

function readDigestMap(stateDir, name) {
  try {
    const parsed = JSON.parse(fs.readFileSync(authBusStatePath(stateDir, name), "utf8"));
    if (!isRecord(parsed.profiles)) return new Map();
    return new Map(
      Object.entries(parsed.profiles).filter(
        ([profileId, profileDigest]) => typeof profileId === "string" && typeof profileDigest === "string",
      ),
    );
  } catch {
    return new Map();
  }
}

function writeDigestMap(stateDir, name, profiles) {
  const dir = path.join(stateDir, "authbus");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = authBusStatePath(stateDir, name);
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(
    temporary,
    `${JSON.stringify({ schemaVersion: 1, updatedAt: Date.now(), profiles: Object.fromEntries(profiles) }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.renameSync(temporary, target);
}

function readRefreshBackoff(stateDir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(authBusStatePath(stateDir, "refresh-backoff.json"), "utf8"));
    if (!isRecord(parsed.profiles)) return new Map();
    return new Map(
      Object.entries(parsed.profiles).filter(([, value]) =>
        isRecord(value) &&
        typeof value.digest === "string" &&
        Number.isFinite(value.failures) &&
        Number.isFinite(value.nextAttemptAt),
      ),
    );
  } catch {
    return new Map();
  }
}

function writeRefreshBackoff(stateDir, profiles) {
  const dir = path.join(stateDir, "authbus");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = authBusStatePath(stateDir, "refresh-backoff.json");
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(
    temporary,
    `${JSON.stringify({ schemaVersion: 1, updatedAt: Date.now(), profiles: Object.fromEntries(profiles) }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.renameSync(temporary, target);
}

function readBadRefreshQuarantine(stateDir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(authBusStatePath(stateDir, "bad-refresh-quarantine.json"), "utf8"));
    if (!isRecord(parsed.profiles)) return new Map();
    return new Map(
      Object.entries(parsed.profiles).filter(([, value]) =>
        isRecord(value) && typeof value.digest === "string" && typeof value.provider === "string" &&
        typeof value.reason === "string" && Number.isFinite(value.firstDetectedAt) && Number.isFinite(value.lastDetectedAt),
      ),
    );
  } catch {
    return new Map();
  }
}

function writeBadRefreshQuarantine(stateDir, profiles) {
  const dir = path.join(stateDir, "authbus");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = authBusStatePath(stateDir, "bad-refresh-quarantine.json");
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(
    temporary,
    `${JSON.stringify({ schemaVersion: 1, updatedAt: Date.now(), profiles: Object.fromEntries(profiles) }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.renameSync(temporary, target);
}

function readLeaseEpochs(stateDir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(authBusStatePath(stateDir, "lease-epochs.json"), "utf8"));
    if (!isRecord(parsed.entries)) return new Map();
    return new Map(
      Object.entries(parsed.entries).filter(([, value]) =>
        isRecord(value) && Number.isFinite(value.epoch) && typeof value.status === "string",
      ),
    );
  } catch {
    return new Map();
  }
}

function writeLeaseEpochs(stateDir, entries) {
  const dir = path.join(stateDir, "authbus");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = authBusStatePath(stateDir, "lease-epochs.json");
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(
    temporary,
    `${JSON.stringify({ schemaVersion: 1, updatedAt: Date.now(), entries: Object.fromEntries(entries) }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.renameSync(temporary, target);
}

function purgeBadRefreshCredentials(agentDirs, quarantine) {
  let changedStores = 0;
  let removedCredentials = 0;
  const orderedAgentDirs = [...agentDirs].sort((left, right) => {
    const leftMain = path.basename(path.dirname(left)) === "main" ? 0 : 1;
    const rightMain = path.basename(path.dirname(right)) === "main" ? 0 : 1;
    return leftMain - rightMain;
  });
  for (const agentDir of orderedAgentDirs) {
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    let changed = false;
    const pruneOrderProfileIds = [];
    for (const [profileId, entry] of quarantine) {
      const credential = store.profiles?.[profileId];
      if (credential && credentialDigest(credential) !== entry.digest) continue;
      pruneOrderProfileIds.push(profileId);
      if (credential) removedCredentials += 1;
      if (removeProfileAndReferences(store, profileId)) changed = true;
    }
    if (!changed) continue;
    saveAuthProfileStore(store, agentDir, {
      filterExternalAuthProfiles: false,
      syncExternalCli: false,
      pruneOrderProfileIds,
    });
    changedStores += 1;
  }
  for (const agentDir of orderedAgentDirs) {
    const reloaded = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    for (const [profileId, entry] of quarantine) {
      const credential = reloaded.profiles?.[profileId];
      if (credential && credentialDigest(credential) === entry.digest) {
        throw new Error(`AuthBus failed to purge quarantined credential from agent ${path.basename(path.dirname(agentDir))}`);
      }
    }
  }
  return { changedStores, removedCredentials };
}

function loadOrCreatePublishBaseline(stateDir, localProfiles, manifestById) {
  const target = authBusStatePath(stateDir, "publish-baseline.json");
  if (fs.existsSync(target)) return readDigestMap(stateDir, "publish-baseline.json");
  const baseline = new Map();
  for (const candidate of localProfiles.values()) {
    if (!manifestById.has(candidate.profileId)) baseline.set(candidate.profileId, candidate.digest);
  }
  writeDigestMap(stateDir, "publish-baseline.json", baseline);
  return baseline;
}

async function updateEveryAgent(agentDirs, profileId, credential, digest) {
  let changed = 0;
  for (const agentDir of agentDirs) {
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    const existing = store.profiles?.[profileId];
    if (existing && credentialDigest(existing) === digest) continue;
    const result = await upsertAuthProfileWithLock({
      agentDir,
      profileId,
      credential: structuredClone(credential),
    });
    if (!result) throw new Error(`Auth-store transaction failed for agent ${path.basename(path.dirname(agentDir))}`);
    changed += 1;
  }
  return changed;
}

function selectLocalProfiles(agentDirs) {
  const grouped = new Map();
  for (const agentDir of agentDirs) {
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    for (const [profileId, credential] of Object.entries(store.profiles ?? {})) {
      if (!validCredential(profileId, credential)) continue;
      const digest = credentialDigest(credential);
      const identity = identityDigest(credential);
      const candidate = { profileId, credential, digest, identity };
      const existing = grouped.get(profileId);
      if (!existing || (Number(candidate.credential.expires) || 0) > (Number(existing.credential.expires) || 0)) {
        grouped.set(profileId, candidate);
      }
    }
  }
  return grouped;
}

function verifyEffectiveStores(agentDirs, manifestProfiles, pendingRuntimeRefreshes = new Map(), badRefreshQuarantine = new Map()) {
  let missing = 0;
  let mismatched = 0;
  for (const agentDir of agentDirs) {
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    for (const entry of manifestProfiles) {
      const expectedDigest = expectedCredentialDigest(entry, pendingRuntimeRefreshes);
      if (isDigestQuarantined(badRefreshQuarantine, entry.profileId, expectedDigest)) continue;
      const credential = store.profiles?.[entry.profileId];
      if (!credential) {
        missing += 1;
        continue;
      }
      if (credentialDigest(credential) !== expectedDigest) mismatched += 1;
    }
  }
  if (missing > 0 || mismatched > 0) {
    throw new Error(`Effective auth verification failed: missing=${missing}, mismatched=${mismatched}`);
  }
  return { verifiedStores: agentDirs.length, missing, mismatched };
}

function findProviderKey(container, provider) {
  const providerKey = resolveProviderIdForAuth(provider);
  return Object.keys(container ?? {}).find((key) => resolveProviderIdForAuth(key) === providerKey) ?? null;
}

function findProviderOrder(store, provider) {
  const orderKey = findProviderKey(store.order, provider);
  return orderKey ? store.order[orderKey] : [];
}

function findProviderLastGood(store, provider) {
  const lastGoodKey = findProviderKey(store.lastGood, provider);
  return lastGoodKey ? store.lastGood[lastGoodKey] : null;
}

function uniqueProfileIds(values) {
  return [...new Set(values.filter((profileId) => typeof profileId === "string" && profileId.trim()).map((profileId) => profileId.trim()))];
}

function credentialMatchesProvider(credential, provider) {
  return isRecord(credential) && typeof credential.provider === "string" &&
    resolveProviderIdForAuth(credential.provider) === resolveProviderIdForAuth(provider);
}

function resolveManagedProviderState(store, provider, providerPolicy) {
  const candidates = providerPolicy.candidates
    .map((candidate) => candidate.profileId)
    .filter((profileId) => credentialMatchesProvider(store.profiles?.[profileId], provider));
  const activeProfile = providerPolicy.activeProfile &&
    credentialMatchesProvider(store.profiles?.[providerPolicy.activeProfile], provider)
    ? providerPolicy.activeProfile
    : null;
  return { candidates, activeProfile };
}

async function saveManagedOrder(agentDir, provider, store, next) {
  let reloaded = store;
  if (!sameOrder(findProviderOrder(reloaded, provider), next)) {
    const saved = await setAuthProfileOrder({ agentDir, provider, order: next });
    if (!saved) return false;
    reloaded = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  }

  if (sameOrder(findProviderOrder(reloaded, provider), next)) return true;

  const fallback = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  fallback.order = { ...(fallback.order ?? {}), [provider]: next };
  saveAuthProfileStore(fallback, agentDir, {
    filterExternalAuthProfiles: false,
    syncExternalCli: false,
    preserveOrderProfileIds: next,
  });
  const verified = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  return sameOrder(findProviderOrder(verified, provider), next);
}

function leaseEpochKey(provider, agentId) {
  return `${resolveProviderIdForAuth(provider)}\u0000${agentId}`;
}

function sameLeaseEpoch(left, right) {
  return left?.epoch === right?.epoch && left?.status === right?.status &&
    left?.leaseId === right?.leaseId && left?.profileId === right?.profileId &&
    left?.digest === right?.digest && left?.model === right?.model;
}

async function saveStrictLeaseOrder(agentDir, provider, store, profileId) {
  // `lastGood` belongs to the inherited OAuth owner in current OpenClaw builds,
  // whereas an AuthBus lease belongs to one agent.  An explicit stored order is
  // already authoritative for normal provider selection, so never try to turn
  // a per-agent lease into a shared `lastGood` pointer.
  if (profileId) return await saveManagedOrder(agentDir, provider, store, [profileId]);
  // An empty stored order is significant to OpenClaw: it resolves to no auth
  // candidate instead of falling back to every credential in the local store.
  const fallback = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  const orderKey = findProviderKey(fallback.order, provider) ?? provider;
  const lastGoodKey = findProviderKey(fallback.lastGood, provider);
  fallback.order = { ...(fallback.order ?? {}), [orderKey]: [] };
  if (lastGoodKey) {
    fallback.lastGood = { ...(fallback.lastGood ?? {}) };
    delete fallback.lastGood[lastGoodKey];
    if (Object.keys(fallback.lastGood).length === 0) fallback.lastGood = undefined;
  }
  saveAuthProfileStore(fallback, agentDir, {
    filterExternalAuthProfiles: false,
    syncExternalCli: false,
    preserveOrderProfileIds: [],
  });
  const verified = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
  return sameOrder(findProviderOrder(verified, provider), []) && !findProviderLastGood(verified, provider);
}

function strictPolicyScopes(policy, hostId) {
  const scopes = [];
  for (const [provider, providerPolicy] of Object.entries(policy?.providers ?? {})) {
    const scheduler = providerPolicy?.scheduler;
    if (!scheduler || scheduler.strategy !== "strict-lease-v1") continue;
    for (const rawScope of scheduler.scopes ?? []) {
      if (rawScope?.hostId !== hostId || rawScope.strict === false || !Array.isArray(rawScope.agentIds)) continue;
      if (typeof rawScope.model !== "string" || !rawScope.model.trim()) continue;
      scopes.push({
        provider: resolveProviderIdForAuth(provider),
        model: rawScope.model.trim(),
        agentIds: rawScope.agentIds.filter((agentId) => typeof agentId === "string" && agentId.trim()),
        strict: true,
        mode: scheduler.mode === "enforce" ? "enforce" : "shadow",
      });
    }
  }
  return scopes;
}

/**
 * Apply only centrally granted strict leases.  A missing, expired, or
 * unassigned lease deliberately clears the provider order rather than allowing
 * OpenClaw to drift back to a shared candidate pool.
 */
async function applyLeaseAssignments(agentDirs, rawAssignments, config, leaseEpochs, policy, now = Date.now()) {
  const document = normalizeLeaseAssignments(rawAssignments, { hostId: config.hostId, now });
  const scopeByKey = new Map(document.scopes.map((scope) => [`${scope.provider}\u0000${scope.model}`, scope]));
  for (const scope of strictPolicyScopes(policy, config.hostId)) {
    const key = `${scope.provider}\u0000${scope.model}`;
    const existing = scopeByKey.get(key);
    scopeByKey.set(key, existing ? { ...existing, mode: scope.mode } : scope);
  }
  const scopes = [...scopeByKey.values()];
  const result = {
    generation: document.generation,
    changedOrders: 0,
    appliedAssignments: 0,
    unassigned: 0,
    expired: 0,
    shadowAssignments: 0,
    staleAssignments: 0,
    materializationMissing: 0,
    observations: [],
  };
  for (const agentDir of agentDirs) {
    const agentId = path.basename(path.dirname(agentDir));
    for (const scope of scopes) {
      if (!scope.agentIds.includes(agentId) || !scope.strict) continue;
      let assignment = leaseAssignmentForAgent(document, { provider: scope.provider, agentId, now });
      const missingControlDocument = !assignment || assignment.reason === "lease_missing";
      if (missingControlDocument) {
        assignment = {
          provider: scope.provider,
          model: scope.model,
          agentId,
          profileId: null,
          digest: null,
          leaseId: null,
          status: "UNASSIGNED",
          reason: "assignment_document_missing",
          mode: scope.mode ?? "shadow",
          epoch: null,
          expiresAt: 0,
        };
      }
      const epochKey = leaseEpochKey(scope.provider, agentId);
      const known = leaseEpochs.get(epochKey);
      const candidateEpoch = Number.isFinite(assignment.epoch) ? Number(assignment.epoch) : null;
      const stale = known && (
        candidateEpoch !== null && (candidateEpoch < Number(known.epoch) ||
          (candidateEpoch === Number(known.epoch) && !sameLeaseEpoch(known, assignment)))
      );
      if (stale) {
        result.staleAssignments += 1;
        result.observations.push({
          provider: scope.provider,
          model: scope.model,
          agentId,
          epoch: candidateEpoch ?? (Number(known?.epoch) || 0),
          status: "STALE",
          leaseId: assignment.leaseId ?? null,
        });
        continue;
      }
      const enforce = config.schedulerMode === "enforce" && assignment.mode === "enforce";
      if (!enforce) {
        result.shadowAssignments += 1;
        result.observations.push({
          provider: scope.provider,
          model: scope.model,
          agentId,
          epoch: candidateEpoch ?? (Number(known?.epoch) || 0),
          status: assignment.status === "ASSIGNED" ? "SHADOW_ASSIGNED" : "SHADOW_UNASSIGNED",
          leaseId: assignment.leaseId ?? null,
        });
        continue;
      }
      const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
      let profileId = assignment.status === "ASSIGNED" ? assignment.profileId : null;
      if (assignment.status === "EXPIRED") result.expired += 1;
      if (profileId) {
        const credential = store.profiles?.[profileId];
        if (!credential || credentialDigest(credential) !== assignment.digest) {
          profileId = null;
          result.materializationMissing += 1;
        }
      }
      const before = findProviderOrder(store, scope.provider);
      const beforeLastGood = findProviderLastGood(store, scope.provider);
      const saved = await saveStrictLeaseOrder(agentDir, scope.provider, store, profileId);
      if (!saved) throw new Error(`AuthBus strict lease transaction failed for agent ${agentId}`);
      const changed = !sameOrder(before, profileId ? [profileId] : []) ||
        (profileId ? beforeLastGood !== profileId : Boolean(beforeLastGood));
      if (changed) result.changedOrders += 1;
      if (profileId) result.appliedAssignments += 1;
      else result.unassigned += 1;
      const accepted = {
        epoch: candidateEpoch,
        status: profileId ? "ASSIGNED" : assignment.status === "EXPIRED" ? "EXPIRED" : "UNASSIGNED",
        leaseId: profileId ? assignment.leaseId : null,
        profileId,
        digest: profileId ? assignment.digest : null,
        model: scope.model,
      };
      if (candidateEpoch !== null) leaseEpochs.set(epochKey, accepted);
      result.observations.push({ provider: scope.provider, model: scope.model, agentId, ...accepted });
    }
  }
  return result;
}

function resolveScheduledProviderState(store, provider, scheduleResult, agentId) {
  const activeProfile = scheduleResult?.assignments.get(agentId) ?? null;
  if (!activeProfile) return null;
  const candidates = scheduleResult.availableProfileIds
    .filter((profileId) => credentialMatchesProvider(store.profiles?.[profileId], provider));
  if (!candidates.includes(activeProfile)) return null;
  return {
    candidates,
    activeProfile,
    enforceLastGood: scheduleResult.scope?.enforceLastGood === true,
  };
}

async function applyOrderPolicy(agentDirs, rawPolicy, { hostId, now = Date.now() } = {}) {
  const policy = normalizeOrderPolicy(rawPolicy);
  let changedOrders = 0;
  let managedOrderBindings = 0;
  let scheduledAssignments = 0;
  let scheduleUnassigned = 0;
  const agentEntries = agentDirs.map((agentDir) => ({
    agentDir,
    agentId: path.basename(path.dirname(agentDir)),
  }));
  const schedules = new Map(
    Object.entries(policy.providers).map(([provider, providerPolicy]) => [
      provider,
      resolveScheduledAssignments(providerPolicy, {
        hostId,
        agentIds: agentEntries.map((entry) => entry.agentId),
        now,
      }),
    ]),
  );
  const scheduleOvercommitted = [...schedules.values()].reduce(
    (total, schedule) => total + schedule.overcommitted,
    0,
  );

  for (const { agentDir, agentId } of agentEntries) {
    for (const [provider, providerPolicy] of Object.entries(policy.providers)) {
      const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
      const scheduleResult = schedules.get(provider);
      const isScheduledAgent = Boolean(scheduleResult?.scheduledAgentIds.includes(agentId));
      const scheduled = resolveScheduledProviderState(store, provider, scheduleResult, agentId);
      if (isScheduledAgent && !scheduled) scheduleUnassigned += 1;
      const managed = scheduled ?? resolveManagedProviderState(store, provider, providerPolicy);
      if (managed.candidates.length === 0 && !managed.activeProfile) continue;
      const existing = findProviderOrder(store, provider);
      const candidates = scheduled
        ? uniqueProfileIds([...managed.candidates, ...resolveManagedProviderState(store, provider, providerPolicy).candidates])
        : managed.candidates;
      const next = mergeManagedOrder(existing, candidates, managed.activeProfile, {
        enforceManagedOrder: scheduled ? false : providerPolicy.enforceManagedOrder,
      });
      managedOrderBindings += candidates.length;
      // OpenClaw resolves an explicit order before considering `lastGood`.
      // Do not force `lastGood` here: inherited OAuth profiles merge that field
      // from the main agent, making a per-agent legacy slot impossible to
      // persist and previously causing the entire AuthBus cycle to abort.
      if (sameOrder(existing, next)) {
        if (scheduled) scheduledAssignments += 1;
        continue;
      }
      const saved = await saveManagedOrder(agentDir, provider, store, next);
      if (!saved) throw new Error(`AuthBus order transaction failed for agent ${path.basename(path.dirname(agentDir))}`);
      changedOrders += 1;
      if (scheduled) scheduledAssignments += 1;
    }
  }

  let verifiedOrderBindings = 0;
  for (const { agentDir, agentId } of agentEntries) {
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    for (const [provider, providerPolicy] of Object.entries(policy.providers)) {
      const scheduled = resolveScheduledProviderState(store, provider, schedules.get(provider), agentId);
      const managed = scheduled ?? resolveManagedProviderState(store, provider, providerPolicy);
      if (managed.candidates.length === 0 && !managed.activeProfile) continue;
      const order = findProviderOrder(store, provider);
      const candidates = scheduled
        ? uniqueProfileIds([...managed.candidates, ...resolveManagedProviderState(store, provider, providerPolicy).candidates])
        : managed.candidates;
      for (const profileId of candidates) {
        if (!order.includes(profileId)) throw new Error("AuthBus managed fallback missing from auth order");
        verifiedOrderBindings += 1;
      }
      if (managed.activeProfile && order[0] !== managed.activeProfile) {
        throw new Error("AuthBus active profile is not first in auth order");
      }
    }
  }
  return {
    policy,
    changedOrders,
    managedOrderBindings,
    verifiedOrderBindings,
    scheduledAssignments,
    scheduleUnassigned,
    scheduleOvercommitted,
  };
}

function makeEvent(config, candidate, reason) {
  return {
    schemaVersion: 1,
    eventId: crypto.randomUUID(),
    sourceHost: config.hostId,
    reason,
    createdAt: Date.now(),
    profileId: candidate.profileId,
    digest: candidate.digest,
    identity: candidate.identity,
    credential: candidate.credential,
  };
}

function makeControlEvent(config, kind, payload) {
  return {
    schemaVersion: 2,
    eventId: crypto.randomUUID(),
    kind,
    sourceHost: config.hostId,
    createdAt: Date.now(),
    ...payload,
  };
}

function makeAgentReports(config, agentDirs, leaseObservations, policy) {
  const observationsByAgent = new Map();
  for (const observation of leaseObservations) {
    const entries = observationsByAgent.get(observation.agentId) ?? [];
    entries.push(observation);
    observationsByAgent.set(observation.agentId, entries);
  }
  return agentDirs.map((agentDir) => {
    const agentId = path.basename(path.dirname(agentDir));
    const requirements = schedulerReportProfileRequirements(policy, { hostId: config.hostId, agentId });
    if (requirements.size === 0) return null;
    const store = loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    const profiles = Object.entries(store.profiles ?? {})
      .filter(([profileId, credential]) => validCredential(profileId, credential) &&
        requirements.has(`${resolveProviderIdForAuth(credential.provider)}\u0000${profileId}`))
      .map(([profileId, credential]) => ({
        provider: resolveProviderIdForAuth(credential.provider),
        profileId,
        digest: credentialDigest(credential),
      }))
      .sort((left, right) => left.provider.localeCompare(right.provider) || left.profileId.localeCompare(right.profileId));
    return makeControlEvent(config, "agent-report", {
      agentId,
      observedAt: Date.now(),
      profiles,
      leases: observationsByAgent.get(agentId) ?? [],
    });
  }).filter(Boolean);
}

function normalizedConfig(raw) {
  const orderExcludeAgentIds = Array.isArray(raw.orderExcludeAgentIds)
    ? [...new Set(raw.orderExcludeAgentIds
      .filter((value) => typeof value === "string")
      .map((value) => value.trim())
      .filter((value) => /^[a-z0-9][a-z0-9_-]{0,127}$/.test(value)))]
    : [];
  return {
    address: raw.address,
    caFile: raw.caFile,
    roleIdFile: raw.roleIdFile,
    secretIdFile: raw.secretIdFile,
    hostId: raw.hostId,
    pollIntervalMs: Number(raw.pollIntervalMs) || 15_000,
    refreshMarginMs: Number(raw.refreshMarginMs) || 15 * 60_000,
    maxRefreshesPerCycle: Number(raw.maxRefreshesPerCycle) || 1,
    leader: raw.leader === true,
    publishNew: raw.publishNew === true,
    manageOrder: raw.manageOrder !== false,
    schedulerMode: raw.schedulerMode === "enforce" ? "enforce" : "shadow",
    schedulerReportIntervalMs: Math.max(15_000, Math.min(300_000, Number(raw.schedulerReportIntervalMs) || 60_000)),
    // This stays opt-in until the central refresh lease has been observed in
    // shadow mode.  It prevents independent hosts from racing OAuth refresh
    // token rotation once strict scheduling is enabled.
    enforceRefreshLeases: raw.enforceRefreshLeases === true,
    orderExcludeAgentIds,
    releaseGeneration: Number.isSafeInteger(raw.releaseGeneration) && raw.releaseGeneration >= 0
      ? raw.releaseGeneration
      : 0,
  };
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "OpenClaw AuthBus",
  description: "Synchronizes auth credentials through OpenBao",
  register(api) {
    if (api.registrationMode !== "full") return;
    const config = normalizedConfig(api.pluginConfig ?? {});
    let timer = null;
    let stopped = false;
    let running = false;
    let bao = null;
    let applied = new Map();
    let appliedLoaded = false;
    const published = new Set();
    let refreshBackoff = new Map();
    let refreshBackoffLoaded = false;
    let badRefreshQuarantine = new Map();
    let badRefreshQuarantineLoaded = false;
    let leaseEpochs = new Map();
    let leaseEpochsLoaded = false;
    let lastSchedulerReportAt = 0;
    let serviceContext = null;
    let operationTail = Promise.resolve();

    async function acquireOperationLock() {
      const previous = operationTail;
      let release;
      operationTail = new Promise((resolve) => {
        release = resolve;
      });
      await previous;
      return release;
    }

    function ensureBadRefreshQuarantineLoaded(stateDir) {
      if (badRefreshQuarantineLoaded) return;
      badRefreshQuarantine = readBadRefreshQuarantine(stateDir);
      badRefreshQuarantineLoaded = true;
    }

    function ensureLeaseEpochsLoaded(stateDir) {
      if (leaseEpochsLoaded) return;
      leaseEpochs = readLeaseEpochs(stateDir);
      leaseEpochsLoaded = true;
    }

    api.agent.events.registerAgentEventSubscription({
      id: "auth-health-reporter",
      description: "Reports exact credential-generation provider failures to the central AuthBus health state",
      streams: ["lifecycle"],
      async handle(event) {
        const ctx = serviceContext;
        if (stopped || !ctx || event.data?.phase !== "error") return;
        const text = lifecycleErrorText(event);
        const failure = classifyProviderFailure(text);
        const sourceAgentId = lifecycleAgentId(event);
        if (!failure || !sourceAgentId) return;
        const releaseOperation = await acquireOperationLock();
        try {
          const agentDirs = discoverAgentDirs(ctx.stateDir);
          const sourceAgentDir = agentDirs.find(
            (agentDir) => path.basename(path.dirname(agentDir)) === sourceAgentId,
          );
          if (!sourceAgentDir) return;
          const sourceStore = loadAuthProfileStoreWithoutExternalProfiles(sourceAgentDir, {
            allowKeychainPrompt: false,
          });
          const permanent = failure.classification === "auth_permanent";
          const selected = permanent
            ? selectRecentlyFailedOAuthProfile(sourceStore, failure.provider, event.ts)
            : selectRecentlyFailedProfile(sourceStore, failure.provider, event.ts);
          if (!selected) {
            ctx.logger.warn(
              `AuthBus observed ${failure.classification} but could not safely identify one credential generation for agent ${sourceAgentId}`,
            );
            return;
          }
          const provider = failure.provider ?? resolveProviderIdForAuth(selected.credential.provider);
          let model = lifecycleModel(event);
          if (model && !model.includes("/")) model = `${provider}/${model}`;
          bao ??= new BaoClient(config);
          const observation = makeControlEvent(config, "health-observation", {
            observedAt: Number(event.ts) || Date.now(),
            provider,
            profileId: selected.profileId,
            digest: credentialDigest(selected.credential),
            model,
            classification: failure.classification,
            reason: failure.reason,
            retryAfterMs: failure.retryAfterMs ?? null,
            traceId: typeof event.runId === "string" ? event.runId : null,
          });
          await bao.writeInbox(config.hostId, observation.eventId, observation);
          if (!permanent) return;

          ensureBadRefreshQuarantineLoaded(ctx.stateDir);
          const failedDigest = credentialDigest(selected.credential);
          const existing = badRefreshQuarantine.get(selected.profileId);
          badRefreshQuarantine.set(selected.profileId, {
            digest: failedDigest,
            provider,
            reason: failure.reason,
            firstDetectedAt: existing?.digest === failedDigest ? existing.firstDetectedAt : Number(event.ts) || Date.now(),
            lastDetectedAt: Number(event.ts) || Date.now(),
            sourceAgentId,
            sourceRunId: typeof event.runId === "string" ? event.runId : null,
          });
          writeBadRefreshQuarantine(ctx.stateDir, badRefreshQuarantine);
          const purged = purgeBadRefreshCredentials(agentDirs, badRefreshQuarantine);
          clearRuntimeAuthProfileStoreSnapshots();
          const recycled = retireSharedCodexAppServerClients();
          ctx.logger.warn(
            `AuthBus quarantined permanent OAuth refresh profile ${profileLogId(selected.profileId)}: reason=${failure.reason}, removed=${purged.removedCredentials}, retired=${recycled.retired}, deferred=${recycled.deferred}`,
          );
        } catch (error) {
          ctx.logger.error(`AuthBus health reporter failed: ${error instanceof Error ? error.message : String(error)}`);
        } finally {
          releaseOperation();
        }
      },
    });

    async function cycle(ctx) {
      if (running || stopped) return;
      running = true;
      const releaseOperation = await acquireOperationLock();
      const startedAt = Date.now();
      let importedProfiles = 0;
      let changedStores = 0;
      let publishedEvents = 0;
      let schedulerReports = 0;
      let schedulerReportProfiles = 0;
      let orderResult = {
        policy: normalizeOrderPolicy(null),
        changedOrders: 0,
        managedOrderBindings: 0,
        verifiedOrderBindings: 0,
        scheduledAssignments: 0,
        scheduleUnassigned: 0,
        scheduleOvercommitted: 0,
      };
      let leaseResult = {
        generation: 0,
        changedOrders: 0,
        appliedAssignments: 0,
        unassigned: 0,
        expired: 0,
        shadowAssignments: 0,
        staleAssignments: 0,
        materializationMissing: 0,
        observations: [],
      };
      let runtimeRecycle = null;
      try {
        bao ??= new BaoClient(config);
        const agentDirs = discoverAgentDirs(ctx.stateDir);
        if (agentDirs.length === 0) throw new Error("No local OpenClaw agent databases found");
        if (!appliedLoaded) {
          applied = readDigestMap(ctx.stateDir, "applied-profiles.json");
          appliedLoaded = true;
        }
        ensureBadRefreshQuarantineLoaded(ctx.stateDir);
        ensureLeaseEpochsLoaded(ctx.stateDir);
        if (config.leader && !refreshBackoffLoaded) {
          refreshBackoff = readRefreshBackoff(ctx.stateDir);
          refreshBackoffLoaded = true;
        }
        const manifestSecret = await bao.readSecret("manifest");
        const manifest = manifestSecret?.data ?? { schemaVersion: 1, generation: 0, profiles: [] };
        if (!Array.isArray(manifest.profiles)) throw new Error("Invalid AuthBus manifest");
        const manifestById = new Map(manifest.profiles.map((entry) => [entry.profileId, entry]));
        if (reconcileQuarantineWithManifest(badRefreshQuarantine, manifestById)) {
          writeBadRefreshQuarantine(ctx.stateDir, badRefreshQuarantine);
        }
        const purged = purgeBadRefreshCredentials(agentDirs, badRefreshQuarantine);
        changedStores += purged.changedStores;
        const localBeforeImport = selectLocalProfiles(agentDirs);
        const pendingRuntimeRefreshes = selectPendingRuntimeRefreshes(localBeforeImport, manifestById, applied);

        for (const candidate of pendingRuntimeRefreshes.values()) {
          changedStores += await updateEveryAgent(agentDirs, candidate.profileId, candidate.credential, candidate.digest);
          const pendingKey = `${candidate.profileId}:${candidate.digest}`;
          if (published.has(pendingKey)) continue;
          const event = makeEvent(config, candidate, "manual-login");
          await bao.writeInbox(config.hostId, event.eventId, event);
          published.add(pendingKey);
          publishedEvents += 1;
        }

        for (const entry of manifest.profiles) {
          if (!isRecord(entry) || typeof entry.profileId !== "string" || typeof entry.key !== "string") continue;
          if (isDigestQuarantined(badRefreshQuarantine, entry.profileId, entry.digest)) continue;
          if (pendingRuntimeRefreshes.has(entry.profileId)) continue;
          if (applied.get(entry.profileId) === entry.digest) continue;
          const secret = await bao.readSecret(`profiles/${encodeURIComponent(entry.key)}`);
          const payload = secret?.data;
          const credential = payload?.credential;
          if (!validCredential(entry.profileId, credential)) throw new Error("Invalid credential payload in AuthBus");
          const digest = credentialDigest(credential);
          if (digest !== entry.digest || digest !== payload.digest) throw new Error("AuthBus credential digest mismatch");
          if (identityDigest(credential) !== payload.identity) throw new Error("AuthBus credential identity mismatch");
          changedStores += await updateEveryAgent(agentDirs, entry.profileId, credential, digest);
          applied.set(entry.profileId, digest);
          importedProfiles += 1;
        }
        writeDigestMap(ctx.stateDir, "applied-profiles.json", applied);

        const orderPolicySecret = await bao.readSecret("order-policy");
        if (config.manageOrder) {
          const excluded = new Set(config.orderExcludeAgentIds);
          const orderAgentDirs = agentDirs.filter(
            (agentDir) => !excluded.has(path.basename(path.dirname(agentDir))),
          );
          orderResult = await applyOrderPolicy(orderAgentDirs, orderPolicySecret?.data, { hostId: config.hostId });
          orderResult.excludedAgents = agentDirs.length - orderAgentDirs.length;
        } else {
          orderResult.policy = normalizeOrderPolicy(orderPolicySecret?.data);
        }
        const assignmentsSecret = await bao.readSecret("scheduler-assignments");
        const epochsBefore = stableStringify(Object.fromEntries(leaseEpochs));
        leaseResult = await applyLeaseAssignments(
          agentDirs,
          assignmentsSecret?.data,
          config,
          leaseEpochs,
          orderResult.policy,
        );
        if (epochsBefore !== stableStringify(Object.fromEntries(leaseEpochs))) {
          writeLeaseEpochs(ctx.stateDir, leaseEpochs);
        }

        if (config.publishNew) {
          const localProfiles = selectLocalProfiles(agentDirs);
          const baseline = loadOrCreatePublishBaseline(ctx.stateDir, localProfiles, manifestById);
          for (const candidate of localProfiles.values()) {
            const manifestEntry = manifestById.get(candidate.profileId);
            if (!manifestEntry && baseline.get(candidate.profileId) === candidate.digest) continue;
            if (manifestEntry && manifestEntry.digest === candidate.digest) continue;
            if (manifestEntry && applied.get(candidate.profileId) !== manifestEntry.digest) continue;
            const pendingKey = `${candidate.profileId}:${candidate.digest}`;
            if (published.has(pendingKey)) continue;
            const event = makeEvent(config, candidate, manifestEntry ? "manual-login" : "new-profile");
            await bao.writeInbox(config.hostId, event.eventId, event);
            published.add(pendingKey);
            publishedEvents += 1;
          }
        }

        if (Date.now() - lastSchedulerReportAt >= config.schedulerReportIntervalMs || leaseResult.observations.length > 0) {
          for (const report of makeAgentReports(config, agentDirs, leaseResult.observations, orderResult.policy)) {
            await bao.writeInbox(config.hostId, report.eventId, report);
            schedulerReports += 1;
            schedulerReportProfiles += report.profiles.length;
          }
          lastSchedulerReportAt = Date.now();
        }

        if (config.leader) {
          const now = Date.now();
          let refreshedCount = 0;
          const activeProfileIds = new Set(
            Object.values(orderResult.policy.providers)
              .map((providerPolicy) => providerPolicy.activeProfile)
              .filter((profileId) => typeof profileId === "string"),
          );
          const refreshCandidates = manifest.profiles
            .filter(
              (entry) =>
                entry.type === "oauth" &&
                Number.isFinite(entry.expires) &&
                activeProfileIds.has(entry.profileId),
            )
            .sort((left, right) => left.expires - right.expires);
          for (const entry of refreshCandidates) {
            if (entry.type !== "oauth" || !Number.isFinite(entry.expires)) continue;
            if (entry.expires > now + config.refreshMarginMs) continue;
            const backoff = refreshBackoff.get(entry.profileId);
            if (backoff?.digest === entry.digest && backoff.nextAttemptAt > now) continue;
            const secret = await bao.readSecret(`profiles/${encodeURIComponent(entry.key)}`);
            const credential = secret?.data?.credential;
            if (!validCredential(entry.profileId, credential)) continue;
            const currentDigest = credentialDigest(credential);
            if (currentDigest !== entry.digest) continue;
            if (config.enforceRefreshLeases && !hasRefreshLease(assignmentsSecret?.data, {
              hostId: config.hostId,
              provider: resolveProviderIdForAuth(credential.provider),
              profileId: entry.profileId,
              digest: currentDigest,
              now,
            })) {
              ctx.logger.info(`AuthBus refresh lease not held for profile ${profileLogId(entry.profileId)}; skipping refresh`);
              continue;
            }
            refreshedCount += 1;
            let refreshed;
            try {
              refreshed = await refreshOAuthCredentialForRuntime({ credential });
            } catch (error) {
              const failures = backoff?.digest === entry.digest ? backoff.failures + 1 : 1;
              const delayMs = Math.min(6 * 60 * 60_000, 5 * 60_000 * 2 ** Math.min(failures - 1, 6));
              refreshBackoff.set(entry.profileId, {
                digest: entry.digest,
                failures,
                nextAttemptAt: now + delayMs,
              });
              writeRefreshBackoff(ctx.stateDir, refreshBackoff);
              ctx.logger.warn(
                `AuthBus refresh deferred for profile ${profileLogId(entry.profileId)} after provider error`,
              );
              if (refreshedCount >= config.maxRefreshesPerCycle) break;
              continue;
            }
            if (!refreshed || !validCredential(entry.profileId, refreshed)) {
              const failures = backoff?.digest === entry.digest ? backoff.failures + 1 : 1;
              refreshBackoff.set(entry.profileId, {
                digest: entry.digest,
                failures,
                nextAttemptAt: now + Math.min(6 * 60 * 60_000, 5 * 60_000 * 2 ** Math.min(failures - 1, 6)),
              });
              writeRefreshBackoff(ctx.stateDir, refreshBackoff);
              if (refreshedCount >= config.maxRefreshesPerCycle) break;
              continue;
            }
            const candidate = {
              profileId: entry.profileId,
              credential: refreshed,
              digest: credentialDigest(refreshed),
              identity: identityDigest(refreshed),
            };
            if (candidate.digest === entry.digest) {
              refreshBackoff.delete(entry.profileId);
              writeRefreshBackoff(ctx.stateDir, refreshBackoff);
              if (refreshedCount >= config.maxRefreshesPerCycle) break;
              continue;
            }
            const pendingKey = `${candidate.profileId}:${candidate.digest}`;
            if (published.has(pendingKey)) continue;
            changedStores += await updateEveryAgent(agentDirs, candidate.profileId, refreshed, candidate.digest);
            pendingRuntimeRefreshes.set(candidate.profileId, candidate);
            const event = makeEvent(config, candidate, "leader-refresh");
            await bao.writeInbox(config.hostId, event.eventId, event);
            published.add(pendingKey);
            publishedEvents += 1;
            refreshBackoff.delete(entry.profileId);
            writeRefreshBackoff(ctx.stateDir, refreshBackoff);
            if (refreshedCount >= config.maxRefreshesPerCycle) break;
          }
        }

        const verification = verifyEffectiveStores(agentDirs, manifest.profiles, pendingRuntimeRefreshes, badRefreshQuarantine);

        // Updating only the OpenClaw auth snapshot is insufficient: a
        // long-lived Codex app-server owns a separate CODEX_HOME runtime and
        // can otherwise keep refreshing an already-replaced credential.
        if (changedStores > 0 || orderResult.changedOrders > 0 || leaseResult.changedOrders > 0) {
          clearRuntimeAuthProfileStoreSnapshots();
          runtimeRecycle = retireSharedCodexAppServerClients();
          ctx.logger.info(
            `AuthBus retired Codex app-server clients: retired=${runtimeRecycle.retired}, closed=${runtimeRecycle.closed}, deferred=${runtimeRecycle.deferred}`,
          );
        }

        writeStatus(ctx.stateDir, {
          ok: true,
          hostId: config.hostId,
          leader: config.leader,
          lastCycleAt: Date.now(),
          elapsedMs: Date.now() - startedAt,
          manifestGeneration: Number(manifest.generation) || 0,
          manifestProfiles: manifest.profiles.length,
          importedProfiles,
          changedStores,
          publishedEvents,
          schedulerReports,
          schedulerReportProfiles,
          agentStores: agentDirs.length,
          verifiedStores: verification.verifiedStores,
          effectiveMissing: verification.missing,
          effectiveMismatched: verification.mismatched,
          pendingRuntimeRefreshes: pendingRuntimeRefreshes.size,
          orderPolicyGeneration: orderResult.policy.generation,
          orderPolicyProviders: Object.keys(orderResult.policy.providers).length,
          changedOrders: orderResult.changedOrders,
          managedOrderBindings: orderResult.managedOrderBindings,
          verifiedOrderBindings: orderResult.verifiedOrderBindings,
          scheduledAssignments: orderResult.scheduledAssignments,
          scheduleUnassigned: orderResult.scheduleUnassigned,
          scheduleOvercommitted: orderResult.scheduleOvercommitted,
          schedulerMode: config.schedulerMode,
          schedulerAssignmentGeneration: leaseResult.generation,
          strictLeaseAssignments: leaseResult.appliedAssignments,
          strictLeaseUnassigned: leaseResult.unassigned,
          strictLeaseExpired: leaseResult.expired,
          strictLeaseShadow: leaseResult.shadowAssignments,
          strictLeaseStale: leaseResult.staleAssignments,
          strictLeaseMaterializationMissing: leaseResult.materializationMissing,
          orderExcludedAgents: orderResult.excludedAgents ?? 0,
          releaseGeneration: config.releaseGeneration,
          codexAppServerRecycle: runtimeRecycle,
        });
      } catch (error) {
        if (error instanceof Error && error.message.startsWith("Effective auth verification failed:")) {
          applied.clear();
          writeDigestMap(ctx.stateDir, "applied-profiles.json", applied);
        }
        ctx.logger.error(`AuthBus cycle failed: ${error instanceof Error ? error.message : String(error)}`);
        writeStatus(ctx.stateDir, {
          ok: false,
          hostId: config.hostId,
          leader: config.leader,
          lastCycleAt: Date.now(),
          elapsedMs: Date.now() - startedAt,
          error: error instanceof Error ? error.message : String(error),
        });
      } finally {
        running = false;
        releaseOperation();
      }
    }

    api.registerService({
      id: PLUGIN_ID,
      async start(ctx) {
        stopped = false;
        serviceContext = ctx;
        await cycle(ctx);
        timer = setInterval(() => void cycle(ctx), config.pollIntervalMs);
        timer.unref?.();
      },
      async stop() {
        stopped = true;
        serviceContext = null;
        if (timer) clearInterval(timer);
        timer = null;
      },
    });
  },
});
