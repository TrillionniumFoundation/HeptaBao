function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function string(value, maximum = 512) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= maximum ? trimmed : null;
}

function integer(value, fallback = 0) {
  return Number.isFinite(value) ? Math.floor(value) : fallback;
}

function providerKey(value) {
  return string(value, 100)?.toLowerCase() ?? null;
}

function key(provider, agentId) {
  return `${provider}\u0000${agentId}`;
}

function normalizeScope(raw, hostId) {
  if (!isRecord(raw) || string(raw.hostId, 63) !== hostId) return null;
  const provider = providerKey(raw.provider);
  const model = string(raw.model, 240);
  const agentIds = [...new Set((Array.isArray(raw.agentIds) ? raw.agentIds : [])
    .map((agentId) => string(agentId, 128))
    .filter(Boolean))].sort();
  if (!provider || !model || agentIds.length === 0) return null;
  return {
    provider,
    model,
    agentIds,
    strict: raw.strict !== false,
    managedProfileIds: [...new Set((Array.isArray(raw.managedProfileIds) ? raw.managedProfileIds : [])
      .map((profileId) => string(profileId, 240))
      .filter(Boolean))],
  };
}

function normalizeAssignment(raw, hostId) {
  if (!isRecord(raw) || string(raw.hostId, 63) !== hostId) return null;
  const provider = providerKey(raw.provider);
  const model = string(raw.model, 240);
  const agentId = string(raw.agentId, 128);
  const status = raw.status === "ASSIGNED" || raw.status === "UNASSIGNED" ? raw.status : null;
  const mode = raw.mode === "enforce" || raw.mode === "shadow" ? raw.mode : null;
  const epoch = integer(raw.epoch, -1);
  if (!provider || !model || !agentId || !status || !mode || epoch < 0) return null;
  const profileId = status === "ASSIGNED" ? string(raw.profileId, 240) : null;
  const digest = status === "ASSIGNED" ? string(raw.digest, 128) : null;
  const leaseId = status === "ASSIGNED" ? string(raw.leaseId, 128) : null;
  if (status === "ASSIGNED" && (!profileId || !digest || !leaseId)) return null;
  return {
    provider,
    model,
    agentId,
    profileId,
    digest,
    leaseId,
    status,
    reason: string(raw.reason, 128),
    mode,
    epoch,
    expiresAt: Math.max(0, integer(raw.expiresAt)),
  };
}

function normalizeRefreshLease(raw, hostId) {
  if (!isRecord(raw)) return null;
  const provider = providerKey(raw.provider);
  const profileId = string(raw.profileId, 240);
  const digest = string(raw.digest, 128);
  const holderHost = string(raw.holderHost, 63);
  const leaseId = string(raw.leaseId, 128);
  const epoch = integer(raw.epoch, -1);
  const expiresAt = Math.max(0, integer(raw.expiresAt));
  if (!provider || !profileId || !digest || !holderHost || !leaseId || epoch < 0 || expiresAt === 0) return null;
  // A client must only act on a lease explicitly held by itself.  Keeping
  // other holders in the normalized document is useful for diagnostics, but
  // never turns them into local authority.
  return { provider, profileId, digest, holderHost, leaseId, epoch, expiresAt, local: holderHost === hostId };
}

/** Parse the non-secret document a client is allowed to read from OpenBao. */
export function normalizeLeaseAssignments(raw, { hostId, now = Date.now() } = {}) {
  const normalizedHostId = string(hostId, 63);
  if (!normalizedHostId || !isRecord(raw) || raw.schemaVersion !== 1) {
    return { generation: 0, scopes: [], assignments: new Map(), now };
  }
  const scopes = (Array.isArray(raw.scopes) ? raw.scopes : [])
    .map((scope) => normalizeScope(scope, normalizedHostId))
    .filter(Boolean);
  const scopeKeys = new Set(scopes.map((scope) => `${scope.provider}\u0000${scope.model}`));
  const assignments = new Map();
  for (const rawAssignment of Array.isArray(raw.assignments) ? raw.assignments : []) {
    const assignment = normalizeAssignment(rawAssignment, normalizedHostId);
    if (!assignment || !scopeKeys.has(`${assignment.provider}\u0000${assignment.model}`)) continue;
    const assignmentKey = key(assignment.provider, assignment.agentId);
    const previous = assignments.get(assignmentKey);
    if (!previous || assignment.epoch > previous.epoch || (assignment.epoch === previous.epoch && assignment.model < previous.model)) {
      assignments.set(assignmentKey, assignment);
    }
  }
  const refreshLeases = new Map();
  for (const rawRefreshLease of Array.isArray(raw.refreshLeases) ? raw.refreshLeases : []) {
    const refreshLease = normalizeRefreshLease(rawRefreshLease, normalizedHostId);
    if (!refreshLease) continue;
    const refreshKey = `${refreshLease.provider}\u0000${refreshLease.profileId}\u0000${refreshLease.digest}`;
    const previous = refreshLeases.get(refreshKey);
    if (!previous || refreshLease.epoch > previous.epoch) refreshLeases.set(refreshKey, refreshLease);
  }
  return {
    generation: Math.max(0, integer(raw.generation)),
    scopes,
    assignments,
    refreshLeases,
    now,
  };
}

/** Return an explicit ASSIGNED/UNASSIGNED/EXPIRED grant for one controlled agent. */
export function leaseAssignmentForAgent(document, { provider, agentId, now = Date.now() } = {}) {
  const normalizedProvider = providerKey(provider);
  const normalizedAgentId = string(agentId, 128);
  if (!normalizedProvider || !normalizedAgentId) return null;
  const scope = document?.scopes?.find(
    (candidate) => candidate.provider === normalizedProvider && candidate.agentIds.includes(normalizedAgentId),
  );
  if (!scope) return null;
  const assignment = document.assignments?.get(key(normalizedProvider, normalizedAgentId));
  if (!assignment) {
    return { provider: normalizedProvider, agentId: normalizedAgentId, model: scope.model, status: "UNASSIGNED", reason: "lease_missing", epoch: 0, mode: "shadow" };
  }
  if (assignment.status === "ASSIGNED" && assignment.expiresAt <= now) {
    return { ...assignment, profileId: null, digest: null, leaseId: null, status: "EXPIRED", reason: "lease_expired" };
  }
  return assignment;
}

/**
 * Refresh is a global side effect: allow it only when this exact credential
 * generation is covered by an unexpired lease held by this host.  The helper
 * deliberately matches digest, so a rotated credential cannot inherit an old
 * refresh grant.
 */
export function hasRefreshLease(raw, { hostId, provider, profileId, digest, now = Date.now() } = {}) {
  const document = normalizeLeaseAssignments(raw, { hostId, now });
  const normalizedProvider = providerKey(provider);
  const normalizedProfileId = string(profileId, 240);
  const normalizedDigest = string(digest, 128);
  if (!normalizedProvider || !normalizedProfileId || !normalizedDigest) return false;
  const refreshLease = document.refreshLeases.get(
    `${normalizedProvider}\u0000${normalizedProfileId}\u0000${normalizedDigest}`,
  );
  return Boolean(refreshLease?.local && refreshLease.expiresAt > now);
}
