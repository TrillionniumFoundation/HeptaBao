function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim()))];
}

const AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,127}$/;
const HOST_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

function nonNegativeInteger(value, fallback = 0) {
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback;
}

function normalizeScheduleResource(raw) {
  if (!isRecord(raw) || typeof raw.profileId !== "string" || !raw.profileId.trim()) return null;
  return {
    profileId: raw.profileId.trim(),
    maxAssignments: Math.min(128, Math.max(1, nonNegativeInteger(raw.maxAssignments, 1))),
    cooldownUntil: nonNegativeInteger(raw.cooldownUntil),
    disabledUntil: nonNegativeInteger(raw.disabledUntil),
  };
}

function normalizeScheduleScope(raw) {
  if (!isRecord(raw) || typeof raw.hostId !== "string" || !HOST_ID_PATTERN.test(raw.hostId.trim())) return null;
  const seenResources = new Set();
  const resources = Array.isArray(raw.resources)
    ? raw.resources
        .map(normalizeScheduleResource)
        .filter((resource) => resource && !seenResources.has(resource.profileId) && seenResources.add(resource.profileId))
    : [];
  if (resources.length === 0) return null;
  const agentIds = uniqueStrings(Array.isArray(raw.agentIds) ? raw.agentIds : [])
    .filter((agentId) => AGENT_ID_PATTERN.test(agentId));
  const model = typeof raw.model === "string" && raw.model.trim() ? raw.model.trim() : null;
  return {
    hostId: raw.hostId.trim(),
    agentIds,
    model,
    resources,
    enforceLastGood: raw.enforceLastGood === true,
  };
}

function normalizeScheduler(raw) {
  if (!isRecord(raw) || raw.enabled !== true) return null;
  const seenHosts = new Set();
  const scopes = Array.isArray(raw.scopes)
    ? raw.scopes
        .map(normalizeScheduleScope)
        .filter((scope) => scope && !seenHosts.has(scope.hostId) && seenHosts.add(scope.hostId))
    : [];
  if (scopes.length === 0) return null;
  return {
    schemaVersion: raw.schemaVersion === 2 ? 2 : 1,
    enabled: true,
    strategy: raw.strategy === "strict-lease-v1" ? raw.strategy : "balanced-round-robin-v1",
    mode: raw.mode === "enforce" ? "enforce" : "shadow",
    scopes,
  };
}

export function normalizeOrderPolicy(raw) {
  const providers = {};
  if (isRecord(raw?.providers)) {
    for (const [provider, value] of Object.entries(raw.providers)) {
      if (!provider.trim() || !isRecord(value)) continue;
      const candidates = Array.isArray(value.candidates)
        ? value.candidates
            .filter((candidate) => isRecord(candidate) && typeof candidate.profileId === "string")
            .map((candidate) => ({
              profileId: candidate.profileId.trim(),
              digest: typeof candidate.digest === "string" ? candidate.digest : null,
              enrolledAt: Number.isFinite(candidate.enrolledAt) ? candidate.enrolledAt : 0,
            }))
            .filter((candidate) => candidate.profileId)
        : [];
      const seen = new Set();
      const uniqueCandidates = candidates.filter((candidate) => {
        if (seen.has(candidate.profileId)) return false;
        seen.add(candidate.profileId);
        return true;
      });
      const activeProfile = typeof value.activeProfile === "string" && value.activeProfile.trim()
        ? value.activeProfile.trim()
        : null;
      const enforceManagedOrder = value.enforceManagedOrder === true;
      const scheduler = normalizeScheduler(value.scheduler);
      if (uniqueCandidates.length > 0 || activeProfile) {
        providers[provider.trim()] = { candidates: uniqueCandidates, activeProfile, enforceManagedOrder, scheduler };
      } else if (scheduler) {
        providers[provider.trim()] = { candidates: uniqueCandidates, activeProfile, enforceManagedOrder, scheduler };
      }
    }
  }
  return {
    schemaVersion: 1,
    generation: Number.isFinite(raw?.generation) ? raw.generation : 0,
    providers,
  };
}

/**
 * Resolve one host-local, capacity-bounded assignment from a centrally stored
 * scheduler scope. The scheduler deliberately assigns only whole agents, not
 * individual requests: OpenClaw retains request/session affinity locally and
 * the policy must not race a live request for an auth-store write.
 */
export function resolveScheduledAssignments(providerPolicy, { hostId, agentIds, now = Date.now() } = {}) {
  const scheduler = providerPolicy?.scheduler;
  const scope = scheduler?.scopes?.find((candidate) => candidate.hostId === hostId);
  const empty = {
    scope: null,
    assignments: new Map(),
    scheduledAgentIds: [],
    availableProfileIds: [],
    unavailableProfileIds: [],
    overcommitted: 0,
  };
  if (!scope) return empty;

  const localAgentIds = uniqueStrings(Array.isArray(agentIds) ? agentIds : [])
    .filter((agentId) => AGENT_ID_PATTERN.test(agentId));
  const scheduledAgentIds = scope.agentIds.length > 0
    ? scope.agentIds.filter((agentId) => localAgentIds.includes(agentId))
    : [...localAgentIds].sort();
  // Strict leases are allocated by the central coordinator.  The legacy local
  // resolver must not manufacture a modulo fallback while clients wait for a
  // central grant.
  if (scheduler.strategy === "strict-lease-v1") return empty;
  const availableResources = scope.resources.filter(
    (resource) => Math.max(resource.cooldownUntil, resource.disabledUntil) <= now,
  );
  const unavailableProfileIds = scope.resources
    .filter((resource) => Math.max(resource.cooldownUntil, resource.disabledUntil) > now)
    .map((resource) => resource.profileId);
  const slots = availableResources.flatMap((resource) =>
    Array.from({ length: resource.maxAssignments }, () => resource.profileId),
  );
  const assignments = new Map();
  slots.slice(0, scheduledAgentIds.length).forEach((profileId, index) => {
    assignments.set(scheduledAgentIds[index], profileId);
  });
  return {
    scope,
    assignments,
    scheduledAgentIds,
    availableProfileIds: availableResources.map((resource) => resource.profileId),
    unavailableProfileIds,
    overcommitted: slots.length === 0 ? 0 : Math.max(0, scheduledAgentIds.length - slots.length),
  };
}

export function mergeManagedOrder(existingOrder, candidateProfileIds, activeProfile, options = {}) {
  const existing = uniqueStrings(Array.isArray(existingOrder) ? existingOrder : []);
  const candidates = uniqueStrings(Array.isArray(candidateProfileIds) ? candidateProfileIds : []);
  const active = typeof activeProfile === "string" && activeProfile.trim() ? activeProfile.trim() : null;
  const managed = uniqueStrings([...(active ? [active] : []), ...candidates]);
  if (managed.length === 0) return existing;
  if (options.enforceManagedOrder === true) return managed;

  if (active && managed.includes(active)) {
    return uniqueStrings([active, ...candidates.filter((profileId) => profileId !== active), ...existing]);
  }
  if (existing.length === 0) return candidates;
  return uniqueStrings([existing[0], ...candidates.filter((profileId) => profileId !== existing[0]), ...existing.slice(1)]);
}

export function sameOrder(left, right) {
  return left.length === right.length && left.every((profileId, index) => profileId === right[index]);
}
