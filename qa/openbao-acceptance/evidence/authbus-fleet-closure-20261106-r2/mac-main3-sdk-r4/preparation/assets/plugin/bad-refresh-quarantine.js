const PERMANENT_REFRESH_REASONS = [
  ["refresh_token_reused", /refresh_token_reused|refresh token has already been used|already been used to generate a new access token/i],
  ["invalid_refresh_token", /invalid_refresh_token|invalid refresh token/i],
  ["token_invalidated", /token_invalidated/i],
  ["invalid_grant", /invalid_grant/i],
  ["revoked", /refresh token[^\n]*(?:expired or revoked|revoked)/i],
];

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeProvider(provider) {
  return typeof provider === "string" ? provider.trim().toLowerCase() : "";
}

/** Classify only refresh failures that cannot recover by retrying the same credential. */
export function classifyPermanentRefreshFailure(value) {
  const message = value instanceof Error ? value.message : typeof value === "string" ? value : "";
  if (!message) return null;
  const lower = message.toLowerCase();
  const isRefreshFailure =
    lower.includes("oauth token refresh failed") ||
    lower.includes("auth refresh request failed") ||
    lower.includes("access token could not be refreshed") ||
    lower.includes("authentication session could not be refreshed automatically");
  if (!isRefreshFailure) return null;
  const matched = PERMANENT_REFRESH_REASONS.find(([, pattern]) => pattern.test(message));
  if (!matched) return null;
  const providerMatch = message.match(/OAuth token refresh failed for\s+([^:\s]+)\s*:/i);
  return { provider: normalizeProvider(providerMatch?.[1]) || null, reason: matched[0] };
}

function credentialMatchesProvider(credential, provider) {
  if (!isRecord(credential) || credential.type !== "oauth") return false;
  const expected = normalizeProvider(provider);
  return !expected || normalizeProvider(credential.provider) === expected;
}

/**
 * Resolve one exact profile after a terminal refresh error.  An ambiguous tie
 * deliberately returns null rather than risking a healthy account.
 */
export function selectRecentlyFailedOAuthProfile(store, provider, eventTs, options = {}) {
  if (!isRecord(store) || !isRecord(store.profiles) || !isRecord(store.usageStats)) return null;
  const timestamp = Number(eventTs);
  if (!Number.isFinite(timestamp)) return null;
  const maxAgeMs = Number.isFinite(options.maxAgeMs) ? Math.max(0, options.maxAgeMs) : 30_000;
  const futureSkewMs = Number.isFinite(options.futureSkewMs) ? Math.max(0, options.futureSkewMs) : 5_000;
  const candidates = [];
  for (const [profileId, credential] of Object.entries(store.profiles)) {
    if (!credentialMatchesProvider(credential, provider)) continue;
    const usage = store.usageStats[profileId];
    if (!isRecord(usage)) continue;
    const lastFailureAt = Number(usage.lastFailureAt);
    if (!Number.isFinite(lastFailureAt)) continue;
    const permanent = usage.disabledReason === "auth_permanent" || Number(usage.failureCounts?.auth_permanent) > 0;
    if (!permanent) continue;
    const ageMs = timestamp - lastFailureAt;
    if (ageMs > maxAgeMs || ageMs < -futureSkewMs) continue;
    candidates.push({ profileId, credential, lastFailureAt, distanceMs: Math.abs(ageMs) });
  }
  candidates.sort((left, right) => left.distanceMs - right.distanceMs || right.lastFailureAt - left.lastFailureAt);
  if (candidates.length === 0) return null;
  if (candidates.length > 1 && candidates[0].distanceMs === candidates[1].distanceMs) return null;
  return candidates[0];
}

/** Remove a profile and its state pointers without disturbing independent fallbacks. */
export function removeProfileAndReferences(store, profileId) {
  if (!isRecord(store) || !isRecord(store.profiles)) return false;
  let changed = false;
  if (store.profiles[profileId]) {
    delete store.profiles[profileId];
    changed = true;
  }
  if (isRecord(store.order)) {
    for (const [provider, order] of Object.entries(store.order)) {
      if (!Array.isArray(order) || !order.includes(profileId)) continue;
      const next = order.filter((candidate) => candidate !== profileId);
      if (next.length > 0) store.order[provider] = next;
      else delete store.order[provider];
      changed = true;
    }
    if (Object.keys(store.order).length === 0) store.order = undefined;
  }
  if (isRecord(store.lastGood)) {
    for (const [provider, candidate] of Object.entries(store.lastGood)) {
      if (candidate !== profileId) continue;
      delete store.lastGood[provider];
      changed = true;
    }
    if (Object.keys(store.lastGood).length === 0) store.lastGood = undefined;
  }
  if (isRecord(store.usageStats)) {
    if (store.usageStats[profileId]) {
      delete store.usageStats[profileId];
      changed = true;
    }
    if (Object.keys(store.usageStats).length === 0) store.usageStats = undefined;
  }
  return changed;
}

export function isDigestQuarantined(quarantine, profileId, digest) {
  const entry = quarantine instanceof Map ? quarantine.get(profileId) : null;
  return Boolean(entry && typeof digest === "string" && entry.digest === digest);
}

/** A re-login changes digest and therefore releases only that old generation. */
export function reconcileQuarantineWithManifest(quarantine, manifestById) {
  let changed = false;
  for (const [profileId, entry] of quarantine) {
    const manifestEntry = manifestById.get(profileId);
    if (manifestEntry?.digest === entry.digest) continue;
    quarantine.delete(profileId);
    changed = true;
  }
  return changed;
}
