import { classifyPermanentRefreshFailure } from "./bad-refresh-quarantine.js";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeProvider(value) {
  return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : null;
}

function retryAfterMs(message) {
  const seconds = message.match(/retry[- ]after[^0-9]*(\d+(?:\.\d+)?)\s*s(?:econds?)?/i)?.[1];
  if (!seconds) return null;
  return Math.max(15_000, Math.min(6 * 60 * 60_000, Math.round(Number(seconds) * 1000)));
}

function providerFromMessage(message) {
  return normalizeProvider(message.match(/(?:for|provider[=:])\s*([a-z0-9_-]+)/i)?.[1]);
}

/**
 * Classify a provider failure into a central health action.  Unknown errors are
 * deliberately ignored; ambiguity must never eject a shared credential.
 */
export function classifyProviderFailure(value) {
  const message = value instanceof Error ? value.message : typeof value === "string" ? value : "";
  if (!message) return null;
  const permanent = classifyPermanentRefreshFailure(message);
  if (permanent) return { classification: "auth_permanent", provider: permanent.provider, reason: permanent.reason };
  if (/\b(?:429|too many requests|rate limit(?:ed)?|quota (?:exceeded|limit)|insufficient_quota)\b/i.test(message)) {
    return { classification: "rate_limited", provider: providerFromMessage(message), reason: "rate_limited", retryAfterMs: retryAfterMs(message) };
  }
  if (/\b(?:503|overloaded|service unavailable|capacity temporarily unavailable)\b/i.test(message)) {
    return { classification: "overloaded", provider: providerFromMessage(message), reason: "overloaded", retryAfterMs: retryAfterMs(message) };
  }
  if (/\b(?:model_not_found|unsupported model|model .*?(?:not found|not supported)|does not support model)\b/i.test(message)) {
    return { classification: "unsupported_model", provider: providerFromMessage(message), reason: "unsupported_model" };
  }
  if (/\b(?:ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ETIMEDOUT|network is unreachable|dns(?: lookup)? failed)\b/i.test(message)) {
    return { classification: "local_network", provider: providerFromMessage(message), reason: "local_network", retryAfterMs: 30_000 };
  }
  return null;
}

function credentialMatchesProvider(credential, provider) {
  if (!isRecord(credential) || typeof credential.provider !== "string") return false;
  return !provider || credential.provider.trim().toLowerCase() === provider;
}

/** Resolve one profile only when the gateway's usage-state timing is unambiguous. */
export function selectRecentlyFailedProfile(store, provider, eventTs, options = {}) {
  if (!isRecord(store) || !isRecord(store.profiles) || !isRecord(store.usageStats)) return null;
  const timestamp = Number(eventTs);
  if (!Number.isFinite(timestamp)) return null;
  const maxAgeMs = Number.isFinite(options.maxAgeMs) ? Math.max(0, options.maxAgeMs) : 30_000;
  const futureSkewMs = Number.isFinite(options.futureSkewMs) ? Math.max(0, options.futureSkewMs) : 5_000;
  const normalizedProvider = normalizeProvider(provider);
  const candidates = [];
  for (const [profileId, credential] of Object.entries(store.profiles)) {
    if (!credentialMatchesProvider(credential, normalizedProvider)) continue;
    const usage = store.usageStats[profileId];
    const lastFailureAt = Number(usage?.lastFailureAt);
    if (!Number.isFinite(lastFailureAt)) continue;
    const age = timestamp - lastFailureAt;
    if (age > maxAgeMs || age < -futureSkewMs) continue;
    candidates.push({ profileId, credential, lastFailureAt, distanceMs: Math.abs(age) });
  }
  candidates.sort((left, right) => left.distanceMs - right.distanceMs || right.lastFailureAt - left.lastFailureAt);
  if (candidates.length === 0) return null;
  if (candidates.length > 1 && candidates[0].distanceMs === candidates[1].distanceMs) return null;
  return candidates[0];
}

export function lifecycleErrorText(event) {
  if (!isRecord(event?.data)) return "";
  return [event.data.error, event.data.errorMessage, event.data.message, event.data.detail]
    .filter((value) => typeof value === "string" && value.trim())
    .join("\n");
}

export function lifecycleAgentId(event) {
  if (typeof event?.agentId === "string" && event.agentId.trim()) return event.agentId.trim();
  if (typeof event?.sessionKey !== "string") return null;
  return event.sessionKey.match(/^agent:([^:]+):/)?.[1] ?? null;
}

export function lifecycleModel(event) {
  const direct = event?.data?.model ?? event?.data?.modelId ?? event?.model ?? event?.modelId;
  return typeof direct === "string" && direct.trim() ? direct.trim() : null;
}
