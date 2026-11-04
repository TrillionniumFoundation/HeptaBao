export function selectPendingRuntimeRefreshes(localProfiles, manifestById, applied) {
  const pending = new Map();
  for (const [profileId, candidate] of localProfiles) {
    const manifestEntry = manifestById.get(profileId);
    if (!manifestEntry || candidate.digest === manifestEntry.digest) continue;
    // A managed producer can rotate again before it observes the canonical
    // acknowledgement of its preceding rotation. Preserve that newer local
    // value even while the manifest advances; otherwise importing the previous
    // acknowledgement would destroy the next credential. This only retains a
    // source candidate and permits an inbox report. The coordinator still needs
    // the exact operator grant before changing the canonical generation.
    const appliedDigest = applied.get(profileId);
    if (typeof appliedDigest !== "string" || !/^[0-9a-f]{64}$/.test(appliedDigest)) continue;
    if (candidate.identity !== manifestEntry.identity) continue;
    if (candidate.credential?.type !== "oauth" || manifestEntry.type !== "oauth") continue;
    const localExpires = Number(candidate.credential.expires) || 0;
    const manifestExpires = Number(manifestEntry.expires) || 0;
    if (localExpires <= manifestExpires) continue;
    pending.set(profileId, candidate);
  }
  return pending;
}

export function expectedCredentialDigest(manifestEntry, pendingRuntimeRefreshes) {
  return pendingRuntimeRefreshes.get(manifestEntry.profileId)?.digest ?? manifestEntry.digest;
}
