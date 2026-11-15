export function selectPendingRuntimeRefreshes(localProfiles, manifestById, applied) {
  const pending = new Map();
  for (const [profileId, candidate] of localProfiles) {
    const manifestEntry = manifestById.get(profileId);
    if (!manifestEntry || candidate.digest === manifestEntry.digest) continue;
    if (applied.get(profileId) !== manifestEntry.digest) continue;
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
