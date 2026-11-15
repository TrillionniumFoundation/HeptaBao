// The Codex extension owns its shared app-server clients in this process-wide
// state. AuthBus cannot import the extension directly because generated plugin
// paths differ across hosts, but the extension intentionally uses this stable
// Symbol.for key.
const SHARED_CODEX_APP_SERVER_CLIENT_STATE = Symbol.for("openclaw.codexAppServerClientState");

function nonNegativeCount(value) {
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

/**
 * Retire every shared Codex app-server client without interrupting an active
 * lease. It removes entries immediately so new work gets freshly authenticated
 * clients, closes idle clients now, and marks leased clients for their normal
 * release path to close.
 */
export function retireSharedCodexAppServerClients() {
  const state = globalThis[SHARED_CODEX_APP_SERVER_CLIENT_STATE];
  if (!state || !(state.clients instanceof Map)) {
    return {
      available: false,
      retired: 0,
      closed: 0,
      deferred: 0,
      invalid: 0,
      closeErrors: 0,
    };
  }

  const result = {
    available: true,
    retired: 0,
    closed: 0,
    deferred: 0,
    invalid: 0,
    closeErrors: 0,
  };
  for (const [key, entry] of state.clients.entries()) {
    state.clients.delete(key);
    if (!entry || typeof entry !== "object") {
      result.invalid += 1;
      continue;
    }
    result.retired += 1;
    entry.closeWhenIdle = true;
    const activeLeases = nonNegativeCount(entry.activeLeases);
    const pendingAcquires = nonNegativeCount(entry.pendingAcquires);
    if (activeLeases > 0 || pendingAcquires > 0) {
      result.deferred += 1;
      continue;
    }
    const client = entry.client;
    if (!client || typeof client.close !== "function") {
      // A startup path can populate entry.client later; its pending-acquire
      // release hook observes closeWhenIdle and closes it.
      result.deferred += 1;
      continue;
    }
    entry.closeWhenIdle = false;
    entry.client = undefined;
    try {
      client.close();
      result.closed += 1;
    } catch {
      result.closeErrors += 1;
    }
  }
  return result;
}
