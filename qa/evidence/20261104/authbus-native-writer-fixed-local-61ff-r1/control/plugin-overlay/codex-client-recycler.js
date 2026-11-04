// Paired with the factory's codex-writer-exit-v1 interface. AuthBus must not
// remove shared entries itself: the factory owns pending startup, leases and
// the actual transport exit barrier.
const SHARED_CODEX_APP_SERVER_CLIENT_STATE = Symbol.for("openclaw.codexAppServerClientState");
const PROTOCOL = "codex-writer-exit-v1";

export function retireSharedCodexAppServerClients() {
  const state = globalThis[SHARED_CODEX_APP_SERVER_CLIENT_STATE];
  const result = {available:false,retired:0,closed:0,closeRequested:0,deferred:0,invalid:0,closeErrors:0};
  if (!state || !(state.clients instanceof Map)) return result;
  const entries = [...state.clients.entries()];
  if (state.retirementProtocol !== PROTOCOL || typeof state.retireEntry !== "function"
    || !(state.retiring instanceof Map)) {
    // Refuse a mixed old-factory/new-recycler installation. No legacy
    // delete/close fallback is safe while an old writer may still exist.
    if (entries.length > 0) throw new Error("Codex factory writer-exit retirement protocol is required");
    return result;
  }
  result.available = true;
  // Validate the entire synchronous batch before asking the factory to mutate
  // any entry. This does not grant authority to unknown entry generations.
  for (const [key,entry] of entries) {
    if (!entry || typeof entry !== "object" || entry.writerExitProtocol !== PROTOCOL
      || !(entry.writerClients instanceof Set) || typeof entry.startupPending !== "boolean"
      || !Number.isInteger(entry.activeLeases) || entry.activeLeases < 0
      || !Number.isInteger(entry.pendingAcquires) || entry.pendingAcquires < 0
      || entry.writerExitBarrier || state.retiring.has(key) || state.clients.get(key) !== entry)
      throw new Error("Codex factory writer-exit entry contract is incompatible");
  }
  for (const [key,entry] of entries) {
    const retired = state.retireEntry(key,entry);
    if (retired?.retired !== true) throw new Error("Codex factory did not accept writer retirement");
    result.retired += 1;
    if (retired.closeRequested === true) result.closeRequested += 1;
    else result.deferred += 1;
  }
  // closed remains zero: a synchronous request is not a confirmed process exit.
  return result;
}
