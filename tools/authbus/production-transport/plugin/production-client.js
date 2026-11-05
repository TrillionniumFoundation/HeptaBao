import { StrictBaoClient } from "./strict-bao-client.js";
import { BoundedOutbox, normalizeTransport, stable } from "./bounded-outbox.js";
import { PrivateOutboxStore, productionStateDirectory, OutboxError } from "./private-outbox-store.js";

function operationOptions(options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options))
    throw new OutboxError("production_request_options_shape");
  const deadlineMs = options.deadlineMs ?? Date.now() + 30000;
  if (!Number.isSafeInteger(deadlineMs) || Date.now() >= deadlineMs)
    throw new OutboxError("production_operation_deadline");
  return { deadlineMs };
}

export async function renewProductionBearerIfDue(client, store, now = Date.now, options = {}) {
  const bounded = operationOptions(options);
  return store.withLock(async () => {
    operationOptions(bounded);
    const state = store.loadAuth().value;
    // Initial login and unresolved intent handling remain owned by the strict
    // client. This wrapper never clears an intent or issues an extra login.
    if (state?.phase !== "active") return;
    if (!Number.isSafeInteger(state.expiresAtUnixMs)) throw new OutboxError("production_bearer_state_shape");
    const remaining = state.expiresAtUnixMs - now();
    if (remaining <= 0) {
      // StrictBaoClient independently validates the persisted active lease.
      // A dispatched/unknown attempt never enters this recovery branch.
      await client.login(bounded);
      return;
    }
    if (remaining > 60000) return;
    if (state.renewable !== true) throw new OutboxError("production_bearer_not_renewable");
    await client.renew(bounded);
  });
}

export class ProductionTransportClient {
  #client; #store; #outbox; #host;
  constructor(config, stateDir) {
    const transport = normalizeTransport(config.productionTransport, config.hostId);
    this.#host = config.hostId;
    const binding = stable({ schema: "heptabao-authbus-local-outbox-v1", address: config.address, transport });
    this.#store = new PrivateOutboxStore(productionStateDirectory(stateDir), binding);
    try {
      this.#client = new StrictBaoClient({ ...config, kvMount: "openclaw-auth",
        serverCertificateSha256: transport.serverCertificateSha256 }, this.#store);
      this.#outbox = new BoundedOutbox(this.#client, this.#store, transport);
    } catch (error) { this.#store.close(); throw error; }
  }
  async readSecret(key, options = {}) {
    const bounded = operationOptions(options);
    await renewProductionBearerIfDue(this.#client, this.#store, Date.now, bounded);
    await this.#outbox.admit(bounded.deadlineMs);
    return this.#client.readSecret(key, bounded);
  }
  async writeInbox(hostId, eventId, event, options = {}) {
    const bounded = operationOptions(options);
    if (hostId !== this.#host || event?.sourceHost !== hostId || event?.eventId !== eventId)
      throw new OutboxError("production_event_path_identity");
    await renewProductionBearerIfDue(this.#client, this.#store, Date.now, bounded);
    return this.#outbox.publish(event, bounded);
  }
  async reconcile(options = {}) {
    const bounded = operationOptions(options);
    await renewProductionBearerIfDue(this.#client, this.#store, Date.now, bounded);
    return this.#outbox.reconcile(bounded);
  }
  async close() {
    try { return await this.#store.withLock(() => this.#client.close({ revoke: true })); }
    finally { this.#store.close(); }
  }
}
