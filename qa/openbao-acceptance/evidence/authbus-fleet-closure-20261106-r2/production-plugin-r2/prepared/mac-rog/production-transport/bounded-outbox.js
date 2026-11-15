import crypto from "node:crypto";
import { OutboxError } from "./private-outbox-store.js";

export const TRANSPORT = "heptabao-authbus-fixed-slots-v1";
const PREFIX = "transport-v1";
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HOST = /^[a-z0-9][a-z0-9-]{0,62}$/;
const AGENT = /^[a-z0-9][a-z0-9_-]{0,127}$/;
function check(ok, code) { if (!ok) throw new OutboxError(code); }
export function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  check(value === null || ["string", "boolean"].includes(typeof value) || Number.isSafeInteger(value), "transport_json_value_shape");
  return value;
}
export const digest = value => crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
export const hashText = value => crypto.createHash("sha256").update(value).digest("hex");
function bounded(value) { check(Buffer.byteLength(JSON.stringify(stable(value))) <= 160 * 1024, "transport_document_bound"); }
function integer(value) { return Number.isSafeInteger(value) && value >= 0 && value < 9007199254740000; }
function exactKeys(value, names) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...names].sort().join("\0"); }
function operationDeadline(options = {}) {
  check(options && typeof options === "object" && !Array.isArray(options), "outbox_request_options_shape");
  const deadlineMs = options.deadlineMs ?? Date.now() + 30000;
  check(Number.isSafeInteger(deadlineMs) && Date.now() < deadlineMs, "outbox_operation_deadline");
  return deadlineMs;
}

export function normalizeTransport(config, hostId) {
  check(config && config.schema === TRANSPORT && config.production === true && HOST.test(hostId)
    && UUID.test(config.epoch) && Number.isInteger(config.slots) && config.slots >= 1 && config.slots <= 32
    && SHA.test(config.controlDigest) && SHA.test(config.serverCertificateSha256)
    && Array.isArray(config.agents) && config.agents.length >= 1 && config.agents.length <= 128
    && config.agents.every(a => typeof a === "string" && AGENT.test(a))
    && new Set(config.agents).size === config.agents.length, "production_transport_configuration");
  return { schema: TRANSPORT, production: true, hostId, epoch: config.epoch, slots: config.slots,
    agents: [...config.agents].sort(), controlDigest: config.controlDigest, serverCertificateSha256: config.serverCertificateSha256 };
}
export const slotKey = (source, index, kind = "outbox") => `${PREFIX}/${source.hostId}/${kind}/slot-${String(index).padStart(3, "0")}`;
export const reportKey = (source, agent) => `${PREFIX}/${source.hostId}/reports/${hashText(agent)}`;
export function initialSlot(source, index) {
  return { schema: `${TRANSPORT}.slot`, sourceHost: source.hostId, epoch: source.epoch, slot: index,
    sequence: 0, previousAckDigest: null, eventId: null, eventDigest: null, event: null };
}
export function initialAck(source, index) {
  return { schema: `${TRANSPORT}.ack`, sourceHost: source.hostId, epoch: source.epoch, slot: index,
    sequence: 0, slotVersion: 1, slotDocumentDigest: digest(initialSlot(source, index)), eventId: null,
    eventDigest: null, status: "empty", receiptDigest: null, receipt: null };
}
function validateSlot(source, index, snapshot) {
  const v = snapshot?.data;
  check(Number.isSafeInteger(snapshot?.version) && snapshot.version >= 1
    && exactKeys(v, ["schema", "sourceHost", "epoch", "slot", "sequence", "previousAckDigest", "eventId", "eventDigest", "event"])
    && v.schema === `${TRANSPORT}.slot` && v.sourceHost === source.hostId && v.epoch === source.epoch
    && v.slot === index && integer(v.sequence) && snapshot.version === v.sequence + 1, "slot_enrollment_or_sequence_binding");
  bounded(v);
  if (v.sequence === 0) check(digest(v) === digest(initialSlot(source, index)), "initial_slot_changed");
  else check(UUID.test(v.eventId) && SHA.test(v.previousAckDigest) && v.event?.eventId === v.eventId
    && v.event?.sourceHost === source.hostId && v.eventDigest === digest(v.event), "slot_event_binding");
  return v;
}
export function validatePair(source, index, snapshot, ackSnapshot) {
  const slot = validateSlot(source, index, snapshot); const ack = ackSnapshot?.data;
  check(Number.isSafeInteger(ackSnapshot?.version) && ackSnapshot.version >= 1
    && exactKeys(ack, ["schema", "sourceHost", "epoch", "slot", "sequence", "slotVersion", "slotDocumentDigest", "eventId", "eventDigest", "status", "receiptDigest", "receipt"])
    && ack.schema === `${TRANSPORT}.ack` && ack.sourceHost === source.hostId && ack.epoch === source.epoch
    && ack.slot === index && integer(ack.sequence) && ackSnapshot.version === ack.sequence + 1
    && ack.slotVersion === ack.sequence + 1 && SHA.test(ack.slotDocumentDigest), "ack_enrollment_or_sequence_binding");
  if (ack.sequence === 0) check(digest(ack) === digest(initialAck(source, index)), "initial_ack_changed");
  else check(UUID.test(ack.eventId) && SHA.test(ack.eventDigest) && ack.receipt && ack.receiptDigest === digest(ack.receipt)
    && ack.receipt.sourceHost === source.hostId && ack.receipt.eventId === ack.eventId && ack.receipt.eventDigest === ack.eventDigest
    && ack.status === ack.receipt.status && ["committed", "observed_health_no_scheduler_action"].includes(ack.status), "ack_terminal_receipt_binding");
  if (ack.sequence > 0 && source.ownerId) check(ack.receipt.ownerId === source.ownerId, "ack_canonical_owner_binding");
  if (slot.sequence === ack.sequence) {
    check(ack.slotDocumentDigest === digest(slot) && ack.eventId === slot.eventId && ack.eventDigest === slot.eventDigest
      && ack.slotVersion === snapshot.version, "ack_wrong_document");
    if (ack.status === "committed") {
      const event = slot.event;
      const profile = { schemaVersion: 1, profileId: event.profileId, credential: event.credential, digest: event.digest, identity: event.identity };
      check(event.schemaVersion === 1 && ack.receipt.schema === "heptabao-authbus-coordinator-v1.receipt"
        && ack.receipt.credentialDigest === event.digest && ack.receipt.profileIdSha256 === hashText(event.profileId)
        && ack.receipt.profileKey === `sha256-${digest(profile)}`, "ack_canonical_profile_binding");
    } else if (ack.status === "observed_health_no_scheduler_action") {
      check(slot.event.schemaVersion === 2 && slot.event.kind === "health-observation", "ack_health_event_kind_binding");
    }
    return true;
  }
  check(slot.sequence === ack.sequence + 1 && slot.previousAckDigest === digest(ack), "slot_skipped_or_stale_ack");
  return false;
}
function eventIdentity(event) {
  // Retry identity ignores a newly generated transport UUID for the same
  // credential. It never selects a newer credential or changes its expiry.
  if (event.schemaVersion === 1 && typeof event.profileId === "string" && SHA.test(event.digest))
    return `credential:${hashText(event.profileId)}:${event.digest}`;
  return `event:${event.eventId}`;
}

export class BoundedOutbox {
  #client; #store; #source; #admitted = false; #hook;
  constructor(client, store, source, phaseHook = () => {}) {
    this.#client = client; this.#store = store; this.#source = source; this.#hook = phaseHook;
  }
  #options(deadlineMs) { check(Date.now() < deadlineMs, "outbox_operation_deadline"); return { deadlineMs }; }
  async admit(deadlineMs = Date.now() + 30000) {
    if (this.#admitted) return;
    const control = await this.#client.readSecret(`${PREFIX}/control`, this.#options(deadlineMs));
    const data = control?.data;
    check(control?.version === 1 && data?.schema === `${TRANSPORT}.control` && digest(data) === this.#source.controlDigest
      && data.retainedSlotVersions === 2 && Number.isSafeInteger(data.bootstrapProfileCount) && data.bootstrapProfileCount > 0,
    "actual_production_control_binding");
    const enrolled = data.topology?.find(row => row.host_id === this.#source.hostId);
    check(enrolled && enrolled.epoch === this.#source.epoch && enrolled.slots === this.#source.slots
      && digest([...enrolled.agents].sort()) === digest(this.#source.agents), "producer_not_in_enrolled_topology");
    check(UUID.test(data.ownerId), "canonical_owner_shape");
    this.#source = { ...this.#source, ownerId: data.ownerId };
    const canonical = await this.#client.readSecret("manifest", this.#options(deadlineMs));
    check(canonical?.version >= 1 && canonical.data?.schemaVersion === 1 && Array.isArray(canonical.data.profiles)
      && canonical.data.profiles.length > 0 && canonical.data.profiles.length <= 64
      && canonical.data.coordinator?.ownerId === data.ownerId, "empty_or_unbound_canonical_production_manifest");
    this.#admitted = true;
  }
  async #resolve(recordName, row, deadlineMs) {
    const r = row.value;
    check(r.schema === `${TRANSPORT}.intent` && r.epoch === this.#source.epoch && r.sourceHost === this.#source.hostId
      && r.desiredDigest === digest(r.desired) && integer(r.expectedVersion) && r.expectedVersion >= 1,
    "durable_outbox_intent_binding");
    if (["confirmed", "acked"].includes(r.phase)) return row;
    if (r.phase === "rejected") throw new OutboxError("outbox_known_request_rejection_requires_review");
    if (r.phase === "prepared") return this.#dispatch(recordName, row, deadlineMs);
    check(["dispatched", "conflict"].includes(r.phase), "durable_outbox_intent_phase");
    const actual = await this.#client.readSecret(r.key, this.#options(deadlineMs));
    if (actual?.version === r.expectedVersion + 1 && digest(actual.data) === r.desiredDigest) {
      const value = { ...r, phase: "confirmed" }; this.#store.cas(recordName, row.revision, value);
      return this.#store.get(recordName);
    }
    // Equality to the preimage is not proof that an already dispatched
    // request can never commit. No retry, overwrite or new UUID is issued.
    throw new OutboxError(r.phase === "conflict" ? "outbox_known_cas_conflict_requires_review" : "outbox_mutation_outcome_unknown", { unknown: r.phase !== "conflict" });
  }
  async #dispatch(recordName, row, deadlineMs) {
    this.#options(deadlineMs);
    const r = { ...row.value, phase: "dispatched" };
    const revision = this.#store.cas(recordName, row.revision, r);
    this.#hook("intent_dispatched", { recordName });
    this.#store.assertCustody();
    let version;
    try {
      version = await this.#client.writeSecret(r.key, r.desired, r.expectedVersion, this.#options(deadlineMs));
    } catch (error) {
      if (error?.conflict === true) this.#store.cas(recordName, revision, { ...r, phase: "conflict" });
      else if (error?.unknown === false && Number.isInteger(error?.status) && error.status >= 400 && error.status < 500) {
        this.#store.cas(recordName, revision, { ...r, phase: "rejected", responseStatus: error.status });
        throw new OutboxError("outbox_known_request_rejection_requires_review");
      }
      // Retain the original dispatched intent for every failure. The next
      // operation may only read to reconcile it, never send it a second time.
      if (error instanceof OutboxError || error?.unknown || error?.conflict) throw error;
      throw new OutboxError("outbox_dispatch_not_confirmed", { unknown: true });
    }
    this.#hook("server_write_confirmed_before_local_receipt", { recordName });
    check(version === r.expectedVersion + 1, "outbox_response_version");
    const actual = await this.#client.readSecret(r.key, this.#options(deadlineMs));
    check(actual?.version === version && digest(actual.data) === r.desiredDigest, "outbox_readback_mismatch");
    this.#store.cas(recordName, revision, { ...r, phase: "confirmed" });
    return this.#store.get(recordName);
  }
  async #reconcileLocked(deadlineMs) {
    for (let slot = 0; slot < this.#source.slots; slot++) {
      const name = `slot:${slot}`; const row = this.#store.get(name);
      if (row && !["confirmed", "acked"].includes(row.value.phase)) await this.#resolve(name, row, deadlineMs);
    }
    for (const agent of this.#source.agents) {
      const name = `report:${hashText(agent)}`; const row = this.#store.get(name);
      if (row && !["confirmed", "acked"].includes(row.value.phase)) await this.#resolve(name, row, deadlineMs);
    }
  }
  async reconcile(options = {}) {
    const deadline = operationDeadline(options);
    return this.#store.withLock(async () => {
      this.#options(deadline); await this.admit(deadline); await this.#reconcileLocked(deadline);
      return { unresolvedIntents: 0, legacyInboxTouched: false };
    });
  }
  #intent(key, old, desired, identity) {
    return { schema: `${TRANSPORT}.intent`, sourceHost: this.#source.hostId, epoch: this.#source.epoch,
      key, expectedVersion: old.version, expectedDigest: digest(old.data), desired, desiredDigest: digest(desired),
      eventIdentity: identity, phase: "prepared" };
  }
  async publish(event, options = {}) {
    const deadline = operationDeadline(options);
    check(event && event.sourceHost === this.#source.hostId && UUID.test(event.eventId), "producer_event_identity");
    bounded(event);
    return this.#store.withLock(async () => {
      this.#options(deadline); await this.admit(deadline); await this.#reconcileLocked(deadline);
      if (event.schemaVersion === 2 && event.kind === "agent-report") return this.#publishReport(event, deadline);
      const identity = eventIdentity(event);
      for (let index = 0; index < this.#source.slots; index++) {
        const name = `slot:${index}`; const row = this.#store.get(name);
        if (!row || row.value.eventIdentity !== identity) continue;
        const current = await this.#client.readSecret(slotKey(this.#source, index), this.#options(deadline));
        const ack = await this.#client.readSecret(slotKey(this.#source, index, "ack"), this.#options(deadline));
        const terminal = validatePair(this.#source, index, current, ack);
        check(current.version === row.value.expectedVersion + 1 && digest(current.data) === row.value.desiredDigest, "local_outbox_state_behind_server");
        if (!terminal) return { accepted: true, duplicatePending: true, originalEventId: current.data.eventId };
        if (identity.startsWith("credential:")) {
          const canonical = await this.#client.readSecret("manifest", this.#options(deadline));
          if (canonical?.data?.profiles?.some(p => p.profileId === event.profileId && p.digest === event.digest))
            return { accepted: true, alreadyCanonical: true };
        } else if (current.data.eventId === event.eventId) return { accepted: true, alreadyAcknowledged: true };
      }
      const cursor = this.#store.get("cursor")?.value.next ?? 0;
      check(integer(cursor) && cursor < this.#source.slots, "producer_cursor_shape");
      for (let offset = 0; offset < this.#source.slots; offset++) {
        const index = (cursor + offset) % this.#source.slots;
        const current = await this.#client.readSecret(slotKey(this.#source, index), this.#options(deadline));
        const ack = await this.#client.readSecret(slotKey(this.#source, index, "ack"), this.#options(deadline));
        if (!validatePair(this.#source, index, current, ack)) continue;
        const local = this.#store.get(`slot:${index}`);
        if (local) check(current.version === local.value.expectedVersion + 1 && digest(current.data) === local.value.desiredDigest, "local_outbox_restore_or_server_rewind");
        else check(current.version === 1, "missing_durable_history_for_used_slot");
        const desired = { schema: `${TRANSPORT}.slot`, sourceHost: this.#source.hostId, epoch: this.#source.epoch,
          slot: index, sequence: current.data.sequence + 1, previousAckDigest: digest(ack.data),
          eventId: event.eventId, eventDigest: digest(event), event };
        bounded(desired);
        const name = `slot:${index}`; this.#store.put(name, this.#intent(slotKey(this.#source, index), current, desired, identity));
        this.#store.put("cursor", { next: (index + 1) % this.#source.slots });
        this.#hook("intent_prepared", { recordName: name });
        await this.#dispatch(name, this.#store.get(name), deadline);
        return { accepted: true, slot: index, sequence: desired.sequence };
      }
      throw new OutboxError("outbox_full_pending_events_retained", { backpressure: true });
    });
  }
  async #publishReport(event, deadline) {
    const agent = event.agentId; check(this.#source.agents.includes(agent) && !Object.hasOwn(event, "credential"), "report_agent_outside_enrollment");
    const key = reportKey(this.#source, agent); const name = `report:${hashText(agent)}`;
    const current = await this.#client.readSecret(key, this.#options(deadline)); const data = current?.data;
    check(Number.isSafeInteger(current?.version) && current.version >= 1 && data?.schema === `${TRANSPORT}.report`
      && data.sourceHost === this.#source.hostId && data.epoch === this.#source.epoch && data.agentId === agent
      && integer(data.sequence) && current.version === data.sequence + 1, "preprovisioned_report_binding");
    const local = this.#store.get(name);
    if (local) check(current.version === local.value.expectedVersion + 1 && digest(data) === local.value.desiredDigest, "report_state_rewind_or_foreign_writer");
    else check(current.version === 1 && data.event === null, "missing_durable_report_history");
    const desired = { schema: `${TRANSPORT}.report`, sourceHost: this.#source.hostId, epoch: this.#source.epoch,
      agentId: agent, sequence: data.sequence + 1, event };
    bounded(desired);
    this.#store.put(name, this.#intent(key, current, desired, `report:${hashText(agent)}`));
    this.#hook("intent_prepared", { recordName: name });
    await this.#dispatch(name, this.#store.get(name), deadline);
    return { accepted: true, fixedReport: true, agentIdSha256: hashText(agent), sequence: desired.sequence };
  }
}
