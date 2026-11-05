/** Strict cold bootstrap layered on the byte-frozen R3 local authority. */
import { performance } from "node:perf_hooks";
import { AdmissionAuthority } from "./authbus_admission_authority_candidate.mjs";
import { consumeTrustedProof } from "./authbus_trusted_control_candidate.mjs";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
export class TrustedAdmissionAuthority extends AdmissionAuthority {
  #source; #bootstrapped = false; #anchor = null; #proofFence = null; #logicalFloor = 0; #publishedShapes = new WeakMap();
  constructor({ directory, scope, controlSource }) {
    super({ directory, scope, monotonicNow: () => performance.now() });
    this.#source = controlSource;
    // Local wall time is not an authority for a freshly authenticated lease.
    // The server Date ceiling plus elapsed monotonic time is conservative;
    // old persisted observation floors can only shorten this lease.
    this.wallNow = () => {
      if (!this.#anchor) fail("trusted_control_clock_unavailable");
      const value = Math.ceil(this.#anchor.serverUpper + Math.max(0, performance.now() - this.#anchor.startedMono));
      this.#logicalFloor = Math.max(this.#logicalFloor, value);
      return this.#logicalFloor;
    };
  }
  #accept(proof, grant, previous) {
    this._close();
    const bound = consumeTrustedProof(this.#source, proof, this.scope, grant);
    if (!this.#bootstrapped && grant.epoch <= (previous?.grant?.epoch ?? -1)) fail("trusted_control_cold_higher_epoch_required");
    this.#anchor = bound;
    this.#logicalFloor = Math.max(this.#logicalFloor, previous?.observedAt ?? 0, this.clockWatermark?.wall ?? 0);
    this.#proofFence = { grantDigest: bound.grantDigest, epoch: grant.epoch, deadlineMono: bound.deadlineMono,
      sourceDigest: bound.sourceDigest, bootId: bound.bootId, version: bound.version, refreshOwnerBound: bound.refreshOwnerBound };
    return bound;
  }
  _leaseDeadline(grant, grantDigest, clocks) {
    const base = super._leaseDeadline(grant, grantDigest, clocks);
    if (grant.status !== "ASSIGNED") return base;
    const fence = this.#proofFence;
    if (!fence || fence.epoch !== grant.epoch || fence.grantDigest !== grantDigest) fail("trusted_control_deadline_proof_missing");
    const deadline = Math.min(base, fence.deadlineMono);
    this.leaseDeadlineFence.deadlineMono = Math.min(this.leaseDeadlineFence.deadlineMono, deadline);
    return this.leaseDeadlineFence.deadlineMono;
  }
  _write(record, expected) {
    const fence = this.#proofFence;
    const trustedControl = fence && record.grantDigest === fence.grantDigest ? {
      sourceDigest: fence.sourceDigest, bootId: fence.bootId, controlVersion: fence.version, refreshOwnerBound: fence.refreshOwnerBound
    } : record.trustedControl;
    const actualExpected = expected && this.#publishedShapes.get(expected) || expected;
    const decorated = { ...record, ...(trustedControl ? { trustedControl } : {}) };
    const result = super._write(decorated, actualExpected);
    this.#publishedShapes.set(record, decorated);
    return result;
  }
  async apply(grant, options) {
    const previous = this._read({ allowMissing: true });
    this.#accept(options?.controlProof, grant, previous);
    const result = await super.apply(grant, options);
    if (this.inspect().allowed) this.#bootstrapped = true;
    return result;
  }
  async reconcileCommitted(grant, options) {
    // Store verification proves only SDK contents. Even a real fresh GET of
    // the old grant cannot authenticate a new process's authorization epoch.
    if (!this.#bootstrapped) { this._close(); fail("trusted_control_cold_higher_epoch_required"); }
    this.#accept(options?.controlProof, grant, this._read());
    return super.reconcileCommitted(grant, options);
  }
  closeUnresolved(options) {
    // Closing requires no fresh positive proof or wall clock. An existing
    // durable observation floor suffices to publish a negative startup state.
    if (!this.#anchor) {
      const previous = this._read({ allowMissing: true });
      this.#logicalFloor = Math.max(this.#logicalFloor, previous?.observedAt ?? 0);
      this.#anchor = { serverUpper: this.#logicalFloor, startedMono: performance.now() };
    }
    return super.closeUnresolved(options);
  }
}

/** The bootstrap/poll adapter reads control itself; callers supply no grant. */
export async function applyFromTrustedControl({ authority, controlSource, updateStore, verifyStore }) {
  let fresh;
  try { fresh = await controlSource.readGrant(authority.scope); }
  catch (error) { authority.closeUnresolved(); throw error; }
  // A store fault deliberately keeps the base authority's durable pending
  // record. Only the coordinator can issue the next cold authorization epoch.
  await authority.apply(fresh.grant, { updateStore, verifyStore, controlProof: fresh.proof });
  return { grant: fresh.grant, public: fresh.public };
}
