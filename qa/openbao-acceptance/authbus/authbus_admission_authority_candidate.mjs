/**
 * Review-only local admission authority for an explicitly configured AuthBus scope.
 * A resolver adapter must call inspect() for each credential selection, and a
 * trusted control adapter must call apply() before touching the SDK auth store.
 * This module does not authenticate control documents or install either adapter.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

const FORMAT = "heptabao-authbus-admission-candidate-v1";
const MAX_RECORD_BYTES = 16384;
const HEX = /^[a-f0-9]{64}$/;
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
export const digest = value => crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
const failure = code => Object.assign(new Error(code), { diagnosticCode: code });
function check(condition, code) { if (!condition) throw failure(code); }
function textField(value, name, limit = 1024) {
  check(typeof value === "string" && value.length > 0 && value.length <= limit &&
    !/[\u0000-\u001f\u007f]/.test(value), "invalid_" + name);
  return value;
}
function ownedDirectory(directory) {
  const stat = fs.lstatSync(directory);
  check(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o077) === 0, "admission_directory_custody_invalid");
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function boundedRead(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    check(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 &&
      stat.size > 0 && stat.size <= MAX_RECORD_BYTES, "admission_record_custody_invalid");
    const bytes = fs.readFileSync(fd);
    check(bytes.length === stat.size && bytes.length <= MAX_RECORD_BYTES, "admission_record_size_changed");
    return JSON.parse(bytes.toString("utf8"));
  } finally { fs.closeSync(fd); }
}
function normalizeGrant(value) {
  check(value && typeof value === "object" && !Array.isArray(value), "admission_grant_invalid");
  check(Number.isSafeInteger(value.epoch) && value.epoch >= 0, "admission_epoch_invalid");
  check(["ASSIGNED", "UNASSIGNED", "EXPIRED"].includes(value.status), "admission_status_invalid");
  check(value.mode === "enforce", "admission_mode_invalid");
  const assigned = value.status === "ASSIGNED";
  if (assigned) {
    check(Number.isSafeInteger(value.expiresAt) && value.expiresAt > 0, "admission_deadline_invalid");
    textField(value.profileId, "profile_id");
    textField(value.leaseId, "lease_id");
    check(typeof value.digest === "string" && HEX.test(value.digest), "admission_credential_digest_invalid");
  }
  return {
    epoch: value.epoch, status: value.status, mode: "enforce",
    profileId: assigned ? value.profileId : null,
    digest: assigned ? value.digest : null,
    leaseId: assigned ? value.leaseId : null,
    expiresAt: assigned ? value.expiresAt : 0,
    model: textField(value.model, "model"),
  };
}

/**
 * Cold instances start closed even if an old positive record is readable.
 * apply() is a TRUSTED-CONTROL boundary: its caller must freshly authenticate
 * the current control state. Reading a cached local grant is not sufficient.
 *
 * A pending record is fsynced before updateStore runs. It remains closed after
 * an SDK exception, uncertain outcome, a crash, or failed final publication.
 * No success/epoch acknowledgement is emitted until verifyStore and the final
 * fsynced record both succeed. Other processes read this same record on every
 * inspect(), so their positive in-memory activation cannot bypass a pending
 * revocation. Startup requires fresh trusted control reconciliation.
 */
export class AdmissionAuthority {
  constructor({ directory, scope, wallNow = Date.now, monotonicNow = () => performance.now() }) {
    check(path.isAbsolute(directory), "admission_absolute_directory_required");
    ownedDirectory(directory);
    check(scope && path.isAbsolute(scope.agentDir), "admission_agent_scope_invalid");
    this.directory = fs.realpathSync(directory);
    this.scope = Object.freeze({
      hostId: textField(scope.hostId, "host_id"),
      agentId: textField(scope.agentId, "agent_id"),
      agentDir: path.resolve(scope.agentDir),
      provider: textField(scope.provider, "provider", 128),
    });
    this.scopeDigest = digest(this.scope);
    this.filename = path.join(this.directory, this.scopeDigest + ".json");
    this.lockPath = path.join(this.directory, this.scopeDigest + ".lock");
    this.wallNow = wallNow;
    this.monotonicNow = monotonicNow;
    this.activation = null;
    // Closing admission must not erase time already consumed by a lease.
    // A fresh control read for the same epoch does not mint a new lifetime.
    this.clockWatermark = null;
    this.leaseDeadlineFence = null;
    this.poisoned = false;
  }
  _validate(record) {
    check(record && record.schema === FORMAT && record.scopeDigest === this.scopeDigest &&
      digest(record.scope) === this.scopeDigest, "admission_scope_mismatch");
    check(["pending", "committed", "expired", "unresolved"].includes(record.phase), "admission_phase_invalid");
    check(Number.isSafeInteger(record.revision) && record.revision > 0, "admission_revision_invalid");
    check(typeof record.intentId === "string" && record.intentId.length <= 64, "admission_intent_invalid");
    check(Number.isSafeInteger(record.acceptedEpoch) && record.acceptedEpoch >= -1, "admission_accepted_epoch_invalid");
    check(Number.isSafeInteger(record.observedAt) && record.observedAt >= 0, "admission_observation_time_invalid");
    check(typeof record.authorized === "boolean", "admission_authorized_state_invalid");
    if (record.grant === null) {
      check(record.phase === "unresolved" && record.grantDigest === null && record.acceptedEpoch === -1 && !record.authorized,
        "admission_unresolved_record_invalid");
    } else {
      check(record.grantDigest === digest(normalizeGrant(record.grant)), "admission_grant_digest_mismatch");
      check(record.acceptedEpoch <= record.grant.epoch, "admission_epoch_order_invalid");
      check(!record.authorized || record.phase === "committed" && record.grant.status === "ASSIGNED", "admission_authorized_phase_invalid");
    }
    return record;
  }
  _read({ allowMissing = false } = {}) {
    ownedDirectory(this.directory);
    if (fs.existsSync(this.lockPath)) throw failure("admission_transition_incomplete");
    try { return this._validate(boundedRead(this.filename)); }
    catch (error) { if (allowMissing && error.code === "ENOENT") return null; throw error; }
  }
  _write(record, expected) {
    ownedDirectory(this.directory);
    // Readers refuse this durable marker, including after writer termination.
    fs.mkdirSync(this.lockPath, { mode: 0o700 });
    syncDirectory(this.directory);
    const temporary = path.join(this.lockPath, "record.new");
    let completed = false;
    try {
      let current = null;
      try { current = this._validate(boundedRead(this.filename)); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      check(digest(current) === digest(expected), "admission_record_compare_failed");
      const bytes = Buffer.from(JSON.stringify(record) + "\n");
      check(bytes.length <= MAX_RECORD_BYTES, "admission_record_too_large");
      const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      fs.renameSync(temporary, this.filename);
      syncDirectory(this.directory);
      fs.rmdirSync(this.lockPath);
      syncDirectory(this.directory);
      completed = true;
    } finally {
      // On any uncertainty retain the lock. Never erase another writer's lock.
      if (!completed) this.poisoned = true;
    }
  }
  _close() { this.activation = null; }
  _sampleClocks(record) {
    const wall = this.wallNow(), mono = this.monotonicNow();
    check(Number.isSafeInteger(wall) && wall >= 0 && Number.isFinite(mono), "admission_clock_invalid");
    const previous = this.clockWatermark;
    if (previous && (wall < previous.wall || mono < previous.mono)) {
      this._close();
      if (record?.grant && record.phase !== "expired") {
        this._write({ ...record, phase: "expired", authorized: false, revision: record.revision + 1,
          observedAt: Math.max(record.observedAt, previous.wall, wall) }, record);
      }
      throw failure("admission_clock_rollback");
    }
    this.clockWatermark = { wall, mono };
    return this.clockWatermark;
  }
  _leaseDeadline(grant, grantDigest, { wall, mono }) {
    if (grant.status !== "ASSIGNED") return null;
    let deadlineMono = mono + Math.max(0, grant.expiresAt - wall);
    const previous = this.leaseDeadlineFence;
    if (previous) {
      check(grant.epoch >= previous.epoch, "admission_lower_epoch_rejected");
      if (grant.epoch === previous.epoch) {
        check(grantDigest === previous.grantDigest, "admission_same_epoch_change_rejected");
        deadlineMono = Math.min(deadlineMono, previous.deadlineMono);
      }
    }
    this.leaseDeadlineFence = { epoch: grant.epoch, grantDigest, deadlineMono };
    return deadlineMono;
  }
  _activate(record) {
    const clocks = this._sampleClocks(record), { wall, mono } = clocks;
    if (!record.authorized || record.grant.status !== "ASSIGNED") { this._close(); return; }
    const deadlineMono = this._leaseDeadline(record.grant, record.grantDigest, clocks);
    if (record.grant.expiresAt <= wall || wall < record.observedAt || mono >= deadlineMono) {
      this._close();
      this._write({ ...record, phase: "expired", authorized: false, revision: record.revision + 1,
        observedAt: Math.max(record.observedAt, wall) }, record);
      return;
    }
    this.activation = {
      intentId: record.intentId, grantDigest: record.grantDigest,
      deadlineMono,
      lastMono: mono, lastWall: wall,
    };
  }
  async apply(grantInput, { updateStore, verifyStore, authorize = grantInput?.status === "ASSIGNED" }) {
    check(!this.poisoned, "admission_authority_poisoned");
    check(typeof updateStore === "function" && typeof verifyStore === "function", "admission_store_callbacks_required");
    const grant = normalizeGrant(grantInput);
    check(typeof authorize === "boolean" && (!authorize || grant.status === "ASSIGNED"), "admission_authorize_option_invalid");
    const previous = this._read({ allowMissing: true });
    const clocks = this._sampleClocks(previous), now = clocks.wall;
    if (previous?.grant) {
      check(grant.epoch >= previous.grant.epoch, "admission_lower_epoch_rejected");
      if (grant.epoch === previous.grant.epoch) {
        check(digest(grant) === previous.grantDigest, "admission_same_epoch_change_rejected");
        check(previous.phase !== "expired" || !authorize && grant.expiresAt <= now, "admission_expired_epoch_rejected");
      }
      check(now >= previous.observedAt, "admission_clock_rollback_rejected");
    }
    this._close();
    // Bind the first monotonic deadline before the awaited SDK transaction.
    this._leaseDeadline(grant, digest(grant), clocks);
    const pending = {
      schema: FORMAT, scope: this.scope, scopeDigest: this.scopeDigest,
      phase: "pending", authorized: false, revision: (previous?.revision ?? 0) + 1,
      intentId: crypto.randomUUID(), acceptedEpoch: previous?.acceptedEpoch ?? -1,
      observedAt: now, grant, grantDigest: digest(grant),
    };
    this._write(pending, previous);
    // Deliberately no catch which would restore the previous positive record.
    const result = await updateStore();
    check(await verifyStore(grant, result) === true, "admission_store_verification_failed");
    // Another writer must not be silently overwritten during an awaited SDK op.
    const actual = this._read();
    check(actual.intentId === pending.intentId && actual.phase === "pending" &&
      actual.grantDigest === pending.grantDigest, "admission_pending_ownership_lost");
    const completedClocks = this._sampleClocks(actual);
    const expired = grant.status === "EXPIRED" || grant.status === "ASSIGNED" &&
      (grant.expiresAt <= completedClocks.wall ||
        completedClocks.mono >= this._leaseDeadline(grant, pending.grantDigest, completedClocks));
    const committed = { ...pending, phase: expired ? "expired" : "committed", authorized: authorize && !expired,
      revision: pending.revision + 1, acceptedEpoch: grant.epoch };
    this._write(committed, pending);
    this._activate(committed);
    return result;
  }
  async reconcileCommitted(grantInput, { verifyStore }) {
    check(!this.poisoned, "admission_authority_poisoned");
    check(typeof verifyStore === "function", "admission_store_verifier_required");
    const grant = normalizeGrant(grantInput);
    const record = this._read();
    const clocks = this._sampleClocks(record);
    this._close();
    check(record.phase === "committed" && record.grantDigest === digest(grant), "admission_current_control_mismatch");
    this._leaseDeadline(grant, record.grantDigest, clocks);
    check(await verifyStore(grant) === true, "admission_store_verification_failed");
    const actual = this._read();
    check(digest(actual) === digest(record), "admission_reconciliation_raced");
    this._activate(record);
  }
  closeUnresolved({ expired = false } = {}) {
    this._close();
    const previous = this._read({ allowMissing: true });
    const now = this._sampleClocks(previous).wall;
    const closed = {
      schema: FORMAT, scope: this.scope, scopeDigest: this.scopeDigest,
      phase: expired && previous?.grant ? "expired" : "unresolved", authorized: false,
      revision: (previous?.revision ?? 0) + 1, intentId: crypto.randomUUID(),
      acceptedEpoch: previous?.acceptedEpoch ?? -1, observedAt: Math.max(previous?.observedAt ?? 0, now),
      grant: previous?.grant ?? null, grantDigest: previous?.grantDigest ?? null,
    };
    this._write(closed, previous);
  }
  inspect() {
    try {
      if (this.poisoned) throw failure("admission_authority_poisoned");
      const record = this._read();
      if (record.phase !== "committed") throw failure("admission_not_committed");
      if (!record.authorized) throw failure("admission_not_authorized");
      if (record.grant.status !== "ASSIGNED") throw failure("admission_revoked");
      if (!this.activation || this.activation.intentId !== record.intentId ||
          this.activation.grantDigest !== record.grantDigest) throw failure("admission_fresh_control_required");
      const { wall: now, mono } = this._sampleClocks(record);
      if (now < this.activation.lastWall || mono < this.activation.lastMono) {
        const floor = Math.max(record.observedAt, this.activation.lastWall);
        this._close();
        this._write({ ...record, phase: "expired", authorized: false, revision: record.revision + 1, observedAt: floor }, record);
        throw failure("admission_clock_rollback");
      }
      if (now >= record.grant.expiresAt || mono >= this.activation.deadlineMono) {
        this._close();
        this._write({ ...record, phase: "expired", authorized: false, revision: record.revision + 1,
          observedAt: Math.max(record.observedAt, now) }, record);
        throw failure("admission_expired");
      }
      this.activation.lastWall = now;
      this.activation.lastMono = mono;
      return { allowed: true, epoch: record.grant.epoch, profileId: record.grant.profileId,
        credentialDigest: record.grant.digest, leaseId: record.grant.leaseId, expiresAt: record.grant.expiresAt };
    } catch (error) {
      this._close();
      return { allowed: false, reason: error.diagnosticCode ?? "admission_authority_unavailable" };
    }
  }
  filterCandidates({ store, candidates }) {
    const permit = this.inspect();
    if (!permit.allowed) return [];
    if (!Array.isArray(candidates) || !candidates.includes(permit.profileId) ||
        !store?.profiles?.[permit.profileId] ||
        digest(store.profiles[permit.profileId]) !== permit.credentialDigest) return [];
    return [permit.profileId];
  }
}


