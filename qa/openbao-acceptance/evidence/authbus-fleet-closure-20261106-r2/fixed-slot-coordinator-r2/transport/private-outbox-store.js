import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export class OutboxError extends Error {
  constructor(code, { unknown = false, backpressure = false } = {}) {
    super(code); this.name = "OutboxError"; this.unknown = unknown; this.backpressure = backpressure;
  }
}

function check(ok, code) { if (!ok) throw new OutboxError(code); }
function privateUmask(fn) {
  const previous = process.umask(0o077);
  try { return fn(); } finally { process.umask(previous); }
}
function syncDirectory(dir) {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function privateFile(file, absent = false) {
  let info;
  try { info = fs.lstatSync(file); } catch (error) { if (absent && error.code === "ENOENT") return; throw new OutboxError("outbox_file_unavailable"); }
  check(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
    && (info.mode & 0o777) === 0o600 && info.nlink === 1, "outbox_file_custody");
}
function privateDirectory(dir, create = false) {
  if (create && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { mode: 0o700 });
    syncDirectory(dir); syncDirectory(path.dirname(dir));
  }
  const info = fs.lstatSync(dir);
  check(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid()
    && (info.mode & 0o777) === 0o700 && fs.realpathSync(dir) === dir, "outbox_directory_custody");
}

/** Two small private databases: an OS-released transaction lock and state.
 * The lock transaction spans awaited network I/O, while state commits are
 * independently FULL synchronous before dispatch. A crash releases the lock
 * without rolling back a previously committed operation intent. No PID-file
 * lease, stale-lock deletion, or timestamp-based lock takeover is used.
 *
 * State uses WAL/FULL: every existing CAS remains a durable commit, including
 * bearer clock observations. Only the journal implementation changes. The
 * lock database stays in DELETE mode and never contains credential payloads.
 * A backup must copy the complete quiescent directory (including any WAL and
 * SHM files), or use SQLite's backup API. A main-file-only copy is not valid.
 */
export class PrivateOutboxStore {
  #state; #lock; #directory; #held = false; #closed = false; #identities = new Map();
  constructor(directory, binding) {
    check(path.isAbsolute(directory) && path.resolve(directory) === directory, "outbox_absolute_directory");
    privateDirectory(path.dirname(directory));
    privateDirectory(directory, true); this.#directory = directory;
    const statePath = path.join(directory, "state.sqlite");
    const lockPath = path.join(directory, "operation.sqlite");
    for (const base of [statePath, lockPath]) {
      privateFile(base, true);
      for (const suffix of ["-journal", "-wal", "-shm"]) privateFile(base + suffix, true);
      if (!fs.existsSync(base)) {
        const fd = fs.openSync(base, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
        fs.fsyncSync(fd); fs.closeSync(fd);
        syncDirectory(directory);
      }
    }
    for (const file of [directory, statePath, lockPath]) {
      const info = fs.lstatSync(file); this.#identities.set(file, { dev: info.dev, ino: info.ino });
    }
    try {
      privateUmask(() => {
        this.#state = new DatabaseSync(statePath);
        this.#lock = new DatabaseSync(lockPath);
        this.#state.exec("PRAGMA busy_timeout=0; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=2097152; PRAGMA secure_delete=ON; PRAGMA max_page_count=16384;");
        check(this.#state.prepare("PRAGMA journal_mode").get().journal_mode === "wal"
          && this.#state.prepare("PRAGMA synchronous").get().synchronous === 2,
        "outbox_durable_journal_configuration");
        this.#lock.exec("PRAGMA busy_timeout=0; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=16;");
        this.#state.exec("CREATE TABLE IF NOT EXISTS records (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL)");
        this.#lock.exec("CREATE TABLE IF NOT EXISTS operation_lock (id INTEGER PRIMARY KEY)");
      });
      const old = this.get("binding");
      if (old === null) this.cas("binding", 0, binding);
      else check(JSON.stringify(old.value) === JSON.stringify(binding), "outbox_deployment_binding_changed");
      this.#checkFiles();
    } catch (error) {
      this.#state?.close(); this.#lock?.close();
      if (error instanceof OutboxError) throw error;
      throw new OutboxError("outbox_database_initialization_failed");
    }
  }
  #checkFiles() {
    privateDirectory(this.#directory);
    for (const [file, original] of this.#identities) {
      const actual = fs.lstatSync(file);
      check(actual.dev === original.dev && actual.ino === original.ino, "outbox_open_file_replaced");
    }
    for (const name of ["state.sqlite", "operation.sqlite"]) {
      const file = path.join(this.#directory, name); privateFile(file);
      check(fs.statSync(file).size <= (name === "state.sqlite" ? 64 * 1024 * 1024 : 65536), "outbox_database_bound");
      for (const suffix of ["-journal", "-wal", "-shm"]) privateFile(file + suffix, true);
    }
  }
  get(name) {
    check(!this.#closed && typeof name === "string" && /^[a-z0-9:._-]{1,160}$/.test(name), "outbox_record_name");
    this.#checkFiles();
    try {
      const row = this.#state.prepare("SELECT value, revision FROM records WHERE name = ?").get(name);
      if (!row) return null;
      check(Number.isSafeInteger(row.revision) && row.revision > 0 && Buffer.byteLength(row.value) <= 192 * 1024, "outbox_record_bound");
      return { revision: row.revision, value: JSON.parse(row.value) };
    } catch (error) { if (error instanceof OutboxError) throw error; throw new OutboxError("outbox_record_read_failed"); }
  }
  cas(name, expectedRevision, value) {
    this.#checkFiles();
    check(Number.isSafeInteger(expectedRevision) && expectedRevision >= 0, "outbox_local_cas_shape");
    const encoded = JSON.stringify(value);
    check(Buffer.byteLength(encoded) <= 192 * 1024, "outbox_record_bound");
    try {
      return privateUmask(() => {
        this.#state.exec("BEGIN IMMEDIATE");
        try {
          const old = this.get(name);
          check((old?.revision ?? 0) === expectedRevision, "outbox_local_cas_conflict");
          const count = Number(this.#state.prepare("SELECT COUNT(*) AS n FROM records").get().n);
          check(old !== null || count < 168, "outbox_record_count_bound");
          const next = expectedRevision + 1;
          check(Number.isSafeInteger(next), "outbox_local_revision_exhausted");
          this.#state.prepare("INSERT INTO records(name,value,revision) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value,revision=excluded.revision")
            .run(name, encoded, next);
          this.#state.exec("COMMIT"); this.#checkFiles(); return next;
        } catch (error) { try { this.#state.exec("ROLLBACK"); } catch {} throw error; }
      });
    } catch (error) { if (error instanceof OutboxError) throw error; throw new OutboxError("outbox_record_commit_failed"); }
  }
  put(name, value) { const row = this.get(name); return this.cas(name, row?.revision ?? 0, value); }
  loadAuth() { const row = this.get("auth"); return row ?? { revision: 0, value: null }; }
  saveAuth(expectedRevision, value) { return this.cas("auth", expectedRevision, value); }
  assertCustody() { check(!this.#closed, "outbox_store_closed"); this.#checkFiles(); }
  async withLock(fn) {
    check(!this.#held && !this.#closed, "outbox_in_process_operation_busy");
    this.#checkFiles();
    try { privateUmask(() => this.#lock.exec("BEGIN IMMEDIATE")); }
    catch { throw new OutboxError("outbox_other_process_operation_busy"); }
    this.#held = true;
    try { this.#checkFiles(); return await fn(); }
    finally {
      try { privateUmask(() => this.#lock.exec("ROLLBACK")); }
      finally { this.#held = false; this.#checkFiles(); }
    }
  }
  close() {
    check(!this.#held, "outbox_close_with_operation_pending");
    if (this.#closed) return;
    this.#state.close(); this.#lock.close(); this.#closed = true;
  }
}

export function productionStateDirectory(stateDir) {
  check(path.isAbsolute(stateDir) && fs.realpathSync(stateDir) === stateDir, "state_directory_alias");
  const authbus = path.join(stateDir, "authbus"); privateDirectory(authbus, true);
  return path.join(authbus, "production-transport");
}
