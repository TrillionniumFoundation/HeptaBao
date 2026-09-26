# PostgreSQL durable-service backend

`heptabao-server::postgres_durable::PostgresDurableBackend` stores the
durable service's already sealed `snapshot`, `ledger`, and `journal` bytes in
the deployment-owned `heptabao_durable_v1` schema. It does not reuse
`heptabao_storage_v1.records_v1`, provider tables, or logical key/value
operations.

The schema has a `manifest_v1` row per scope and `chunks_v1` rows keyed by
`(scope, artifact, chunk_no)`. Each artifact is bounded to 64 MiB and split
into 768 KiB chunks so a hex encoded parameter remains under the PostgreSQL
wire client's parameter limit. A checkpoint deletes and inserts chunks and
advances the manifest revision in one repeatable-read transaction. The
manifest is updated last. Readers first validate the bounded chunk layout,
then load at most two chunks per query within the same repeatable-read
transaction. Two hex-encoded chunks occupy at most 3 MiB, below the wire
client's unchanged 4 MiB aggregate result limit. This permits artifacts above
2 MiB without raising parser memory bounds. Readers reject gaps, extra chunks,
non-full interior chunks, incorrect tail lengths, and chunk revisions newer
than the manifest. Full sealed-artifact authentication remains the durable
service's responsibility.

Opening a backend takes a scope-specific PostgreSQL session advisory fence via
`pg_try_advisory_lock`. A second writer receives `WriterLocked` immediately.
Every operation begins a repeatable-read transaction and verifies that the
same session still owns the advisory lock through `pg_locks`. Connection or
commit acknowledgement loss poisons the backend and returns
`OutcomeUnknown`; it never reconnects or retries a write. A fresh backend must
be opened and the durable service must run its normal authenticated replay
recovery before mutation resumes.

A persistent PostgreSQL session starts a fresh absolute operation deadline only
at an idle, usable `BEGIN` boundary; no query, page, frame, commit or rollback
renews it. The budget is 3 seconds plus one second per started 8 MiB of expected
hex-encoded transfer. Validated sizes cap it at 768 MiB (the largest full
read-and-replace checkpoint), or 99 seconds. Small metadata-only transactions
retain 3 seconds. An append budgets only its frame and at most one partial tail;
it does not gain time proportional to the untouched journal. A full load first
reads bounded manifest lengths in a short planning transaction, then verifies
that manifest is unchanged and reads every artifact in a second, appropriately
budgeted repeatable-read transaction. The same session writer fence spans both.
A poisoned session cannot start a new budget or recover itself after an unknown
commit. This fixes idle-session expiry without allowing slow peers to extend a
transaction indefinitely. Server statement and lock timeouts remain unchanged.

`initialize` is the only operation that creates the fixed schema. It runs DDL
and strict relation, column, collation, nullability, primary-key, constraint,
RLS, and persistence checks in one transaction. `open` performs the same
checks without creating or migrating objects. This keeps schema ownership
explicit and makes malformed, unlogged, partitioned, or altered tables fail
closed.

Journal append reads bounded layout metadata for all three artifacts, then
reads and updates only a partial journal tail and inserts any new chunks. Full
prefix chunks, snapshot and ledger payloads are not read or rewritten. The
manifest length and revision advance by compare-and-swap in that same fenced
transaction. Payload transfer and mutation are O(chunk size + frame size),
while layout inspection is O(number of chunks); memory for the append excludes
the preexisting full journal. Checkpoint and truncation still compare and
replace complete artifacts, using bounded pages for their reads. Unknown
commit outcomes still poison the session and require reopening and replay.

The optional `postgres_durable` object in
the server JSON configuration selects this backend for initialization and
reopen through `Service::install_postgres_durable_storage`. Its fields are
`endpoint`, `connection_url`, `username`, `password`, and `scope`, matching
`PgStorageConfig`. The enrolled endpoint contains the pinned address, TLS
server name, CA PEM and allowed path prefix; it cannot be changed through HTTP.
Omitting the configuration selects filesystem storage only for a new or
existing filesystem deployment. A PostgreSQL profile refuses unseal when its
matching configuration is absent or changed, as described in
[the profile contract](HEPTABAO_DURABLE_BACKEND_PROFILE.md).

The server integration does not establish HA, migration, full OpenBao
compatibility or production qualification. Local seal metadata and audit files
remain required even when encrypted application artifacts reside in PostgreSQL.
