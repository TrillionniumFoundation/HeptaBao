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
manifest is updated last; readers load all chunks and lengths from one
transaction and reject gaps, duplicate chunk numbers, length mismatches, or
oversized data.

Opening a backend takes a scope-specific PostgreSQL session advisory fence via
`pg_try_advisory_lock`. A second writer receives `WriterLocked` immediately.
Every operation begins a repeatable-read transaction and verifies that the
same session still owns the advisory lock through `pg_locks`. Connection or
commit acknowledgement loss poisons the backend and returns
`OutcomeUnknown`; it never reconnects or retries a write. A fresh backend must
be opened and the durable service must run its normal authenticated replay
recovery before mutation resumes.

`initialize` is the only operation that creates the fixed schema. It runs DDL
and strict relation, column, collation, nullability, primary-key, constraint,
RLS, and persistence checks in one transaction. `open` performs the same
checks without creating or migrating objects. This keeps schema ownership
explicit and makes malformed, unlogged, partitioned, or altered tables fail
closed.

The backend currently rewrites the journal chunks for an append inside its
single transaction. This preserves the crash and stale-writer contract but is
an O(n) physical path; an optimization can update only the final chunk and
append new chunks after profiling. The optional `postgres_durable` object in
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
