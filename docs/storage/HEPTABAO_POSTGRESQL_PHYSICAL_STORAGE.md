# PostgreSQL physical storage implementation

The `heptabao_server::postgres_storage` Rust adapter implements PostgreSQL
physical records and interactive transactions. It is a storage component under
development; `heptabao-server --config` still uses its existing file journal and
Raft state path. There is no PostgreSQL server-storage selector yet. Database
credential issuance in `service_database.rs` and `bootstrap/postgresql/provider.sql`
is a separate subsystem and supplies no evidence for this adapter.

The replacement target includes hierarchical Put/Get/Delete/List/ListPage,
transactions, HA locks and fenced writes, as described by the
[OpenBao PostgreSQL storage documentation](https://openbao.org/docs/configuration/storage/postgresql/)
and the physical-storage interfaces at OpenBao 2.6.2 source revision
`dd9c19c37a878cf4a81b18efb8d6f0599c7da923`. The current adapter does not read,
modify or claim compatibility with existing `openbao_kv_store` tables.

## Data and trust boundary

Physical values are opaque bytes. The caller must authenticate and encrypt
application records before sending them to this adapter, and verify the returned
bytes through the barrier. Database transport encryption does not provide
at-rest encryption or protection from a database administrator. The adapter
keeps an explicit scope in each record key; it does not create an HTTP namespace
authority or let API callers select storage scopes.

Deployment configuration pins the PostgreSQL socket address, CA, TLS server
name, database and credentials. The adapter uses mandatory verified TLS and
SCRAM-SHA-256. It does not use ambient PostgreSQL environment variables or retry
unknown writes. Statements and identifiers are internal constants; record keys
and values are protocol parameters. Binary values use PostgreSQL BYTEA with a
hexadecimal transport encoding.

This first adapter bounds one value to 1 MiB, a key to 512 UTF-8 bytes,
one page to 256 child names and one configured client's connections to 16.
Clones share that connection budget. Text keys use the explicit PostgreSQL
`C` collation, so locale settings cannot alter uniqueness or cursor order.
The fixed schema checks its column types, primary-key columns and validated
format/revision constraints before use. It rejects unlogged tables and row-level
security policies that would change the physical-store contract. It has no unused logical-namespace
selector; logical namespaces remain part of the caller's authenticated data.
The value bound accommodates the server's 768 KiB owner chunks plus encryption
framing. Parameters/results allow their 2 MiB hex representation, with a 4 MiB
frame and aggregate result limit. Provider scalar queries keep their existing
smaller SQL, parameter and scalar-result limits.

## Transactions and failure behavior

Each interactive transaction owns its PostgreSQL connection. Repeatable Read
provides a consistent transaction view and rejects conflicting concurrent
updates. Read-only handles reject writes locally. Commit waits for a completed
PostgreSQL command and an idle ReadyForQuery; malformed, truncated or missing
replies cannot report a successful commit. A lost commit reply returns
`StorageError::OutcomeUnknown` and must not trigger a blind retry. Dropping an unfinished
transaction closes its connection so PostgreSQL rolls it back.

The transport bounds parameters, frame sizes, row counts and aggregate result
bytes. Connections retain a three-second absolute deadline, including TLS and
authentication; each statement also has PostgreSQL statement and lock timeouts.
Connections explicitly request `synchronous_commit=on`; the database must still
be operated with durable WAL and storage settings such as `fsync=on`.
Queries cannot extend this deadline by sending fragments. This limits the
initial transaction profile; larger migrations must use bounded transactions
with explicit progress and recovery.

## Executable validation

`qa/openbao-acceptance/postgres_storage_live.py` creates a fresh PostgreSQL 17
cluster, a non-superuser storage owner and test TLS material. It drives the
compiled Rust `postgres_storage_probe` example through private stdin, then kills
and restarts the client and database. The fixture records only case IDs, build
and source bindings, and outcomes; passwords and physical record values are
not receipt fields. It never accepts an existing PostgreSQL data directory.
An additional transparent TCP proxy forwards the verified TLS connection, then
drops only the commit response. Independent SQL readback checks whether the
record committed while the Rust caller reports the outcome as unknown.

Build and run inside an isolated Linux environment:

```sh
cargo +1.98.0 build --locked -p heptabao-server --example postgres_storage_probe
python3 qa/openbao-acceptance/postgres_storage_live.py \
  --probe "$CARGO_TARGET_DIR/debug/examples/postgres_storage_probe" \
  --postgres-bin /usr/lib/postgresql/17/bin \
  --work-dir /absolute/new-private-fixture-directory \
  --output /absolute/new-receipt.json
```

The current replacement CI lane owns this real PostgreSQL fixture alongside
the distinct dynamic-credential provider fixture. Missing PostgreSQL is a
blocking prerequisite failure, not a passing simulated test.

The [recorded PostgreSQL 17.11 run](../../qa/openbao-acceptance/evidence/postgresql-storage-live-d782284.json)
passed all 52 checks on clean source `d7822841edf74cd3c5abb0ef9378381dc3d44068`,
including 1 MiB records, conflicting transactions, lost commit replies,
schema faults and process/database crash recovery. This qualifies the component
within the limits above; the server integration below remains open.

## Remaining integration and acceptance

The next integration must adapt the journal, sealed owner records and recovery
frontiers to transactional physical storage and select it explicitly during
server startup. It must preserve existing barrier, audit, replay and snapshot
invariants. The existing `DurableGenerationStore` whole-state contract cannot
be substituted for the physical key/value and transaction interface.

Automatic HA lock renewal/loss notification, service write fencing, larger
record support, format migration, application reconciliation after a lost commit
response, multi-host partitions, database disk
and power faults, supported-version coverage and independent reproduction
remain required. This fixture alone grants no complete OpenBao compatibility,
server migration or production qualification.
