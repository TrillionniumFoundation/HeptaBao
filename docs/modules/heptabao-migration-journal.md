# heptabao-migration-journal

Package: `heptabao-migration-journal`

Source: `crates/heptabao-migration-journal`

## Purpose and boundaries

Provides an authenticated, append-only migration transaction state machine. It does not itself claim full OpenBao object coverage or production migration authority.

## Public API and ownership

`MigrationJournal` owns durable phase transitions; `MigrationObjectId`, `MigrationRecord`, and `ReconciliationProof` are the public contracts.

## State and data model

Records bind sequence, operation ID, object ID, source and target digests, phase, previous tag, and HMAC tag.

## Invariants and authorization

One writer is admitted per journal root. Commit after an uncertain outcome requires a matching target digest reconciliation proof.

## Failure, retry and reconciliation

Torn tails are truncated only after the authenticated prefix is verified. HMAC or chain failures are rejected. Exact duplicate begin requests are idempotent.

## Concurrency model

A create-new owner-private lock serializes writers. Readers are reconstructed from the authenticated journal under that lock.

## Security considerations

Roots reject symlink traversal and permissive Unix modes. Journal records form an HMAC chain and the in-memory key is overwritten on drop.

## Persistence and compatibility

The binary `HBMJ1` format is versioned and bounded. Format migration requires a future explicit decoder rather than silent reinterpretation.

## Observability

Typed phases and errors distinguish invalid transitions, writer contention, tampering, I/O failure, and outcome-unknown writes.

## Operations

Operators must preserve the journal and key together, resolve stale locks through an audited recovery procedure, and reconcile pending commits before retry.

## Tests and evidence

Tests cover restart recovery, reconciliation, torn-tail repair, authenticated corruption, single-writer exclusion, invalid transitions, rollback, and idempotency.

## Evolution and open boundaries

Adapters for every OpenBao mount, auth, identity, policy, lease, audit, and key format remain separate work. Independent cutover and rollback evidence is still required.

The writer lock is RAII-owned, so failed open or recovery cannot strand a lock. Existing journal files are admitted only when they are non-symlink regular files with owner-private Unix permissions.
