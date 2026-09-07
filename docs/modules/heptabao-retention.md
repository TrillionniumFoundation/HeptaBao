# heptabao-retention

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns retention-policy validation, compaction counts and a backup lifecycle contract. It does not read storage, encrypt archives or perform offsite transfer.

## Public API and ownership

`RetentionPolicy` owns bounded version, audit and schedule limits. `BackupCoordinator` owns one backup state machine and its latest receipt.

## State and data model

Backup state moves through idle, snapshotting, sealed and verified, with a failed branch. Each sealed receipt binds source generation, start tick and nonzero digest.

## Invariants and authorization

Zero limits and a restore-drill interval shorter than the backup interval are rejected. Verification requires an exact digest match.

## Failure, retry and reconciliation

A failed snapshot may begin again under a new operation. Digest mismatch moves the coordinator to failed and requires investigation rather than silent acceptance.

## Concurrency and ordering

The coordinator has one owner and no interior lock. Storage snapshotting must bind a stable source generation before `seal` is called.

## Security and privacy

Receipts contain digests and generations, never plaintext secrets. Digest presence is integrity metadata and does not prove encryption or custody.

## Persistence and compatibility

No archive format exists. Production backup formats need versioned manifests, encryption, key custody, retention deletion evidence and restore compatibility.

## Observability

Recommended events are `backup.started`, `backup.sealed`, `backup.verified` and `backup.failed`, with bounded outcome and state labels.

## Operations

Operators must schedule backup and restore drills separately. A successful snapshot without readback and restore validation is not a qualified backup.

## Tests and executable evidence

`cargo test -p heptabao-retention` covers policy validation, prune planning and backup transition/digest enforcement.

## Evolution and open boundaries

Offsite custody, WORM retention, compaction execution, legal hold and destructive restore drills remain environment and operator work.
