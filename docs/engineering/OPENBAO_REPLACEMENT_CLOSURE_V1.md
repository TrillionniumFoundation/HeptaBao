# OpenBao 2.6.2 complete-replacement closure V1

Status: **current development contract; not replacement, production, migration, or release authority**.

The machine-readable authority boundary is `planning/OPENBAO_REPLACEMENT_ADMISSION_V1.yaml`. This document explains how engineering work closes those gates. A branch name, implementation count, module guide, test fixture, or historical CI run is never a substitute for an admitted gate.

## 1. One candidate, one evidence identity

The candidate is always one exact Git commit. The prospective-main-merge observation is a separate immutable merge object whose parents must be the current main base and that exact candidate. Module evidence uses Git tree identities, not absolute checkout paths. CI receipts are emitted only after their represented commands return successfully and always retain `compatibility`, `production`, `migration`, and `release` authority as false.

The repository may have many development branches. They are inputs to engineering, not additive evidence. A result from another commit can motivate a fix but cannot admit the candidate.

## 2. Storage architecture closure

The current server owns one logical `State`, but local durability now publishes a versioned chunk/manifest representation with a 16 MiB serialized-state bound and 512 KiB chunks. The logical mutation path still serializes the complete state and current HA proposals remain bounded to 768 KiB. The replay ledger is bounded to 32,000 detailed identities per authenticated epoch, with explicit epoch retirement. Chunking, epoch rotation, or raising constants alone is not storage-scale closure.

The storage transition must preserve the existing barrier and crash semantics while moving to record-oriented state. The required order is:

1. Add a durable-service atomic batch mutation primitive in which one request identity binds one deterministic set of resource mutations and advances one durable generation.
2. Add a versioned server-state manifest. Component/chunk resources are immutable for a manifest generation; publication of the manifest is the commit point.
3. Reopen must accept the existing `system/state` representation and the new manifest representation, but it must never merge two partially valid representations by guesswork.
4. Provide an explicit migration that reads the legacy state, validates it, writes the new representation, reopens it, compares a canonical state digest, and only then makes the new manifest authoritative.
5. HA replication must commit the same logical transaction identity and canonical state digest. A leader may not acknowledge a state generation that followers cannot reconstruct after restart.
6. Snapshot, restore, rollback rejection, backup, compaction, and recovery reconciliation must operate on the full logical state rather than on one legacy blob.
7. Exercise a corpus materially larger than the legacy ceiling, including crash between intent/publication/commit, leader loss, follower catch-up, snapshot restore, and rolling restart.

Until all seven properties have executable evidence, `scalable_state_storage` remains OPEN.

## 3. Replay identity lifecycle closure

Journal compaction is not replay-ledger retirement. Ordinary compaction deliberately preserves the current epoch ledger. The runtime now has an authenticated replay-epoch retirement protocol and this candidate carries the epoch in replicated application state; admission still requires exact multi-host execution across retirement, stale retry, snapshot and failover boundaries.

Retirement therefore needs its own protocol. It must prove that an identity retired from the active exact set can never be replayed as a fresh mutation after process restart, snapshot restore, HA leadership change, or stale client retry. An implementation may use epochs, durable high-water marks, immutable retired digests, or another exact scheme, but probabilistic acceptance is forbidden. False negatives would violate idempotency; silently dropping old identities is not permitted.

The admission evidence must include duplicate-before-retirement, duplicate-after-retirement, stale snapshot, restored backup, leader failover, and adversarial boundary tests. Only then may `replay_identity_lifecycle` become ADMITTED.

## 4. Product-surface closure

The frozen comparison corpus contains the product surfaces required for the OpenBao 2.6.2 replacement claim. Each surface is admitted only through the executable server/tool path that users would actually run.

For every surface, the ledger must bind:

- protocol routes, methods, fields, defaults, status codes, error precedence, and list semantics;
- authorization, namespace, token/lease, revocation, and audit effects;
- durable state ownership, restart behavior, HA behavior, backup/restore and upgrade behavior where applicable;
- real external provider behavior for provider-backed capabilities;
- differential observations against the frozen OpenBao 2.6.2 oracle;
- negative, crash, timeout, duplicate, malformed-input, and unavailable-provider cases;
- migration treatment for pre-existing OpenBao assets.

An isolated crate, contract, mock provider, local LDAP record, or limited fixture is useful engineering evidence but cannot set `whole_surface_admitted: true`.

## 5. External providers

Provider-backed features must be exercised against real compatible services. In particular, LDAP replacement requires network connection, TLS validation where configured, bind/search, user DN resolution, group membership, policy mapping, provider errors, timeout behavior, and restart/configuration persistence. The same standard applies to databases, KMS/seal providers, plugins, messaging systems, and other external integrations in the frozen scope.

Provider credentials must not enter receipts, logs, repository files, test names, or debug structures. Tests should record provider type/version and non-secret topology only.

## 6. Full-asset migration

Migration is an inventory problem before it is a copy problem. A rehearsal begins by enumerating the source instance and ends by proving that every in-scope asset has an explicit disposition: migrated, transformed with documented semantics, deliberately unsupported and therefore blocking admission, or verified absent.

The migration gate requires policy, auth mounts and configuration, identity entities and aliases, secret-engine mounts and data, transit/PKI/key versions where in scope, leases and revocation safety, namespaces, audit/storage configuration treatment, application credentials, cutover, rollback, and post-cutover differential validation. Revoked or expired capabilities must not resurrect after migration or rollback.

## 7. Multi-host and upgrade qualification

A production replacement claim requires independent host processes and independent durable directories. Qualification includes clean start, leader loss, standby forwarding, process kill, restart, network partition and heal, snapshot and compaction under load, disk/I/O fault injection, stale node rejoin, rolling upgrade, supported mixed-version windows, and post-fault state comparison.

A single-process in-memory cluster may be a unit test but is not this gate.

## 8. Admission transition

`planning/OPENBAO_REPLACEMENT_ADMISSION_V1.yaml` starts with every required gate OPEN and `replacement_authority: false`. Evidence may close gates one at a time, but the validator intentionally requires an explicit final authority transition after every gate is ADMITTED. This prevents an implementation or generated report from silently turning partial evidence into a product claim.

The final transition must identify the exact release commit and immutable evidence bundle. It should be independently reviewed before merge or release. The validator is a fail-closed repository guard, not the independent reviewer itself.
