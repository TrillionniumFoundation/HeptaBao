# HeptaBao V2.2 durable Raft runtime vertical slice

> Scope: this retained increment describes its named library composition and tests. It is not the complete current HTTP server assembly. See [current runtime architecture](HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md) for the concrete server, private authentication boundary and per-process HA integration.

Status: repository implementation under exact-head review. Authority effect: none.

## Scope

`heptabao-raft-runtime` converts the earlier OpenRaft experiment into a workspace-owned, documented and continuously compiled consensus component. The public boundary accepts only a bounded opaque Barrier-sealed envelope. The implementation owns persistent vote/log/membership/state-machine/snapshot data and exposes committed-write receipts plus an explicit ReadIndex barrier.

This slice proves consensus and durable recovery semantics in one process with three independent Raft instances and three independent durable stores. The deterministic router is an executable fault-injection transport, not the future production peer network.

## Mandatory write path

```text
upstream authenticated/authorized/audited operation
→ immutable sealed ReplicatedEnvelope
→ current leader resolution
→ OpenRaft client write with stable serial
→ quorum replication and commitment
→ state-machine apply
→ all-voter convergence evidence
→ CommitReceipt
```

The receipt is not a secret-use grant and does not imply result delivery. A lost result after consensus entry remains an uncertain caller outcome even when the durable operation later reconciles as committed.

## Linearizable read boundary

A future server read must resolve the current leader and complete OpenRaft `ReadIndex` before reading its local state-machine projection. A follower cache, heartbeat observation or previous leader ID cannot substitute for this barrier. ReadIndex failure during quorum loss fails closed.

## Durable ownership

Each node owns one log store and one state-machine store. The formats use strict magic, exact length and CRC validation. Atomic replacement preserves one predecessor until the new generation has been published and parent-synced. Reopen rejects ambiguous histories, missing post-initialization generations and symlink substitution. Application entries are already encrypted; Raft metadata is not treated as secret material.

## Fault model

The qualification router can isolate and pause a node, then heal the topology. The package proves an isolated former leader cannot advance its committed index. The store suite covers truncation, corruption, interrupted replacement, stale predecessor cleanup, unexpected directory occupants and replacement attacks. Cross-process power loss, disk-full, network TLS, Byzantine peers and correlated-host failure remain separate gates.

## Repository implementation closure and external admission

The repository-controlled product path now contains pinned mTLS peer identity, bounded
same-CA leaf overlap rotation with old-pin retirement, authorized membership
transitions, bounded peer framing/backpressure, server leader forwarding, ReadIndex
reads, three independent local operating-system processes, snapshot catch-up,
quorum/partition faults and exact-base-to-candidate rolling upgrade fixtures. Those
fixtures are mandatory exact-source gates; they are scoped evidence, not production
authority.

HB-V2-REP-013 is therefore implementation-complete and review-required. Production
admission still requires independently controlled multi-host execution, CA/trust-root
rotation and revocation, HSM/KMS custody, real power-loss/disk-full campaigns,
longitudinal concurrent-history observation and independent reproduction. Repository
CI must not convert those external facts into self-issued qualification.
