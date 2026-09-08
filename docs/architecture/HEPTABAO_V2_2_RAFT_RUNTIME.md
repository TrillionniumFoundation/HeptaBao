# HeptaBao V2.2 durable Raft runtime vertical slice

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

## Activation gap

Production activation still requires:

```text
mTLS peer identity and certificate rotation
+ authorized join/promote/remove protocols
+ bounded network framing and backpressure
+ server leader forwarding and redirect semantics
+ three independent operating-system processes/hosts
+ rolling upgrade and snapshot transfer
+ destructive partition/quorum/power-loss qualification
+ independent linearizability observation
```

Until those gates pass, `HB-V2-REP-013` remains `IMPLEMENTATION_IN_PROGRESS` even though the repository-owned consensus core is implemented and reviewable.
