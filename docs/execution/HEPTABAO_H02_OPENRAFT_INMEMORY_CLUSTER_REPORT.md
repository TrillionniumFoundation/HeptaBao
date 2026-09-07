# HeptaBao H02 OpenRaft In-Memory Cluster Execution Report

Status: `IMPLEMENTED / REMOTE UNEXECUTED / NOT QUALIFIED`  
Plan: `HEPTABAO-PLAN-2026-08-28` revision `1.1`

## 1. Source binding

```text
Repository:            ProfHepta/HeptaBao
Branch:                codex/h02-openraft-inmemory-cluster-v1
Stack base:            codex/h02-candidate-adapters-v1
Implementation commit: cdc6b1155a26d300bd8914764dba880bb1fb902e
Implementation tree:   1053a24a04115ece151d4cfcecf36ff47c7526c3
Candidate:             OpenRaft 0.10.0-alpha.33
Candidate state:       IDENTIFIED
Qualification:         false
Selection effect:      NONE
Authority effect:      NONE
```

## 2. Delivered implementation

The previous OpenRaft candidate adapter only exercised configuration and HeptaBao-owned failure-model guards. This slice adds a real three-node OpenRaft cluster inside an isolated probe workspace.

### 2.1 Real OpenRaft objects

- three `Raft<TypeConfig, Arc<MemStateMachine>>` instances;
- exact `openraft = 0.10.0-alpha.33`;
- exact `openraft-memstore = 0.10.0-alpha.33`;
- exact `tokio = 1.53.1`;
- one HeptaBao-owned in-process `RaftNetworkFactory`/`RaftNetworkV2` implementation;
- real OpenRaft log storage and state machine using the upstream-published test memstore;
- no OpenRaft or memstore dependency in the HeptaBao core workspace.

### 2.2 Protocol path

The in-process network forwards actual candidate protocol messages:

```text
AppendEntries
PreVote
Vote
FullSnapshot
```

The router supports deterministic link isolation, transport pause/resume, healing and per-RPC counters. The implementation does not copy an upstream network implementation.

### 2.3 Cluster lifecycle

The probe performs:

```text
start node 1
→ initialize node 1 as the only voter
→ start nodes 2 and 3
→ add nodes 2 and 3 as blocking learners
→ execute OpenRaft joint-to-uniform membership change
→ wait for exact voters {1,2,3}
```

It then executes actual `client_write`, `ReadIndex`, membership, snapshot and failure paths.

## 3. Seeded candidate cases

### `raft-deterministic-apply-and-restart`

- commits seeded requests through `client_write`;
- waits for all three nodes to apply the committed index;
- shuts down a follower;
- retains its log store but replaces its state machine with a fresh one;
- restarts the candidate node and waits for committed-log replay;
- compares application state after reconstruction.

### `raft-committed-snapshot-conflict-rejected`

The implemented candidate scope is intentionally narrower than the case name:

- isolates a follower;
- commits enough writes to trigger snapshot construction;
- invokes the actual snapshot trigger;
- heals the network;
- requires an observed `full_snapshot` RPC;
- requires monotonic committed index and state convergence.

A deliberately conflicting snapshot is **not** injected into the OpenRaft core because the candidate API documents inconsistent local committed-state input as a panic condition. That hostile path remains an explicit promotion blocker and must later run in an isolated subprocess/fault harness.

### `raft-joint-membership-single-writer`

- executes real learner addition and membership change;
- requires all nodes to report voters `{1,2,3}`;
- requires one reported leader;
- executes `ensure_linearizable(ReadPolicy::ReadIndex)`.

### `raft-process-pause-plus-partition`

- transport-pauses and isolates the original leader;
- waits for a leader among the remaining majority;
- bounds an old-leader write attempt;
- requires old-leader rejection or timeout;
- requires the new leader to commit a write.

This is a transport-level pause, not an operating-system process suspension. OS scheduling pause remains a blocker.

### `raft-quorum-loss-fail-closed`

- records the leader committed index;
- isolates the active leader from both followers;
- bounds a candidate write attempt;
- requires rejection or timeout;
- requires the local committed index not to advance.

### `raft-incomplete-run-replay-diagnostics`

- derives a deterministic fault plan with `SplitMix64`;
- binds the exact 64-bit seed;
- records a last-event index;
- records actual protocol RPC counts;
- executes the full binary twice and requires canonical same-seed output equality.

## 4. Evidence semantics

Every execution produces candidate-bound evidence with:

```text
candidate = HB-DEP-RAFT-OPENRAFT
version = 0.10.0-alpha.33
real_raft_nodes = 3
durability_class = TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM
review_status = PENDING
qualification = false
selection_effect = NONE
promotion_effect = BLOCK_PENDING_DURABLE_STORE_AND_HOSTILE_FAULTS
authority_effect = NONE
```

An `EXECUTED_PASS` requires:

- all six cases `PASS`;
- zero failed, blocked, unexecuted or unknown cases;
- exact same-seed replay;
- clean source tree;
- a real observed full-snapshot RPC;
- exact manifest and lockfile digests.

A pass still cannot select OpenRaft because the storage is test-only and hostile durability/distributed-fault evidence is incomplete.

## 5. Local validation

The current local container has Python 3.13 but no Rust toolchain.

Executed locally:

```text
semantic plan/source/workflow validator: PASS
Python evidence and negative tests:       9/9 PASS
Python syntax compilation:                PASS
Rust candidate compilation:               UNEXECUTED
OpenRaft three-node cluster execution:     UNEXECUTED
```

The nine negative tests cover:

- complete replay remains promotion-blocked;
- replay mismatch;
- non-zero candidate exit;
- candidate case failure;
- missing required case;
- candidate metadata mismatch;
- false PASS with unknown result;
- false operational authority;
- false snapshot PASS without observed full-snapshot RPC.

Local results are unattested and have no qualification effect.

## 6. Remote execution observation

The implementation commit triggered:

```text
Workflow:    h02-openraft-inmemory-cluster
Run ID:      33170620788
Job ID:      98846599620
Head SHA:    cdc6b1155a26d300bd8914764dba880bb1fb902e
Job:         validate-plan
Status:      queued
Conclusion:  null
Runner ID:   null
Runner name: null
Steps:       []
```

Classification:

```text
INFRASTRUCTURE_UNEXECUTED
```

No Python validator, Rust compiler or OpenRaft cluster case ran remotely. This is neither passing evidence nor a code-test failure.

## 7. Remaining promotion blockers

1. Execute the two toolchains and three fixed seeds on an attested runner.
2. Preserve and repair any actual compilation/API/runtime failure.
3. Bind numeric runner and job identities through trusted post-run enrichment.
4. Reproduce the exact matrix in a second independent attested environment.
5. Add hostile snapshot injection in an isolated crash-safe harness.
6. Add operating-system process pause, disk stall, torn-write, corruption and clock-fault tests.
7. Produce an external linearizability history and checker result.
8. Select and qualify a separate production durable storage implementation.
9. Complete package byte, locked graph, SBOM, advisory, license, unsafe/native/build-script and effective-MSRV reviews.
10. Obtain independent distributed-systems, platform and security approvals.

OpenRaft remains `IDENTIFIED`. No prototype selection, production dependency, Raft implementation, compatibility, production, migration or release authority is granted.
