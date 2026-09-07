# H02 OpenRaft hostile snapshot and external linearizability implementation report

## Binding

```text
plan_id:              HEPTABAO-PLAN-2026-08-28
revision:             1.2
parent branch:        codex/h02-openraft-inmemory-cluster-v1
parent PR:            #22
active branch:        codex/h02-openraft-hostile-faults-linearizability-v1
implementation commit:66a7f888944d1ae74129edaacc03660e69986f81
implementation tree:  8930306e005361b30ecddf3eb7f701dccefed0f2
candidate:             openraft 0.10.0-alpha.33
profile:               HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33
```

This slice is a stacked development layer. It is not retargeted to `main`, grants no selection or production authority, and does not change the parent H02 qualification state.

## What was implemented

The isolated probe workspace now contains a third binary, `heptabao-h02-openraft-fault-lab`, with three execution modes:

1. `hostile-snapshot-parent` starts the same exact executable as an isolated child, applies a bounded deadline, captures stdout/stderr, requires an explicit pre-injection phase marker, and classifies the child without allowing an unrelated pre-injection crash to pass.
2. `hostile-snapshot-child` builds a real three-voter OpenRaft cluster, commits an older value plus six later writes, creates a real snapshot, changes only `snapshot.meta.last_log_id` to the older committed log id, flushes `ABOUT_TO_INSTALL_STALE_COMMITTED_SNAPSHOT`, and calls the target node's real `Raft::install_full_snapshot` API.
3. `linearizability-history` executes two overlapping real `client_write` calls, one overlapping `ReadIndex` read and one final `ReadIndex` read, retaining invocation/completion sequence numbers and candidate RPC counters.

The safety classification is deliberately narrow:

```text
EXECUTED_PASS = explicit rejection after the phase marker,
                or isolated process fatality only after the marker
EXECUTED_FAIL = candidate accepts the stale committed snapshot
BLOCKED       = no marker, timeout, spawn failure, malformed output,
                or any unrecognized execution state
```

A process-fatal rejection is never represented as an availability, durability or production pass.

## Independent linearizability checker

`scripts/h02_linearizability_checker_v1.py` is separate from the Rust candidate process. It checks the exported history against a bounded single-register model:

```text
maximum operations: 64
real-time edge:      A.complete < B.invoke implies A before B
write transition:   register := input
read transition:    output must equal current register
algorithm:           real-time-precedence constrained backtracking
```

Failed, unknown, duplicate, malformed or unsupported operations block checking rather than being dropped. A well-formed history without a legal witness is `EXECUTED_FAIL`; malformed or incomplete input is `BLOCKED`.

## Fail-closed evidence chain

The layer adds four Draft 2020-12 JSON Schemas and a combined collector. The collector binds:

- exact candidate/version/profile/seed;
- source repository, branch, commit, tree and clean-tree state;
- manifest and generated `Cargo.lock` digests;
- hostile result and exit code;
- raw history and canonical history digest;
- checker result and checker exit code;
- toolchain, target and executor identity.

A technical `EXECUTED_PASS` requires both hostile-snapshot safety and external linearizability to pass. Even then the evidence remains:

```text
qualification=false
selection_effect=NONE
promotion_effect=BLOCK_PENDING_DURABLE_STORE_OS_DISK_CLOCK_AND_INDEPENDENT_REPRODUCTION
authority_effect=NONE
```

## Local validation

The locally executable layer was run after the CI fail-preservation correction:

```text
semantic validator:             PASS
JSON Schema meta-validation:    PASS
linearizability checker tests:  13 / 13 PASS
combined evidence tests:        14 / 14 PASS
total Python tests:             27 / 27 PASS
Python syntax:                  PASS
Rust compile:                   UNEXECUTED
hostile snapshot execution:     UNEXECUTED
real history generation:        UNEXECUTED
```

The local container has no Rust toolchain and cannot provide attested candidate execution. The Python result is useful development evidence only, not H02 qualification.

## Remote execution observation

The corrected implementation triggered:

```text
workflow:   h02-openraft-fault-lab
run_id:     33174789738
head_sha:   66a7f888944d1ae74129edaacc03660e69986f81
status:     pending
jobs:       []
runner_id:  null
runner_name:null
steps:      []
```

Classification: `INFRASTRUCTURE_UNEXECUTED`. No validator, Rust compiler, child process, real history or checker step has executed. This is not passing evidence and is not a code-test failure.

## Remaining blockers

The following remain outside this slice and continue to block promotion:

- an executable attested runner and six actual toolchain/seed executions;
- a second independent attested reproduction;
- production durable log, state-machine and snapshot storage qualification;
- OS-level process suspension and scheduling pause;
- disk stall, torn write, fsync loss and corruption testing;
- monotonic and wall-clock fault injection;
- package graph, SBOM, advisory, license, unsafe/native/build-script and effective-MSRV closure;
- independent distributed-systems, storage, platform and security approvals;
- a separately signed bounded prototype-selection receipt.

OpenRaft remains `IDENTIFIED`; selected candidates remain zero; all compatibility, production, migration and release authority remains closed.
