# H02 OpenRaft fault-lab current profile V2

## Scope and admission

The [V2 plan](../../planning/HEPTABAO_H02_OPENRAFT_HOSTILE_FAULTS_LINEARIZABILITY_V2.yaml)
and [V2 workflow](../../.github/workflows/h02-openraft-fault-lab-v2.yml) prepare one
isolated forward execution profile, `HB-H02-OPENRAFT-FAULT-LAB-CURRENT-V2`.
It runs exactly Rust 1.88.0 (the effective floor) and 1.99.0 with the existing
three seeds, serially on one Linux runner: six compiler/seed entries. Each entry
runs the existing hostile-snapshot parent and exports one actual ReadIndex
single-register history for the unchanged external checker.

This is a source-only successor. The plan records zero current exact-head remote
executions. No Rust 1.99.0 runtime pass, timing behavior, remote artifact receipt,
qualification or independent admission is established by source checks or
synthetic Python tests. Historical output cannot satisfy the new execution gate.
The raw native profile remains `HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33`; it names
compiler-neutral behavior, not the V2 execution matrix.

Publication and execution are separate steps. After authorized publication, the
first requested hosted admission is a manual `workflow_dispatch` run on the exact
published PR branch, when GitHub exposes that workflow for dispatch. A new workflow
may first need to be present on the default branch before the manual entry point
is available. The exact-input `pull_request` trigger provides initial branch
admission without adding a broad push trigger or changing repository settings.
If dispatch is unavailable, report that limitation and use the scoped PR event;
do not add privileges, merge the branch or alter protection to make dispatch work.
Every resulting run still needs independently supplied expected head/tree and
run/attempt/runner bindings, retained evidence, and successful terminal checks.

The PR path list contains the new workflow, plan, aggregate schema, collector,
validator and tests; the preserved checker and raw schemas; and explicit inputs
read by the preserved V1 source-contract validator. Those historical inputs
include its workflow, plan, collector, aggregate schema, tests and execution
queue. The queue remains provenance and is not rewritten as V2 authorization.
Probe manifest/lock, build script and `src`, `tests`, `examples` and `benches`
paths are included because Cargo tests execute `--all-targets`. The Python requirements and workflow-trust policy modules/registry are
included as execution or source-check inputs. Root Cargo configuration is not
an execution input: the isolated command cwd and explicit config-free Cargo
home deliberately exclude it. There are no repository-wide source or documentation globs.
Documentation-only and unrelated changes do not start this runtime lane.

The workflow has only `contents: read`, pinned current checkout/Python/artifact
actions, exact event-head checkout and disabled persisted checkout credentials.
It has no privileged PR-target, workflow-run, push or schedule trigger and
introduces no required-check, branch-protection or permission setting.

## Fresh observations and committed graph

The [V2 collector](../../scripts/h02_openraft_fault_lab_evidence_v2.py) owns the
serial execution and writes every matrix entry. Isolated probe copies and Cargo
targets live under `RUNNER_TEMP/h02-fault-v2-work`; evidence lives separately under
`RUNNER_TEMP/h02-fault-v2-evidence`. Evidence is kept outside the checkout so its
creation cannot masquerade as a clean source tree or dirty the tested source.
The source commit and tree are measured from the actual checkout, and the
collector receives the expected event-selected commit independently.

Each isolated probe copy is materialized from regular Git blobs in the captured
commit, preserving executable modes. Ignored files and symlink/gitlink inputs
cannot enter that copy. Its `Cargo.toml` and `Cargo.lock` must match the captured
committed hashes before any native command executes.
Cargo uses `--locked`; V2 never generates or refreshes a replacement lock. The
manifest and lock are digested and checked against the committed source, and the
lock must remain unchanged after execution. The exact OpenRaft alpha.33 family,
Rust 1.88 manifest floor and validit override
`7016fa5e072a86092928144b3a3040381e6964e9` remain intact. This does not add the
candidate to the production workspace or copy upstream source into it.

The compiler observation is the actual exact-version `rustc --version --verbose`
output, not a requested toolchain label. The same selected toolchain executes
Cargo tests and the hostile/history binary. The command profile and recorded
stage outcomes bind the actual compiler, manifest, seed and execution root.
The context also records source commit/tree, clean-tree status, GitHub run ID,
attempt and runner name. The validator is given these expectations separately;
it does not take its expected source or run identity from the receipt it checks.
Downloaded artifacts can be verified in a different directory. Supply the expected
producer checkout and evidence paths using `--producer-source-root` and
`--producer-evidence-root`, and the expected producer work path with
`--execution-root`, separately from the local `--evidence-root`. These are
independent run expectations, never values adopted from the receipt under review.
The validator rebuilds producer commands while reading local artifact bytes;
stable I/O diagnostics keep failed and blocked receipts portable too. Recorded
`cwd` and compiler-specific `CARGO_TARGET_DIR` bind the actual execution context.
For downloaded receipts from another runner, independently supply the expected
producer `PATH` and `RUSTUP_HOME` using `--producer-path` and
`--producer-rustup-home`; the local runner environment is the default expectation.
Those values are never adopted from the receipt itself.

Every native/checker command starts in its isolated committed-probe directory.
A fresh per-run `CARGO_HOME`, `HOME`, and temporary directory are created outside
the source checkout. Cargo's cache is shared only inside that new run. The child
environment is constructed from a closed list: trusted runner `PATH` and
`RUSTUP_HOME`, the controlled directory paths, fixed locale/timezone values, and
Git configuration-disabling settings. Ambient `RUSTFLAGS`, `RUSTC`, compiler
wrappers, `CARGO_*`, Python/loader overrides, and proxy/config override variables
are not inherited. This preserves access to the already installed exact rustup
toolchains without using the runner's Cargo home or Git user/system configuration.

Before and after every attempted stage, V2 checks the actual Cargo discovery
paths: `.cargo/config` and `.cargo/config.toml` in the cwd and each ancestor, plus
`config` and `config.toml` in its explicit Cargo home. Existing configuration or
symlinked discovery paths block execution/admission. The exact policy, paths,
closed environment, environment digest and per-stage absence observations are
bound into the context. Ignored root-checkout Cargo configuration therefore
cannot affect this lane even when Git reports a clean source tree. This is a
bounded input-control policy, not a sandbox against malicious build scripts or
an attestation of the runner, rustup installation, executable PATH or transient
filesystem changes.

Runner-generated labels and observations are not malicious-runner protection,
independent attestation or authenticated runner API enrichment.

The existing checker is reused without changing its bytes, raw schemas or
semantics. The aggregate has its own V2 identity and requires the exact six
compiler/seed keys. A missing, duplicate or unexpected entry cannot disappear
from the denominator. Source/profile/compiler/seed drift, a missing or changed
lock, dirty source, forged authority, unknown outcomes, malformed records or
contradictory exits fail closed. Per-stage stdout/stderr, command outcomes,
compiler output, raw hostile result, raw history, checker result and content
digests are retained for diagnosis.

## Failures retain their meaning

The preserved native parent returns exit 0 for `EXECUTED_PASS`, 1 for
`EXECUTED_FAIL`, and 2 for `BLOCKED`. V2 enforces those pairs; it does not inherit
V1's collector assumption that a hostile executed failure exits zero.
A pass requires the injection phase and recognized rejection/no-op or abort
outcome. A failure requires a validated injection and accepted stale snapshot
that changes a guarded state surface. Guarded state uses the pinned native wire
types: optional u64 log index, optional string log-id displays, and the memstore's
string-to-string client-status map. Child exit is `null` for a signal or an integer
in Linux's 0..255 exit domain. BLOCKED must fit the native early-setup, child-timeout,
unrecognized-result or pre-injection-abnormal-exit decision table; relabeling an
ACCEPTED/regression result as BLOCKED produces an explicit contradiction diagnostic.
The original raw failure details remain retained. Unknown, contradictory and malformed
records never become executed successes or authoritative executed failures.

A genuine validated hostile failure or non-linearizable executed history takes
precedence over a separate blocked component. For example, a valid hostile
`EXECUTED_FAIL` with exit 1 remains an executed safety failure when history export
is blocked. Conversely, a status string in an invalid record cannot manufacture
a failure. If there is no valid executed failure, any missing, malformed,
timed-out, unexecuted or contradictory required component leaves the entry
`BLOCKED`. `EXECUTED_PASS` requires every necessary stage and both components to
pass with complete valid bindings. No build, history or checker error can be
turned into a pass by a successful sibling observation.

Both the pre-upload validation and the final all-pass gate inspect retained
artifacts. Validation without `--require-pass` permits faithfully represented
invalid-input/blocked diagnostics to be uploaded; it is diagnostic retention,
not execution admission or validation of a contradictory native component.
A relabeled ACCEPTED result therefore has a null validated component, an explicit
integrity problem, and its unchanged raw bytes. The final gate rejects it. Its
inner label alone cannot establish a verified failure when the outer result and
recorded exit disagree. An independently valid sibling failure still retains
`EXECUTED_FAIL` priority. Upload uses `always()` and precedes the final gate, which also uses
`always()`. Thus failed and blocked observations remain available even when the
all-pass check fails. Setup outcomes are retained separately under `RUNNER_TEMP/h02-fault-v2-setup`
and included in the same upload; the evidence root contains exactly the six
entry directories. An unavailable toolchain
still reaches the collector so it can record blocked matrix entries. Runner
termination, failed checkout, or an unavailable Python runtime can prevent
collection; missing evidence must then fail the lane, never imply execution.
The existing closed workflow-trust registry gains only the exact V2 upload
invocation and path, with its production and test count guards incremented once.

## Concurrent histories are not byte replay

The seed controls the native fault plan and seeded jitter. It does not make
Tokio task scheduling, Raft elections, RPC counts, operation timing, child
diagnostics or snapshot metadata reproducible byte for byte. Writers/readers
can legally interleave in different ways. Every execution retains its actual
history and hashes those bytes; each history is independently evaluated with
the existing single-register checker and real-time precedence rule.

A different legal history, RPC count or witness order across runs is not by
itself a fault-lab failure. V2 adds no second-run equality test, shared raw
canonicalization override, suppression of diagnostics or replay subsystem.
The checker result must still match the history produced by that same entry.
Raw history substitution, a mismatched history digest, invalid operations or a
well-formed history with no legal witness cannot be excused as scheduling noise.

The hostile guard still compares its own before/after safety state around one
injection, including its original 100 ms settle interval and bounded 10-second
child operation and 25-second parent deadline. These local safety comparisons
are not cross-run equality requirements. Process-fatal rejection after injection
can preserve this one safety case; it does not establish availability. Source
review cannot prove that the existing timing contract passes under Rust 1.99.0.

## Preservation and verification boundary

Every V1 workflow, plan, collector, validator, schema, test, queue and historical
receipt remains unchanged. The V1 workflow remains event-selected, rather than
an immutable source replay, and keeps its historical 1.88.0/1.98.0 contract.
The native Rust sources, raw-result schemas and checker bytes are also retained.
Candidate-probe/adapter, durable, blocker-closure and exact-head-matrix families
are outside this isolated successor.

Source-only verification uses the following focused commands:

```text
python scripts/validate_h02_openraft_fault_lab_v2.py
python -m unittest discover -s tests/platform -p 'test_h02_openraft_fault_lab_evidence_v2.py' -v
python -m unittest discover -s tests/platform -p 'test_h02_linearizability_checker_v1.py' -v
python -m unittest discover -s tests/platform -p 'test_h02_openraft_fault_lab_evidence_v1.py' -v
python -m unittest discover -s tests/platform -p 'test_h02_openraft_fault_lab_source_binding_v1.py' -v
python scripts/validate_workflow_trust.py
python scripts/validate_plan_v2.py
```

Workflow YAML must also parse under the repository YAML 1.2 loader, embedded
shell blocks must pass `bash -n`, and aggregate/raw schemas must validate as
schemas. These checks do not invoke Cargo, install toolchains, download packages
or dispatch workflows during source preparation. Test results belong in the
actual validation report; the plan does not predeclare a test count or runtime
pass.

Completion of the execution slice requires a fresh exact-published-head hosted
run for all six entries, schema-valid evidence and successful terminal checks.
Even those results remain bounded candidate-controlled observations.
Qualification stays false, selection and authority remain `NONE`, and the legacy
fail-closed promotion-effect identifier is retained without implying that related
layers are absent. Test-only memstore, durable/OS/disk/clock qualification,
independent reproduction/review and production, compatibility, migration and
release admission remain separate open boundaries.
