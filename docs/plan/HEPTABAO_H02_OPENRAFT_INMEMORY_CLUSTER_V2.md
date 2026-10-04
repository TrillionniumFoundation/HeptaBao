# H02 OpenRaft in-memory current profile V2

## Current entry point

Use the path-filtered pull-request [V2 workflow](../../.github/workflows/h02-openraft-inmemory-cluster-v2.yml)
and [V2 plan](../../planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V2.yaml).
It selects the event's checkout, with exactly Rust 1.88.0 (effective MSRV) and
1.99.0 (current), the existing three seeds, six cases per entry, and same-seed
replay. The two compilers × three seeds remain six serial entries on one runner.
No required-check or repository-protection setting is introduced.

Pull-request admission is restricted to the exact V1/V2 workflow, collector,
validator, schema, plan and test files this profile reads; its Python requirements;
and the policy modules imported by its tests. Native filters cover the isolated
probe manifest/lock, build script and Cargo target directories (`src`, `tests`,
`examples`, `benches`). Cargo runs with `--all-targets`, so sibling fault-lab and
durable-store sources genuinely affect the lane. The in-memory binary also
includes the sibling fault-lab cluster. Source inspection found no out-of-package
Rust includes, path dependencies or checked-in external fixture inputs. Exact
root `.cargo/config` and `.cargo/config.toml` paths cover Cargo configuration used
from the repository working directory, including future addition of those files.

No repository-wide source, documentation or arbitrary script glob is admitted.
Documentation-only and unrelated PRs do not start this 180-minute lane. Manual
`workflow_dispatch` remains available for later reruns; the scoped PR event permits
initial hosted admission while the new workflow exists only on the PR branch.
There is no push, schedule, privileged PR-target or workflow-run trigger. The V2
validator rejects missing, broadened or unrelated path filters and event changes.

The [V1 workflow](../../.github/workflows/h02-openraft-inmemory-cluster.yml), plan,
schema, emitter, validator, tests and historical receipts are preserved. V1's
1.88.0/1.98.0 acceptance contract remains valid. Its workflow is event-selected,
not frozen-source replay, and its old evidence cannot satisfy the V2 gate.
Other H02 profiles are unaffected by this bounded slice.

## Fresh evidence and shared observations

The V2 collector accepts fresh probe JSONL and replay JSONL, never a V1 receipt.
It uses a private import of the byte-pinned V1 observation engine. Only that
private instance's JSONL parser is replaced, to fail closed on non-object,
duplicate or unexpected records and non-integer assertion counts. No canonical
V1 module globals, source bytes, constants or previously issued receipts change.
The loader hashes a captured byte buffer and executes that exact buffer, bypassing
cached bytecode and later path replacement. The private V1 validator uses the
same verified-byte loading rule.
V2 then emits its own schema, revision and execution-profile identity from those
fresh observations. The Rust behavior-profile identifier remains unchanged.

The V2 validator first runs the unchanged byte-pinned V1 artifact validator, then
checks the additive V2 contract. It requires the exact compiler/seed directory
set, source commit/tree, fresh manifest equality, complete cases and counts,
raw/replay/manifest/lock/compiler SHA-256 bindings and semantic recollection.
The compiler record is `rustup run <exact-version> rustc --version --verbose`,
archived per entry. Both its header and release must match the selected version.
The same exact toolchain executes Cargo tests and both probe runs.
A requested version label alone is insufficient.

Each workflow-produced execution context binds GitHub run ID, attempt, runner
name, compiler, seed and exact manifest location. The validator requires those
run/attempt/runner/execution-root expectations independently on its command line;
it never learns its expected run identity from the evidence being checked.
A canonical command profile records the exact rustc, lock-generation, Cargo-test,
probe and replay argv plus their SHA-256 digest. The command recorder executes
those exact argv and records each return code, rejecting repeated or out-of-order
stages. Only shared compiler/build outcomes are copied into the three seed
contexts; each seed records its own probe and replay. The final gate requires all
five stages to have executed successfully in all six entries. Wrong or mixed
attempts, runner labels, command vectors and manifest targets fail even when a
modified context's digest is recomputed. The runner ID remains explicitly marked
as awaiting API enrichment; these checks do not authenticate a malicious runner.

The workflow uploads bounded V2 evidence before its final all-pass gate. The
workflow-trust registry adds only the exact V2 upload invocation/path; its closed
registry count increases by one. Existing entries and permission rules stay intact.

## Replay contract, revision 2.1

`replay_match` retains its original canonical raw-output meaning and may be false.
The separate `semantic_replay` result names
`heptabao.h02-inmemory-bounded-semantic-replay.v1`. It means repeated bounded
safety/outcome observations agree, not byte-identical output, deterministic Raft
scheduling, identical RPC traffic or performance equivalence.

The seed controls application ordering and the diagnostic fault-plan shuffle.
It does not control the four-worker Tokio scheduler, election timing or RPC
retries. Exact replay would need a separate deterministic native harness with
controlled clock, election randomness, task ordering and transport scheduling.
A single-thread runtime, extra sleeps, forcing a chosen successor or suppressing
printed counters would not establish that claim and could reduce fault coverage.
This revision makes no native-source changes.

Both complete streams must independently pass the unchanged observation engine
and the stricter full-shape contract. Every safety Boolean, assertion count
(4/8/3/3/2/3), seed-derived plan/index, membership and hostile-snapshot before/after
state is checked. Identical wrong values on both sides do not become a pass.
Original parse/meta/exit/case/snapshot failures remain failures or blockers; no
inherited BLOCKED result is promoted merely because a projected pair matches.

Only six validated diagnostic leaves may differ:

- Partition successor ID must be 2 or 3. It names the initially stabilized
  successor; the write retry helper may redirect before committing.
- Post-heal isolated-leader ID must be 1, 2 or 3. A legal new election may change
  it, so it need not equal the earlier successor.
- The exact four RPC counters, `append_entries`, `vote`, `pre_vote` and
  `full_snapshot`, must each be positive u64 integers. They count attempts before
  blocked/paused transport checks, not successful deliveries. Positivity alone
  is insufficient; all associated behavioral and stage assertions still apply.

The hostile observation must be internally consistent and caught up: applied and
state-machine log IDs agree; original snapshot <= applied <= local commit <=
local log index; independently, original snapshot <= known cluster commit <=
local log index; purged <= covering snapshot <= applied; and IDs at the same log
index agree. No relative publication order between local and cluster metrics is
assumed. This intentionally excludes lagging observations. It is not a claim
that arbitrary Raft followers can never know a cluster commit beyond their local
log. Non-finite JSON numbers, including exponent overflow, fail closed.

The stale snapshot ID comes from a successful local node-1 write. The native
helper performs six further distinct awaited writes and waits for a snapshot
covering the last one. Each stream therefore requires stale writer ID 1 and an
original-snapshot index at least six beyond the stale index. Extra log entries
and term changes are allowed. Pinned-source bootstrap requires initial membership,
an election blank, two learner memberships and joint/uniform voter memberships.
Thus the later stale client write has term at least 1 and index at least 6;
the separate four-write restart baseline is at least 9. These are source-derived
lower bounds, not exact observed values. The pinned memstore uses OpenRaft's
advanced leader IDs, so leadership
must be nondecreasing in `(term, node_id)` order as committed indices increase.
Different node IDs within one term can be legal. Equal indices must still carry
the exact same complete LogId. These are per-stream constraints: two identical
forgeries, including `T99-N1.6` before `T1-N1.12` or a one-index stale gap, fail
even when canonical raw replay equality is true.

All other values remain canonically equal, including hostile transport detail,
application state and log boundaries. Missing/extra fields, reordered cases,
Boolean-as-integer values, overflow and unrecognized variation fail closed.
No performance threshold is inferred from this small sample. Raw output/replay
hashes, the original first-side detail hashes, both raw case-detail hash maps,
raw equality, named semantic result and the permitted differences are retained.
No global canonicalization function is replaced.

The first native V2 run, 37227812209 at
`fa686c4b71a8d47a5243245c854057e73ccc1efb`, remains six BLOCKED revision-2.0
receipts because its original exact-replay contract failed. Its failed ZIP and
raw digests are unchanged. The committed raw regression fixture records that
failure explicitly; evaluating a later comparator against it is not a new native
pass. Fresh exact-head execution is required for revision 2.1.

The raw stream does not emit the membership bytes compared internally by the
hostile guard or leader-at-injection metrics for quorum loss. This contract
cannot independently reconstruct those facts; observations remain source-bound
and unqualified, with no malicious-runner attestation claim.

## Boundaries

Source validation and synthetic Python unit tests are not native execution proof.
The committed plan records zero current exact-head remote executions. New Rust
1.99.0 native runs must produce new V2 artifacts; old receipts are never relabeled.
The generated execution lock is bound to its archived bytes; this does not assert
that resolution is identical to a prior run. Compiler output, raw results and
source labels remain runner-produced, candidate-controlled observations, not
independent attestation or proof against a malicious runner.

OpenRaft memstore remains test-only in-memory storage. Qualification is false,
selection and authority are NONE, promotion stays blocked, and production
durability, independent review and all existing promotion blockers remain open.
