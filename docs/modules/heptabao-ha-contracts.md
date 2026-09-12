# heptabao-ha-contracts

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns term, membership and writer-fence semantics for an HA composition. It does not implement Raft networking, log replication, snapshots, quorum reads or leader election.

## Public API and ownership

### Current API contract and integration boundary

`HaState::new(local_node, voters)` owns local role, term, leader, voter/learner sets and fence generation. Membership must be nonempty and include the local node. `grant_leadership(leader_id, term)` accepts a voter and nonzero non-stale term, updates the local role, and returns `WriterFence { term, leader_id, generation }`. It does not conduct an election or require a quorum certificate; the consensus adapter must establish authority before calling it.

`observe_higher_term(term)` requires a strictly larger term, demotes the node and invalidates existing fences. `validate_writer(&fence)` requires the exact local leader, term and generation, otherwise `StaleFence`. `add_learner`, `promote` and `remove_voter` mutate membership, reject duplicates/missing learners/last-voter removal, and invalidate fences by advancing generation. Generations use saturating arithmetic; the model is not a durable or unbounded fence authority.

The caller must serialize membership and leadership events, persist the authoritative consensus state, and recheck writer authority at the actual commit boundary. `HaState` owns no storage, peer identities, timeout or joint-consensus protocol. This crate is outside the current server dependency closure; the separately implemented `heptabao-ha-service` and `heptabao-raft-runtime` drive current server HA paths. Their existence does not turn this standalone fence model into that runtime.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-ha-contracts`; Cargo SHA-256 `c16ed8d85802428a25d38a8de02e66165bfa81ce266bfd2777fffe42e000386e`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `NodeRole` | `crates/heptabao-ha-contracts/src/lib.rs:13` | `pub enum NodeRole {` |
| `struct` | `WriterFence` | `crates/heptabao-ha-contracts/src/lib.rs:20` | `pub struct WriterFence {` |
| `struct` | `HaState` | `crates/heptabao-ha-contracts/src/lib.rs:27` | `pub struct HaState {` |
| `fn` | `new` | `crates/heptabao-ha-contracts/src/lib.rs:38` | `pub fn new(local_node: Id, voters: BTreeSet<Id>) -> Result<Self, HaError> {` |
| `fn` | `role` | `crates/heptabao-ha-contracts/src/lib.rs:53` | `pub fn role(&self) -> NodeRole {` |
| `fn` | `term` | `crates/heptabao-ha-contracts/src/lib.rs:57` | `pub fn term(&self) -> u64 {` |
| `fn` | `local_node` | `crates/heptabao-ha-contracts/src/lib.rs:61` | `pub fn local_node(&self) -> &Id {` |
| `fn` | `voters` | `crates/heptabao-ha-contracts/src/lib.rs:65` | `pub fn voters(&self) -> &BTreeSet<Id> {` |
| `fn` | `observe_higher_term` | `crates/heptabao-ha-contracts/src/lib.rs:69` | `pub fn observe_higher_term(&mut self, term: u64) -> Result<(), HaError> {` |
| `fn` | `grant_leadership` | `crates/heptabao-ha-contracts/src/lib.rs:80` | `pub fn grant_leadership(&mut self, leader_id: Id, term: u64) -> Result<WriterFence, HaError> {` |
| `fn` | `validate_writer` | `crates/heptabao-ha-contracts/src/lib.rs:102` | `pub fn validate_writer(&self, fence: &WriterFence) -> Result<(), HaError> {` |
| `fn` | `add_learner` | `crates/heptabao-ha-contracts/src/lib.rs:114` | `pub fn add_learner(&mut self, node_id: Id) -> Result<(), HaError> {` |
| `fn` | `promote` | `crates/heptabao-ha-contracts/src/lib.rs:122` | `pub fn promote(&mut self, node_id: &Id) -> Result<(), HaError> {` |
| `fn` | `remove_voter` | `crates/heptabao-ha-contracts/src/lib.rs:131` | `pub fn remove_voter(&mut self, node_id: &Id) -> Result<(), HaError> {` |
| `enum` | `HaError` | `crates/heptabao-ha-contracts/src/lib.rs:150` | `pub enum HaError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Nodes are followers, leaders or removed. Higher terms demote a leader. Learners must be explicitly promoted before they are voters, and the last voter cannot be removed.

## Invariants and authorization

Only the exact local leader fence validates for writing. Stale terms, nonvoter leaders and stale generations fail closed. Membership does not imply application authorization.

## Failure, retry and reconciliation

Stale fence and membership failures occur before a write enters storage. A provider failure after a validated fence still requires the durable unknown-outcome taxonomy.

## Concurrency and ordering

A real consensus runtime serializes term and membership updates. Writer validation must occur at the storage commit boundary, not only when a request is accepted.

## Security and privacy

Cluster identifiers are bounded and nonsecret. Production peer identity, mTLS, certificate rotation and join authorization remain external provider responsibilities.

## Persistence and compatibility

No Raft log or snapshot format is owned. Persisted term, vote, membership and fence state require versioned crash-consistent storage.

## Observability

Recommended events are leader change, term change, membership change and stale-fence rejection, using node role and outcome labels only.

## Operations

Learner addition, promotion and voter removal are explicit transitions. Production runbooks must include quorum loss, certificate failure, snapshot restore and split-brain fencing.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::stale_writer_fence_is_rejected_after_term_change`](../../crates/heptabao-ha-contracts/src/lib.rs) checks a previously granted fence fails after observing a larger term.
- [`tests::learner_promotion_and_last_voter_guard_are_explicit`](../../crates/heptabao-ha-contracts/src/lib.rs) checks promotion ordering and protection against removing the final voter.

`cargo test -p heptabao-ha-contracts` proves stale-fence rejection, learner promotion and last-voter protection.

## Evolution and open boundaries

This crate does not implement consensus. The repository separately contains `heptabao-raft-runtime` and `heptabao-ha-service`; integration with this model, its joint-consensus/read-index contract and independent network-fault qualification require separate evidence.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-ha-contracts`
- Crate path: `crates/heptabao-ha-contracts`
- Cargo manifest SHA-256: `c16ed8d85802428a25d38a8de02e66165bfa81ce266bfd2777fffe42e000386e`
- Rust source files: `1`
- Public lexical declarations: `15`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
