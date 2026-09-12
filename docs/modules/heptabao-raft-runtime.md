# heptabao-raft-runtime

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package implements a durable three-voter OpenRaft consensus core for HeptaBao. It replicates bounded opaque sealed envelopes, persists Raft log, vote, membership, state-machine and snapshot generations, rejects writes without a quorum, and exposes an explicit ReadIndex linearizability barrier. It provides both the in-process qualification facade and a separate `ProcessRaftNode`/`RemoteNetworkFactory` per-process path. The server now composes this path with mTLS and leader forwarding. Operator join authorization, key rotation, rolling-version upgrade and independent destructive qualification remain separate blockers.

## Public API and ownership

Current source binding: `docs/modules/CURRENT_SOURCE_BINDING.md` and
`planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`. Any V1.4.7 generated
blocks below are historical lexical snapshots, not current API authority.

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-raft-runtime`; Cargo SHA-256 `688cceef93fca7a05c56f110d5213723170927e9cea644a909d26c4f3ead345b`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `type` | `AnyResult` | `crates/heptabao-raft-runtime/src/cluster.rs:22` | `pub type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;` |
| `struct` | `DurableNode` | `crates/heptabao-raft-runtime/src/cluster.rs:39` | `pub struct DurableNode {` |
| `struct` | `DurableCluster` | `crates/heptabao-raft-runtime/src/cluster.rs:46` | `pub struct DurableCluster {` |
| `fn` | `new` | `crates/heptabao-raft-runtime/src/cluster.rs:54` | `pub fn new(root: impl AsRef<Path>) -> AnyResult<Self> {` |
| `fn` | `bootstrap_three_voters` | `crates/heptabao-raft-runtime/src/cluster.rs:127` | `pub async fn bootstrap_three_voters(&mut self) -> AnyResult<()> {` |
| `fn` | `reopen_three_voters` | `crates/heptabao-raft-runtime/src/cluster.rs:166` | `pub async fn reopen_three_voters(&mut self) -> AnyResult<u64> {` |
| `fn` | `consensus_leader` | `crates/heptabao-raft-runtime/src/cluster.rs:179` | `pub async fn consensus_leader(&self) -> AnyResult<u64> {` |
| `fn` | `write` | `crates/heptabao-raft-runtime/src/cluster.rs:219` | `pub async fn write(&self, leader: u64, serial: u64, status: String) -> AnyResult<u64> {` |
| `fn` | `wait_all_applied` | `crates/heptabao-raft-runtime/src/cluster.rs:262` | `pub async fn wait_all_applied(&self, index: u64) -> AnyResult<()> {` |
| `fn` | `read_index` | `crates/heptabao-raft-runtime/src/cluster.rs:272` | `pub async fn read_index(&self, leader: u64) -> AnyResult<()> {` |
| `fn` | `trigger_snapshot` | `crates/heptabao-raft-runtime/src/cluster.rs:306` | `pub async fn trigger_snapshot(&self, leader: u64, minimum_index: u64) -> AnyResult<()> {` |
| `fn` | `state` | `crates/heptabao-raft-runtime/src/cluster.rs:366` | `pub async fn state(&self, id: u64) -> MemStoreStateMachine {` |
| `fn` | `all_states_equal` | `crates/heptabao-raft-runtime/src/cluster.rs:370` | `pub async fn all_states_equal(&self) -> bool {` |
| `fn` | `snapshot_status` | `crates/heptabao-raft-runtime/src/cluster.rs:383` | `pub async fn snapshot_status(&self) -> BTreeMap<u64, (bool, u64)> {` |
| `fn` | `artifact_paths` | `crates/heptabao-raft-runtime/src/cluster.rs:398` | `pub fn artifact_paths(&self) -> BTreeMap<String, PathBuf> {` |
| `fn` | `rpc_counts` | `crates/heptabao-raft-runtime/src/cluster.rs:418` | `pub async fn rpc_counts(&self) -> BTreeMap<String, u64> {` |
| `fn` | `exercise_partition` | `crates/heptabao-raft-runtime/src/cluster.rs:423` | `pub async fn exercise_partition(&self, leader: u64) -> AnyResult<(bool, bool)> {` |
| `fn` | `shutdown` | `crates/heptabao-raft-runtime/src/cluster.rs:454` | `pub async fn shutdown(mut self) -> AnyResult<()> {` |
| `struct` | `ReplicatedEnvelope` | `crates/heptabao-raft-runtime/src/lib.rs:31` | `pub struct ReplicatedEnvelope {` |
| `fn` | `new` | `crates/heptabao-raft-runtime/src/lib.rs:38` | `pub fn new(` |
| `struct` | `CommitReceipt` | `crates/heptabao-raft-runtime/src/lib.rs:88` | `pub struct CommitReceipt {` |
| `enum` | `RaftRuntimeError` | `crates/heptabao-raft-runtime/src/lib.rs:95` | `pub enum RaftRuntimeError {` |
| `struct` | `RaftRuntime` | `crates/heptabao-raft-runtime/src/lib.rs:117` | `pub struct RaftRuntime {` |
| `fn` | `bootstrap` | `crates/heptabao-raft-runtime/src/lib.rs:131` | `pub async fn bootstrap(root: impl AsRef<Path>) -> Result<Self, RaftRuntimeError> {` |
| `fn` | `reopen` | `crates/heptabao-raft-runtime/src/lib.rs:142` | `pub async fn reopen(root: impl AsRef<Path>) -> Result<Self, RaftRuntimeError> {` |
| `fn` | `leader` | `crates/heptabao-raft-runtime/src/lib.rs:153` | `pub async fn leader(&self) -> Result<u64, RaftRuntimeError> {` |
| `fn` | `replicate` | `crates/heptabao-raft-runtime/src/lib.rs:160` | `pub async fn replicate(` |
| `fn` | `ensure_linearizable` | `crates/heptabao-raft-runtime/src/lib.rs:185` | `pub async fn ensure_linearizable(&self) -> Result<u64, RaftRuntimeError> {` |
| `fn` | `trigger_snapshot` | `crates/heptabao-raft-runtime/src/lib.rs:192` | `pub async fn trigger_snapshot(&self, minimum_index: u64) -> Result<(), RaftRuntimeError> {` |
| `fn` | `snapshot_status` | `crates/heptabao-raft-runtime/src/lib.rs:201` | `pub async fn snapshot_status(&self) -> Result<BTreeMap<u64, (bool, u64)>, RaftRuntimeError> {` |
| `fn` | `states_converged` | `crates/heptabao-raft-runtime/src/lib.rs:205` | `pub async fn states_converged(&self) -> Result<bool, RaftRuntimeError> {` |
| `fn` | `shutdown` | `crates/heptabao-raft-runtime/src/lib.rs:209` | `pub async fn shutdown(mut self) -> Result<(), RaftRuntimeError> {` |
| `type` | `DurableRaft` | `crates/heptabao-raft-runtime/src/network.rs:20` | `pub type DurableRaft = Raft<TypeConfig, DurableStateMachine>;` |
| `struct` | `DurableRouter` | `crates/heptabao-raft-runtime/src/network.rs:23` | `pub struct DurableRouter {` |
| `fn` | `register` | `crates/heptabao-raft-runtime/src/network.rs:36` | `pub async fn register(&self, id: u64, raft: DurableRaft) {` |
| `fn` | `unregister` | `crates/heptabao-raft-runtime/src/network.rs:40` | `pub async fn unregister(&self, id: u64) {` |
| `fn` | `isolate` | `crates/heptabao-raft-runtime/src/network.rs:45` | `pub async fn isolate(&self, id: u64) {` |
| `fn` | `pause` | `crates/heptabao-raft-runtime/src/network.rs:64` | `pub async fn pause(&self, id: u64) {` |
| `fn` | `resume` | `crates/heptabao-raft-runtime/src/network.rs:69` | `pub async fn resume(&self, id: u64) {` |
| `fn` | `heal_all` | `crates/heptabao-raft-runtime/src/network.rs:74` | `pub async fn heal_all(&self) {` |
| `fn` | `rpc_counts` | `crates/heptabao-raft-runtime/src/network.rs:80` | `pub async fn rpc_counts(&self) -> BTreeMap<String, u64> {` |
| `struct` | `DurableNetworkFactory` | `crates/heptabao-raft-runtime/src/network.rs:116` | `pub struct DurableNetworkFactory {` |
| `fn` | `new` | `crates/heptabao-raft-runtime/src/network.rs:122` | `pub fn new(source: u64, router: DurableRouter) -> Self {` |
| `struct` | `DurableNetwork` | `crates/heptabao-raft-runtime/src/network.rs:139` | `pub struct DurableNetwork {` |
| `struct` | `DurableLogStore` | `crates/heptabao-raft-runtime/src/store.rs:422` | `pub struct DurableLogStore {` |
| `fn` | `create` | `crates/heptabao-raft-runtime/src/store.rs:428` | `pub fn create(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `open_existing` | `crates/heptabao-raft-runtime/src/store.rs:442` | `pub fn open_existing(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `adopt_legacy` | `crates/heptabao-raft-runtime/src/store.rs:468` | `pub fn adopt_legacy(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `state_path` | `crates/heptabao-raft-runtime/src/store.rs:509` | `pub fn state_path(&self) -> &Path {` |
| `struct` | `DurableStateMachine` | `crates/heptabao-raft-runtime/src/store.rs:729` | `pub struct DurableStateMachine {` |
| `fn` | `create` | `crates/heptabao-raft-runtime/src/store.rs:735` | `pub fn create(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `open_existing` | `crates/heptabao-raft-runtime/src/store.rs:749` | `pub fn open_existing(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `adopt_legacy` | `crates/heptabao-raft-runtime/src/store.rs:775` | `pub fn adopt_legacy(root: impl AsRef<Path>) -> io::Result<Self> {` |
| `fn` | `get_state_machine` | `crates/heptabao-raft-runtime/src/store.rs:818` | `pub async fn get_state_machine(&self) -> MemStoreStateMachine {` |
| `fn` | `has_current_snapshot` | `crates/heptabao-raft-runtime/src/store.rs:822` | `pub async fn has_current_snapshot(&self) -> bool {` |
| `fn` | `generation` | `crates/heptabao-raft-runtime/src/store.rs:826` | `pub async fn generation(&self) -> u64 {` |
| `fn` | `state_path` | `crates/heptabao-raft-runtime/src/store.rs:831` | `pub fn state_path(&self) -> &Path {` |
| `fn` | `snapshot_path` | `crates/heptabao-raft-runtime/src/store.rs:835` | `pub fn snapshot_path(&self) -> &Path {` |
| `fn` | `flip_first_payload_byte` | `crates/heptabao-raft-runtime/src/store.rs:978` | `pub fn flip_first_payload_byte(path: &Path) -> io::Result<()> {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Each node owns a versioned CRC-protected log generation, persistent vote and committed membership, a versioned state-machine bundle, and a snapshot generation. Store initialization is marked before the first generation is published; interrupted replacement preserves exactly one recoverable predecessor and ambiguous multiple predecessors fail closed. Application entries contain the `hbr1` envelope profile: operation identity, semantic digest and ciphertext encoded without plaintext interpretation. Client serial numbers provide OpenRaft state-machine deduplication and must be nonzero.

## Invariants and authorization

Only the current consensus leader may acknowledge mutation. A successful public receipt requires a committed log index and convergence of every configured voter. An isolated former leader cannot advance its committed index. Read callers must cross `ensure_linearizable`, which executes OpenRaft ReadIndex against a freshly resolved leader. Consensus membership is not application authorization: authentication, policy, namespace qualification, final-use grants and audit remain upstream responsibilities. The runtime never unseals, parses or logs the opaque application ciphertext.

## Failure, retry and reconciliation

Invalid bounds and zero client serials fail before consensus entry. Fatal OpenRaft failures terminate the operation; leader-forwarding and short membership transitions are retried with the same serial and identical payload under a bounded attempt/deadline policy. A caller that loses the response after consensus entry must reconcile through its stable operation identity rather than issue a new semantic mutation. Quorum loss, partition or shutdown returns an error and must not be interpreted as proof that no earlier commit occurred. Store corruption, incompatible magic, truncated envelopes, symlink substitution and ambiguous interrupted replacement fail closed during reopen.

## Concurrency and ordering

OpenRaft serializes leader terms, log append, commitment and state-machine application. The façade first resolves the current leader, invokes one idempotent client write, observes the returned log index, and waits for every voter to apply at least that index before releasing a receipt. ReadIndex occurs after leader resolution and before a linearizable read may be served. The deterministic router supports isolation, pause, healing and RPC counting only for qualification; it is not exposed as a production bypass. Shutdown unregisters every node before releasing the corresponding Raft task.

## Security and privacy

The public payload must already be protected by the HeptaBao Barrier; this package deliberately has no key, unseal or plaintext API. `Debug` for `ReplicatedEnvelope` redacts operation identity and digest and reports only ciphertext length. Durable application values are ciphertext, while Raft metadata such as node IDs, terms and membership remain nonsecret. The store rejects symlinked roots/generations and limits every durable artifact to 128 MiB. Peer authentication, transport encryption, certificate rotation, join tokens, anti-rollback hardware and host isolation are explicitly outside this in-process vertical slice and remain mandatory before production activation.

## Persistence and compatibility

The package owns repository-local formats `HBRLOG01`, `HBRSB001` and `HBRINI01`, each with exact length and CRC validation. Atomic replacement writes a temporary complete generation, syncs it, renames it, syncs the parent, and retires one validated predecessor. Reopen refuses a missing authoritative generation after initialization, unresolved multiple predecessors, corrupt checksums, wrong format magic, non-regular files and unsafe directory substitution. Format changes require new magic/version identifiers, hostile decoder tests, an interruption-safe migration and an explicit rollback decision; existing bytes are never silently reinterpreted.

## Observability

The public façade exposes leader ID, committed log index and the caller-supplied semantic digest in `CommitReceipt`; no ciphertext or credential enters metrics. The internal qualification router records bounded RPC counts by method so tests can prove vote, append, snapshot and ReadIndex activity. Recommended production events are term/leader change, quorum unavailable, stale leader forwarding, snapshot publish, store recovery and corruption rejection. Labels must remain low-cardinality and must not contain operation identifiers, paths, namespaces, tokens or encrypted payload bytes.

## Operations

Repository qualification supports bootstrap of exactly three voters, orderly shutdown, exact-root reopen, leader discovery, snapshot generation, deterministic partition/heal and state convergence checks. Operators must treat a failed reopen, checksum mismatch or ambiguous replacement as a recovery event and preserve all artifacts. Deleting log/state files to regain liveness is forbidden. The future networked service must add peer certificate enrollment, membership-change authorization, rolling upgrade, node replacement, snapshot transfer limits, quorum-loss runbooks and cross-host backup/restore before this runtime can back production requests.

## Tests and executable evidence

Run `cargo +1.98.0 test --locked -p heptabao-raft-runtime` for the package and the full workspace commands from `README.md`. The primary executable regression bootstraps three voters, commits a bounded sealed envelope, proves all state machines converge, crosses ReadIndex, isolates the leader and proves no isolated commit, shuts down, reopens every durable store, crosses ReadIndex again and proves convergence. Store tests additionally cover interrupted atomic replacement, corruption, missing generations, stale predecessors, legacy adoption boundaries, symlink roots/generations, directory substitution and exact round-trip encoding.

## Evolution and open boundaries

The separate per-process path is now connected through `heptabao-server::ha::HaProcess`; the deterministic router remains a test helper and is not the production transport. The next gate executes real three-process failover, quorum-loss, snapshot transfer, restart and rolling-version-upgrade tests against that exact composition. Joint-consensus membership changes, witness/learner operation, production storage performance, disk-full behavior, mTLS/KMS custody, cross-platform destructive tests and independent linearizability campaigns remain open. This guide grants no compatibility, production, migration or release authority.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-raft-runtime`
- Crate path: `crates/heptabao-raft-runtime`
- Cargo manifest SHA-256: `688cceef93fca7a05c56f110d5213723170927e9cea644a909d26c4f3ead345b`
- Rust source files: `4`
- Public lexical declarations: `59`
- Discovered test functions: `27`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->

## Current remote-process path

`ProcessRaftNode` owns one voter. `RemoteNetworkFactory` transports vote, append
and snapshot RPC through the injected `RaftPeerRpc`. The server supplies bounded
mTLS framing and pinned peer identities; the consensus package never receives
public bearer credentials or decrypts application state. Do not apply the
in-process facade's wait-for-all-voters completion description to every remote
call: public success must be evaluated at the composed service boundary and
Raft's actual quorum/application receipt. The V2 source inventory binds both
paths and their discovered tests without treating either as a test-pass record.

The separate process runtime's default timers are heartbeat 200 ms and election
1000–2000 ms, allowing bounded mTLS and durable I/O rather than importing the
in-process fixture's 40/120/240 ms test timings. Linearizable reads still use
ReadIndex, not a clock-dependent lease shortcut. Real process behavior is
exercised by `qa/openbao-acceptance/ha_destructive.py`; scenario success, ignored
fault categories and the binary/source identity must be reported separately.
