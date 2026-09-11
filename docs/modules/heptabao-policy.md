# heptabao-policy

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns deterministic path-capability policy evaluation. It does not authenticate callers, expand identities, store policies durably or implement deny overrides, templating or Sentinel-style evaluation.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-policy`; Cargo SHA-256 `7ac2233dc0a58b056b87f400d97335c42dc29109deeca52d52ae39835bce3b25`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `Capability` | `crates/heptabao-policy/src/lib.rs:13` | `pub enum Capability {` |
| `struct` | `PolicyRule` | `crates/heptabao-policy/src/lib.rs:23` | `pub struct PolicyRule {` |
| `fn` | `new` | `crates/heptabao-policy/src/lib.rs:29` | `pub fn new(` |
| `fn` | `path_prefix` | `crates/heptabao-policy/src/lib.rs:42` | `pub fn path_prefix(&self) -> &CanonicalPath {` |
| `fn` | `capabilities` | `crates/heptabao-policy/src/lib.rs:46` | `pub fn capabilities(&self) -> &BTreeSet<Capability> {` |
| `struct` | `Policy` | `crates/heptabao-policy/src/lib.rs:58` | `pub struct Policy {` |
| `fn` | `new` | `crates/heptabao-policy/src/lib.rs:64` | `pub fn new(id: Id, rules: Vec<PolicyRule>) -> Result<Self, PolicyError> {` |
| `fn` | `id` | `crates/heptabao-policy/src/lib.rs:71` | `pub fn id(&self) -> &Id {` |
| `fn` | `rules` | `crates/heptabao-policy/src/lib.rs:75` | `pub fn rules(&self) -> &[PolicyRule] {` |
| `struct` | `PolicyStore` | `crates/heptabao-policy/src/lib.rs:81` | `pub struct PolicyStore {` |
| `fn` | `insert` | `crates/heptabao-policy/src/lib.rs:86` | `pub fn insert(&mut self, policy: Policy) -> Result<(), PolicyError> {` |
| `fn` | `remove` | `crates/heptabao-policy/src/lib.rs:94` | `pub fn remove(&mut self, id: &Id) -> Result<Policy, PolicyError> {` |
| `fn` | `get` | `crates/heptabao-policy/src/lib.rs:98` | `pub fn get(&self, id: &Id) -> Result<&Policy, PolicyError> {` |
| `fn` | `authorize` | `crates/heptabao-policy/src/lib.rs:102` | `pub fn authorize(` |
| `enum` | `PolicyError` | `crates/heptabao-policy/src/lib.rs:120` | `pub enum PolicyError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Policies are immutable after insertion in the current candidate. The store supports insert, get and remove. Rules match canonical paths only at exact or segment-prefix boundaries.

## Invariants and authorization

Authorization is default deny. Empty rules and empty capability sets are rejected. `Sudo` satisfies any capability only for a matching path prefix; a policy identifier that is absent from the store grants nothing.

## Failure, retry and reconciliation

Duplicate and missing-policy errors are deterministic before any external effect. Evaluation returns a boolean and has no ambiguous outcome or retry state.

## Concurrency and ordering

The package has no interior synchronization. A composition root serializes mutations to `PolicyStore` and may share immutable evaluation references concurrently.

## Security and privacy

Policy errors do not contain request paths or identities. The evaluator assumes inputs were canonicalized by `heptabao-domain` and never treats authentication as authorization.

## Persistence and compatibility

No persisted policy encoding is owned yet. A future encoding must version capabilities, preserve default deny and reject unknown mandatory capability values.

## Observability

The package emits no events directly. The service composition records allow/deny outcomes using bounded event names without embedding secret paths or token material.

## Operations

Policy changes are explicit store mutations. Production operation still requires durable storage, policy revision history and an audited administrative API.

## Tests and executable evidence

`cargo test -p heptabao-policy` proves default denial, capability separation, segment-bounded matching and duplicate rejection. Workspace Clippy runs with warnings denied.

## Evolution and open boundaries

Deny rules, parameter constraints, response wrapping, control groups and policy templates remain open. Adding them must preserve deterministic evaluation and explicit conflict precedence.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-policy`
- Crate path: `crates/heptabao-policy`
- Cargo manifest SHA-256: `7ac2233dc0a58b056b87f400d97335c42dc29109deeca52d52ae39835bce3b25`
- Rust source files: `1`
- Public lexical declarations: `15`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
