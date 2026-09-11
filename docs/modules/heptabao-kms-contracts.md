# heptabao-kms-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns provider-neutral key lifecycle, wrapping context, secret buffer and operation-outcome contracts for KMS integration. It does not implement cryptography, contact a cloud KMS or HSM, manage credentials, attest hardware or create signing and custody authority.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-kms-contracts`; Cargo SHA-256 `06bf9f721dfcbfbde4222a5ca33d232c614be54e2ddcf337b26d2b967b0053fc`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_WRAPPED_VALUE_BYTES` | `crates/heptabao-kms-contracts/src/lib.rs:12` | `pub const MAX_WRAPPED_VALUE_BYTES: usize = 2 * 1024 * 1024;` |
| `enum` | `KmsCapability` | `crates/heptabao-kms-contracts/src/lib.rs:15` | `pub enum KmsCapability {` |
| `enum` | `KeyState` | `crates/heptabao-kms-contracts/src/lib.rs:22` | `pub enum KeyState {` |
| `struct` | `KeyVersion` | `crates/heptabao-kms-contracts/src/lib.rs:30` | `pub struct KeyVersion(u64);` |
| `fn` | `new` | `crates/heptabao-kms-contracts/src/lib.rs:33` | `pub fn new(value: u64) -> Result<Self, KmsError> {` |
| `const` | `fn` | `crates/heptabao-kms-contracts/src/lib.rs:40` | `pub const fn as_u64(self) -> u64 {` |
| `struct` | `KeyRegistration` | `crates/heptabao-kms-contracts/src/lib.rs:46` | `pub struct KeyRegistration {` |
| `struct` | `KeyView` | `crates/heptabao-kms-contracts/src/lib.rs:53` | `pub struct KeyView {` |
| `struct` | `KeyCatalog` | `crates/heptabao-kms-contracts/src/lib.rs:83` | `pub struct KeyCatalog {` |
| `fn` | `register` | `crates/heptabao-kms-contracts/src/lib.rs:88` | `pub fn register(&mut self, registration: KeyRegistration) -> Result<KeyView, KmsError> {` |
| `fn` | `view` | `crates/heptabao-kms-contracts/src/lib.rs:107` | `pub fn view(&self, key_id: &Id) -> Result<KeyView, KmsError> {` |
| `fn` | `require_operation` | `crates/heptabao-kms-contracts/src/lib.rs:114` | `pub fn require_operation(` |
| `fn` | `disable` | `crates/heptabao-kms-contracts/src/lib.rs:138` | `pub fn disable(&mut self, key_id: &Id) -> Result<KeyView, KmsError> {` |
| `fn` | `enable` | `crates/heptabao-kms-contracts/src/lib.rs:151` | `pub fn enable(&mut self, key_id: &Id) -> Result<KeyView, KmsError> {` |
| `fn` | `schedule_destruction` | `crates/heptabao-kms-contracts/src/lib.rs:164` | `pub fn schedule_destruction(` |
| `fn` | `destroy` | `crates/heptabao-kms-contracts/src/lib.rs:185` | `pub fn destroy(&mut self, key_id: &Id, now: Tick) -> Result<KeyView, KmsError> {` |
| `struct` | `WrappingContext` | `crates/heptabao-kms-contracts/src/lib.rs:203` | `pub struct WrappingContext {` |
| `fn` | `new` | `crates/heptabao-kms-contracts/src/lib.rs:210` | `pub fn new(` |
| `struct` | `WrappedValue` | `crates/heptabao-kms-contracts/src/lib.rs:227` | `pub struct WrappedValue(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-kms-contracts/src/lib.rs:230` | `pub fn new(bytes: Vec<u8>) -> Result<Self, KmsError> {` |
| `fn` | `expose` | `crates/heptabao-kms-contracts/src/lib.rs:237` | `pub fn expose(&self) -> &[u8] {` |
| `fn` | `len` | `crates/heptabao-kms-contracts/src/lib.rs:241` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-kms-contracts/src/lib.rs:245` | `pub fn is_empty(&self) -> bool {` |
| `struct` | `WrapCommand` | `crates/heptabao-kms-contracts/src/lib.rs:267` | `pub struct WrapCommand {` |
| `struct` | `UnwrapCommand` | `crates/heptabao-kms-contracts/src/lib.rs:276` | `pub struct UnwrapCommand {` |
| `enum` | `RetryDisposition` | `crates/heptabao-kms-contracts/src/lib.rs:285` | `pub enum RetryDisposition {` |
| `enum` | `KmsOutcome` | `crates/heptabao-kms-contracts/src/lib.rs:292` | `pub enum KmsOutcome<T> {` |
| `fn` | `retry_disposition` | `crates/heptabao-kms-contracts/src/lib.rs:299` | `pub fn retry_disposition(&self) -> RetryDisposition {` |
| `trait` | `KmsProvider` | `crates/heptabao-kms-contracts/src/lib.rs:314` | `pub trait KmsProvider {` |
| `enum` | `KmsError` | `crates/heptabao-kms-contracts/src/lib.rs:320` | `pub enum KmsError {` |
| `const` | `fn` | `crates/heptabao-kms-contracts/src/lib.rs:341` | `pub const fn is_retryable_before_entry(self) -> bool {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Key state advances among enabled, disabled, pending destruction and destroyed, with generation incremented for each accepted transition. `KeyVersion` is nonzero. `WrappedValue` is bounded, redacted and zeroed on drop; plaintext is carried only by the shared redacted `SecretValue` type.

## Invariants and authorization

Every registered key declares at least one capability. Operations require the exact key version, enabled state and requested capability. Associated-data digests cannot be all-zero, destruction requires a future not-before tick, and destroyed keys can never be re-enabled by the catalog.

## Failure, retry and reconciliation

`FailedBeforeEntry` is distinguishable from `OutcomeUnknownAfterEntry`. Only a provider-unavailable error proven before entry is eligible for a new operation ID; an unknown wrap or unwrap result is `ReconcileOnly` and retains a redacted reconciliation reference until authoritative readback or provider evidence resolves it.

## Concurrency and ordering

`KeyCatalog` has no internal lock and must be mutated by a serialized custody controller. Version/state/capability validation occurs immediately at the provider entry boundary. Destruction scheduling and execution must be durably ordered with audit and recovery records before external provider calls are considered complete.

## Security and privacy

Plaintext, ciphertext and reconciliation identifiers are absent from ordinary diagnostics or represented by redacted types. Provider credentials, key material, PINs, attestation documents and unwrap results must never enter logs, arguments or repository fixtures. Production use requires least-privilege identities and independent custody controls.

## Persistence and compatibility

The crate defines no vendor wire format. Persisted catalogs must version key IDs, provider identity, key version, capabilities, state, generation and destruction deadline. Provider-specific ciphertext formats require explicit algorithm/version metadata and migration tests before stable compatibility can be claimed.

## Observability

Recommended events are key registration, enable/disable, destruction scheduling, provider entry, before-entry failure, unknown outcome and reconciliation completion. Labels are limited to provider class, capability and outcome; key IDs, ciphertext, plaintext, credentials and reconciliation references are not exported.

## Operations

Operator procedures must include bootstrap, rotation, provider outage, disabled-key recovery, pending destruction cancellation policy, irreversible destruction approval and ambiguous operation reconciliation. Repository code cannot substitute for real dual control, hardware attestation or cloud-account custody.

## Tests and executable evidence

`cargo test -p heptabao-kms-contracts` verifies capability/version checks, monotonic lifecycle, delayed destruction, retry classification and secret diagnostic redaction. The V2 validator binds this package to the capability matrix and requires this guide and test surface.

## Evolution and open boundaries

Cloud and HSM adapters, data-key generation, cryptographic algorithm negotiation, provider attestation, multi-region failover, durable reconciliation and real signer/KMS custody evidence remain open. `HB-BLK-EXT-004` therefore remains external even after this repository contract is implemented.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-kms-contracts`
- Crate path: `crates/heptabao-kms-contracts`
- Cargo manifest SHA-256: `06bf9f721dfcbfbde4222a5ca33d232c614be54e2ddcf337b26d2b967b0053fc`
- Rust source files: `1`
- Public lexical declarations: `31`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
