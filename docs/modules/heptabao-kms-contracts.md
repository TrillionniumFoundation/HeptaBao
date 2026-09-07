# heptabao-kms-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns provider-neutral key lifecycle, wrapping context, secret buffer and operation-outcome contracts for KMS integration. It does not implement cryptography, contact a cloud KMS or HSM, manage credentials, attest hardware or create signing and custody authority.

## Public API and ownership

`KeyCatalog` owns registered key version, capabilities, lifecycle state and generation. `WrapCommand` and `UnwrapCommand` bind one operation ID, key ID/version and `WrappingContext`; a `KmsProvider` consumes commands and returns a typed `KmsOutcome` rather than an ambiguous generic error.

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
