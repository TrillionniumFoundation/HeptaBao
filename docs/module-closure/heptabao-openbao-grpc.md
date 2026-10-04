# heptabao-openbao-grpc module closure dossier

## Design and state ownership

`crates/heptabao-openbao-grpc/src` owns the Wrapper RPC session, exact protobuf contract and authenticated AutoMTLS transport. `Session` serializes lifecycle transitions and retains uncertainty after an entered call. The concrete server adapter owns the child process, immutable executable/configuration descriptors, seal lifecycle and durable barrier/recovery publication. The crate has no direct internal workspace dependencies and owns no durable application state.

## Module boundaries and trust assumptions

IdentityProbe must observe actual owner identity and lifecycle at each boundary. A handshake string, PID, path or cached generation alone is insufficient. Mutual TLS binds the private local socket and fresh client identity to the admitted provider certificate. Same-UID adversarial containment, external hardware custody and general plugin compatibility are not supplied by this package. Secret material and provider error bodies must remain absent from diagnostics.

## Failure semantics and ordering

Expired deadlines and unavailable readiness deny provider entry. Entered timeout, cancellation, malformed response or identity change leaves OutcomeUnknown and prohibits replay. Configuration must precede initialization; encryption/decryption require an initialized session. Finalization and reconfiguration cannot bypass the authoritative sealed lifecycle. The Service retains responsibility for reconciliation, durable commit and post-audit delivery veto.

## Acceptance evidence

**Named executable anchor:** `timeout_fences_and_never_replays` in `crates/heptabao-openbao-grpc/src/tests.rs`.

Run `cargo +1.99.0 test --locked -p heptabao-openbao-grpc` on the exact candidate. Protocol golden bytes, all seven RPC paths, unknown-outcome fencing, readiness deadlines and authenticated transport have separate named source tests. Actual official SDK/PKCS11 provider runs and the full workspace gates are separate evidence; this dossier grants no current-head test success or replacement qualification.

## Known gaps and evolution

This package implements the Wrapper transport only. General auth/secret/database plugin protocols, every provider, independent process containment, hardware attestation and OpenBao snapshot interchange remain outside it. The current module guide describes the server integration and lifecycle owner in detail.
