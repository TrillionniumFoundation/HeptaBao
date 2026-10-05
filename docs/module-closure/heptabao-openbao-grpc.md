# heptabao-openbao-grpc module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`heptabao-openbao-grpc`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** owned OpenBao Wrapper RPC and AutoMTLS transport
- **Repository state:** `IMPLEMENTED_REVIEW_REQUIRED`.
- **Source root:** `crates/heptabao-openbao-grpc`; Rust files: `crates/heptabao-openbao-grpc/src/automatic_tls.rs`, `crates/heptabao-openbao-grpc/src/handshake.rs`, `crates/heptabao-openbao-grpc/src/lib.rs`, `crates/heptabao-openbao-grpc/src/linux_identity/tests.rs`, `crates/heptabao-openbao-grpc/src/linux_identity.rs`, `crates/heptabao-openbao-grpc/src/loopback_tests.rs`, `crates/heptabao-openbao-grpc/src/protocol.rs`, `crates/heptabao-openbao-grpc/src/tests.rs`, `crates/heptabao-openbao-grpc/src/transport.rs`.
- **Internal dependencies:** none.
- **Runtime placement:** `no/standalone or indirect; verify CURRENT_RUNTIME_MAP`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** struct `AutomaticHandshake`; fn `parse`; struct `PerLaunchClientIdentity`; fn `generate`; fn `public_certificate_pem`; struct `AutomaticWrapperTransport`; const `KMS_MAGIC_COOKIE_KEY`; const `KMS_MAGIC_COOKIE_VALUE`; const `KMS_APPLICATION_VERSION`; enum `TransportKind`; enum `LocalEndpoint`; struct `PublicHandshake`; fn `parse`; fn `endpoint`; fn `automatic_launch_admission`; mod `automatic_tls`; mod `handshake`; mod `linux_identity`; mod `protocol`; mod `transport`; enum `BridgeError`; struct `OwnedPluginIdentity`; fn `validate`; struct `HostLifecycle`; trait `IdentityProbe`; enum `RpcAuthentication`; enum `WrapperMethod`; const `fn`; trait `WrapperRpcTransport`; struct `RpcLimits`

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `crates/heptabao-openbao-grpc`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. heptabao-openbao-grpc has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: `BridgeError::InvalidHandshake`; `BridgeError::AutoMtlsWireContractUnavailable`; `BridgeError::InvalidBinding`; `BridgeError::ProcessObservationUnavailable`; `BridgeError::IdentityChanged`; `BridgeError::LifecycleDenied`; `BridgeError::UnauthenticatedTransport`; `BridgeError::InvalidState`; `BridgeError::InvalidLimits`; `BridgeError::InvalidOptions`; `BridgeError::InvalidResponse`; `BridgeError::MessageTooLarge`; `BridgeError::BeforeDispatch`; `BridgeError::OutcomeUnknown`

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** portable repository-relative source SHA-256 `b598afed505130e0d201411b9a68971f1246b74f8eda56590f2f705125b8cac6`; manifest SHA-256 `1d283990770b8a2fe75e3c2c85c1d64216f085bce673f0a69de6ceba052b134e`.
- **Named executable anchor:** `automatic_handshake_has_one_literal_six_field_certificate_contract` in `crates/heptabao-openbao-grpc/src/automatic_tls.rs`.
- **Required command:** `cargo +1.99.0 test --locked -p heptabao-openbao-grpc` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit.

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
