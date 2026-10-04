# heptabao-openbao-grpc

Current source binding: [CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).
Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate implements bounded OpenBao Wrapper protobuf RPCs and authenticated go-plugin AutoMTLS transport. Its manifest is `crates/heptabao-openbao-grpc/Cargo.toml`; its source root is `crates/heptabao-openbao-grpc/src`. It has no direct workspace crate dependencies. The server's Linux adapter owns process creation, immutable executable/configuration descriptors, seal lifecycle and provider termination. This bridge does not grant a provider access to arbitrary server state or implement general OpenBao auth, database or secret plugins.

## Public API and ownership

`Session` owns the RPC state machine and consumes a `WrapperTransport` plus an `IdentityProbe`. `OwnedPluginIdentity` binds the captured process and executable/configuration identities; the trusted adapter must observe their actual values. `HostLifecycle` supplies the authoritative seal and configuration generation. `set_config`, `wrapper_type`, `key_id`, `init`, `encrypt`, `decrypt` and `finalize` use the exact `WrapperMethod` RPC paths. Their `*_before` forms retain a caller deadline. `RpcLimits` bounds messages and elapsed RPC time; configuration maps and options are validated before entry.

On Unix, `PerLaunchClientIdentity` creates a fresh client identity, `AutomaticHandshake::parse` validates the admitted private socket path and server certificate, and `AutomaticTransport::connect_after_owned_launch` binds TLS to the captured provider. The concrete Linux owner in `service_openbao_wrapper_linux.rs` supplies filesystem and process observations. A public handshake alone is insufficient authentication.

## State and data model

`SessionState` progresses from Created to Configured, Initialized and Finalized. A dropped or uncertain entered RPC leaves OutcomeUnknown. BlobInfo is opaque protocol data, carried with its exact protobuf representation and caller-bound associated data; the bridge does not reinterpret it as a local plaintext key. Secret buffers and per-launch private material use zeroizing ownership.

## Invariants and authorization

Every provider call requires the admitted mutual TLS transport, exact owner identity and unchanged configuration generation. Lifecycle checks forbid reconfiguration and finalization while unsealed. Expired deadlines deny entry. Encrypt and decrypt require an initialized session; malformed responses, oversized values and changed identities cannot produce accepted plaintext or silently reset the session.

## Failure, retry and reconciliation

`BridgeError::BeforeDispatch` identifies unavailable transport before provider entry. A timeout, canceled waiter, malformed entered response or changed identity yields an unknown outcome and fences the session. The bridge never retries an entered RPC. The Service owner must reconcile durable publication and withhold delivery when its provider or audit result is unknown.

## Concurrency and ordering

Session methods require exclusive mutable access. Readiness and the final pre-dispatch check use the same original deadline; a late readiness result cannot begin an RPC. Identity and lifecycle observations surround provider awaits. The server serializes barrier state publication and supervises the actual owned child through terminal wait.

## Security and privacy

The crate forbids unsafe Rust. Debug and error formatting redact process/configuration details, paths, transport status and secret values. AutoMTLS pins the per-launch peer certificate and admits only the private local socket. Process capture and directory ownership remain trusted platform boundaries, not claims of containment against a hostile same-UID process or hardware custody.

## Persistence and compatibility

The crate owns no durable application format. It implements the Wrapper wire messages in `protocol.rs`, including the seven exact RPC paths and opaque encrypted BlobInfo. The Service owns encrypted barrier envelopes, recovery credentials and schema floors. General plugin compatibility and OpenBao snapshot byte interchange are separate features.

## Observability

The bridge emits no logs or metrics. Callers may record fixed method/outcome classifications and bounded timing; they must not record RPC status text, configuration values, wrapped/plaintext buffers, certificates containing private material, PINs or provider credentials.

## Operations

Deployment must enroll the exact provider executable and private configuration, then let the server create and supervise each owned launch. Seal or configuration changes invalidate stale sessions. Unknown outcomes require reconciliation rather than launching a replacement and replaying a mutation. The Linux adapter keeps its short private socket directory descriptor through actual provider exit.

## Tests and executable evidence

`cargo +1.99.0 test --locked -p heptabao-openbao-grpc` exercises the crate. Named source scenarios in `src/tests.rs` include `seven_exact_rpc_paths_options_wrapper_identity_and_opaque_blob_are_used`, `timeout_fences_and_never_replays`, `dropped_rpc_waiter_leaves_unknown_outcome_without_replay` and `expired_ready_deadline_does_not_even_poll_readiness`. Transport tests exercise authenticated Unix-socket TLS. These are executable anchors; current-head test results and genuine provider runs must be recorded separately.

## Evolution and open boundaries

The server currently composes the Wrapper consumer; this does not establish every OpenBao plugin protocol or provider implementation. Real PKCS11/HSM custody, broader provider lifecycle behavior, backend recovery publication and full platform qualification remain distinct acceptance work.

## Independent module closure dossier

See [the module closure dossier](../module-closure/heptabao-openbao-grpc.md) for source ownership and acceptance boundaries.
