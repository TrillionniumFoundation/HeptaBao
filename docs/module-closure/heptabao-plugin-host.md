# heptabao-plugin-host module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`heptabao-plugin-host`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** durable sandbox-wrapper invocation and dynamic lease lifecycle
- **Repository state:** `IMPLEMENTED_REVIEW_REQUIRED`.
- **Source root:** `crates/heptabao-plugin-host`; Rust files: `crates/heptabao-plugin-host/src/command_runner.rs`, `crates/heptabao-plugin-host/src/command_runner_tests.rs`, `crates/heptabao-plugin-host/src/durable.rs`, `crates/heptabao-plugin-host/src/lib.rs`.
- **Internal dependencies:** `heptabao-domain`, `heptabao-durable-service`, `heptabao-plugin-contracts`.
- **Runtime placement:** `no/standalone or indirect; verify CURRENT_RUNTIME_MAP`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** struct `PluginMutationContext`; fn `new`; fn `principal`; fn `request_id`; struct `PendingPluginInvocation`; enum `DurableReconciliationDecision`; struct `DurableDynamicSecretBroker`; fn `create_new`; fn `reopen`; fn `host_state`; fn `pending_invocation`; fn `upgrade`; fn `view`; fn `issue`; fn `renew`; fn `revoke`; fn `reconcile`; enum `PluginOperation`; struct `PluginLimits`; fn `validate`; struct `SandboxBinding`; fn `new`; struct `PluginManifest`; fn `new`; fn `descriptor`; fn `sandbox`; const `fn`; fn `operations`; fn `environment_allowlist`; struct `SecretEnvironment`

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `crates/heptabao-plugin-host`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. heptabao-plugin-host has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: `SandboxFailure::BeforeEntry`; `SandboxFailure::OutcomeUnknownAfterEntry`; `PluginHostError::Domain`; `PluginHostError::InvalidLimits`; `PluginHostError::InvalidSandboxBinding`; `PluginHostError::InvalidEnvironment`; `PluginHostError::PluginNotEnabled`; `PluginHostError::SandboxUnavailable`; `PluginHostError::CapabilityDenied`; `PluginHostError::RequestTooLarge`; `PluginHostError::ResponseTooLarge`; `PluginHostError::MalformedResponse`; `PluginHostError::EnvironmentDenied`; `PluginHostError::ProcessBeforeEntry`; `PluginHostError::ProcessOutcomeUnknown`; `PluginHostError::ReconciliationRequired`; `PluginHostError::InvalidReconciliation`; `PluginHostError::PluginRevoked`; `PluginHostError::InvalidLeaseTtl`; `PluginHostError::DuplicateLease`; `PluginHostError::MissingLease`; `PluginHostError::LeaseNotRenewable`

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** portable repository-relative source SHA-256 `77072c9cdad67527b4f48b3ee53de0b358c9e8d13441137cde79e42d1161febd`; manifest SHA-256 `e3b38eb71633b42def1909170307da08a6a6f0ff6e892bb57cf613d745449d87`.
- **Named executable anchor:** `blocked_stdin_obeys_deadline_before_any_output` in `crates/heptabao-plugin-host/src/command_runner_tests.rs`.
- **Required command:** `cargo +1.98.0 test --locked -p heptabao-plugin-host` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit.

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
