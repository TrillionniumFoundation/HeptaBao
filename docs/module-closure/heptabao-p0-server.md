# heptabao-p0-server module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`heptabao-p0-server`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** loopback memory server
- **Repository state:** `INHERITED_IMPLEMENTED`.
- **Source root:** `crates/heptabao-p0-server`; Rust files: `crates/heptabao-p0-server/src/lib.rs`, `crates/heptabao-p0-server/src/main.rs`.
- **Internal dependencies:** `heptabao-protocol`.
- **Runtime placement:** `no/standalone or indirect; verify CURRENT_RUNTIME_MAP`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** const `P0_PROFILE`; const `P0_PRODUCTION_SUPPORTED`; const `P0_COMPATIBILITY_CLAIM`; const `P0_AUTHORITY_EFFECT`; struct `DevelopmentCredentials`; fn `new`; trait `AuditSink`; struct `MemoryAuditSink`; fn `with_failure_on`; fn `events`; struct `FileAuditSink`; fn `create_new`; fn `path`; struct `P0Server`; struct `P0Response`; fn `new`; fn `audit`; fn `generation`; fn `handle`; enum `AuditError`; enum `P0Error`

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `crates/heptabao-p0-server`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. heptabao-p0-server has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: `BodyError::InvalidUtf8`; `BodyError::InvalidObject`; `BodyError::UnexpectedShape`; `BodyError::InvalidEscape`; `BodyError::InvalidCharacter`; `BodyError::EmptyValue`; `AuditError::PathMustBeAbsolute`; `AuditError::InvalidPath`; `AuditError::UnsafePath`; `AuditError::PathAlreadyExists`; `AuditError::Io`; `AuditError::InjectedFailure`; `P0Error::WeakDevelopmentCredential`; `P0Error::Protocol`; `P0Error::Audit`

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** source tree SHA-256 `c590cfb9bb38f5a2a9313f43efb4717c256d19180180e692e59bc8fedbb092e6`; manifest SHA-256 `9aab2dfc3c34a4295478fa867bc246bf7bb97b9daf90d0507062c54677453962`.
- **Named executable anchor:** `fresh_server_starts_fail_closed_and_sealed` in `crates/heptabao-p0-server/src/lib.rs`.
- **Required command:** `cargo +1.98.0 test --locked -p heptabao-p0-server` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit. 

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
