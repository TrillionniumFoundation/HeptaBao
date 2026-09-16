# heptabao-compatibility module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`heptabao-compatibility`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** differential compatibility admission
- **Repository state:** `IMPLEMENTED_REVIEW_REQUIRED`.
- **Source root:** `crates/heptabao-compatibility`; Rust files: `crates/heptabao-compatibility/src/lib.rs`.
- **Internal dependencies:** `heptabao-domain`.
- **Runtime placement:** `no/standalone or indirect; verify CURRENT_RUNTIME_MAP`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** struct `SurfaceId`; fn `parse`; fn `as_str`; enum `EvidenceOrigin`; struct `EvidenceBinding`; fn `validate`; struct `SurfaceRequirement`; struct `SurfaceCatalog`; fn `new`; fn `profile_id`; const `fn`; fn `requirements`; fn `len`; fn `is_empty`; enum `ObservationResult`; struct `Observation`; fn `result`; struct `CoverageReport`; fn `complete`; enum `ClaimStatus`; struct `CompatibilityClaim`; struct `CompatibilityMatrix`; fn `new`; fn `add`; fn `coverage`; fn `admit`; fn `observed_surface_ids`; enum `CompatibilityError`

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `crates/heptabao-compatibility`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. heptabao-compatibility has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: `CompatibilityError::InvalidSurfaceId`; `CompatibilityError::DuplicateSurface`; `CompatibilityError::EmptyCatalog`; `CompatibilityError::CatalogTooLarge`; `CompatibilityError::UnknownSurface`; `CompatibilityError::DuplicateObservation`; `CompatibilityError::ObservationCapacityExceeded`; `CompatibilityError::MatrixMismatch`; `CompatibilityError::IncompleteCoverage`; `CompatibilityError::IndependentEvidenceRequired`; `CompatibilityError::InvalidEvidenceBinding`; `CompatibilityError::InventoryBindingMismatch`

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** source tree SHA-256 `5646d73b8c26c1905b896becc97d87ddb78b646831afe87edf0f66e4c3bf7ec8`; manifest SHA-256 `acb3b12563e57626ecc37ad0f01c0a0b47c113e17a6fee76a3ccaa1e44a0712f`.
- **Named executable anchor:** `repository_cannot_self_admit_compatibility` in `crates/heptabao-compatibility/src/lib.rs`.
- **Required command:** `cargo +1.98.0 test --locked -p heptabao-compatibility` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit. 

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
