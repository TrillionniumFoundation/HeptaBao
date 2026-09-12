# heptabao-compatibility

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns an exact compatibility surface denominator, differential response/side-effect observations and fail-closed compatibility admission. It does not generate Oracle observations or grant release authority.

## Public API and ownership

### Current API contract and integration boundary

`SurfaceCatalog::new(profile_id, inventory_sha256, requirements)` owns an immutable map of unique `SurfaceId` requirements. A surface ID is at most 96 bytes; the catalog permits 1–1024 surfaces and each minimum count is a `NonZeroU16`. Empty/duplicate/oversized catalogs and zero inventory digests fail construction. The catalog digest is supplied by the caller; this crate does not hash or load the inventory artifact.

`CompatibilityMatrix::new(catalog)` owns observations keyed by operation ID. `add(Observation)` rejects undeclared surfaces, reused operation IDs and more than 65,536 observations. An observation compares both response and side-effect digests, treating absent actual data as a mismatch class. `coverage()` reports surfaces meeting their minimum observation count separately from matching observations; a counted surface can still contain a mismatch, which blocks `complete()`/admission.

`admit(EvidenceBinding)` requires independent origin, nonzero distinct oracle/candidate artifact digests, the exact catalog inventory digest, complete minima and no mismatches. It returns an owned `CompatibilityClaim`; it does not write a release record or revoke an earlier claim. `EvidenceOrigin::Independent` is caller-supplied metadata, not authenticated provenance: the evidence adapter must verify signatures, artifact hashing and oracle/candidate independence before invoking admission. Public report/claim fields also mean manually constructed values are not equivalent to successful `admit` evidence.

This crate is an evidence evaluator outside the current server dependency closure. It never implements OpenBao endpoints, executes differential tests or changes qualification flags. Test fixture admission demonstrates the rule, not product compatibility with OpenBao.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-compatibility`; Cargo SHA-256 `acb3b12563e57626ecc37ad0f01c0a0b47c113e17a6fee76a3ccaa1e44a0712f`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `SurfaceId` | `crates/heptabao-compatibility/src/lib.rs:23` | `pub struct SurfaceId(String);` |
| `fn` | `parse` | `crates/heptabao-compatibility/src/lib.rs:26` | `pub fn parse(value: impl Into<String>) -> Result<Self, CompatibilityError> {` |
| `fn` | `as_str` | `crates/heptabao-compatibility/src/lib.rs:44` | `pub fn as_str(&self) -> &str {` |
| `enum` | `EvidenceOrigin` | `crates/heptabao-compatibility/src/lib.rs:62` | `pub enum EvidenceOrigin {` |
| `struct` | `EvidenceBinding` | `crates/heptabao-compatibility/src/lib.rs:68` | `pub struct EvidenceBinding {` |
| `fn` | `validate` | `crates/heptabao-compatibility/src/lib.rs:76` | `pub fn validate(self) -> Result<Self, CompatibilityError> {` |
| `struct` | `SurfaceRequirement` | `crates/heptabao-compatibility/src/lib.rs:89` | `pub struct SurfaceRequirement {` |
| `struct` | `SurfaceCatalog` | `crates/heptabao-compatibility/src/lib.rs:95` | `pub struct SurfaceCatalog {` |
| `fn` | `new` | `crates/heptabao-compatibility/src/lib.rs:102` | `pub fn new(` |
| `fn` | `profile_id` | `crates/heptabao-compatibility/src/lib.rs:132` | `pub fn profile_id(&self) -> &Id {` |
| `const` | `fn` | `crates/heptabao-compatibility/src/lib.rs:136` | `pub const fn inventory_sha256(&self) -> [u8; 32] {` |
| `fn` | `requirements` | `crates/heptabao-compatibility/src/lib.rs:140` | `pub fn requirements(&self) -> impl Iterator<Item = &SurfaceRequirement> {` |
| `fn` | `len` | `crates/heptabao-compatibility/src/lib.rs:144` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-compatibility/src/lib.rs:148` | `pub fn is_empty(&self) -> bool {` |
| `enum` | `ObservationResult` | `crates/heptabao-compatibility/src/lib.rs:154` | `pub enum ObservationResult {` |
| `struct` | `Observation` | `crates/heptabao-compatibility/src/lib.rs:162` | `pub struct Observation {` |
| `fn` | `result` | `crates/heptabao-compatibility/src/lib.rs:172` | `pub fn result(&self) -> ObservationResult {` |
| `struct` | `CoverageReport` | `crates/heptabao-compatibility/src/lib.rs:190` | `pub struct CoverageReport {` |
| `fn` | `complete` | `crates/heptabao-compatibility/src/lib.rs:200` | `pub fn complete(&self) -> bool {` |
| `enum` | `ClaimStatus` | `crates/heptabao-compatibility/src/lib.rs:208` | `pub enum ClaimStatus {` |
| `struct` | `CompatibilityClaim` | `crates/heptabao-compatibility/src/lib.rs:215` | `pub struct CompatibilityClaim {` |
| `struct` | `CompatibilityMatrix` | `crates/heptabao-compatibility/src/lib.rs:224` | `pub struct CompatibilityMatrix {` |
| `fn` | `new` | `crates/heptabao-compatibility/src/lib.rs:230` | `pub fn new(catalog: SurfaceCatalog) -> Self {` |
| `fn` | `add` | `crates/heptabao-compatibility/src/lib.rs:237` | `pub fn add(&mut self, observation: Observation) -> Result<(), CompatibilityError> {` |
| `fn` | `coverage` | `crates/heptabao-compatibility/src/lib.rs:256` | `pub fn coverage(&self) -> CoverageReport {` |
| `fn` | `admit` | `crates/heptabao-compatibility/src/lib.rs:295` | `pub fn admit(` |
| `fn` | `observed_surface_ids` | `crates/heptabao-compatibility/src/lib.rs:322` | `pub fn observed_surface_ids(&self) -> BTreeSet<SurfaceId> {` |
| `enum` | `CompatibilityError` | `crates/heptabao-compatibility/src/lib.rs:331` | `pub enum CompatibilityError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Observation results are match, response mismatch, side-effect mismatch or missing actual. `CoverageReport` lists missing surfaces and mismatched operations. A claim can be admitted only when every surface meets its declared minimum, every observation matches and the independent evidence binding matches the exact inventory digest.

## Invariants and authorization

Repository-controlled evidence cannot self-admit compatibility. Unknown surfaces, duplicate operations, zero or rebinding artifact digests, incomplete minimum counts and matching responses with mismatched side effects all fail closed.

## Failure, retry and reconciliation

Missing or mismatched observations require new attributable measurement against the bound artifact pair; they cannot be waived by retrying a validator, reducing the denominator or moving an operation to an undeclared surface.

## Concurrency and ordering

The catalog is frozen before collection and the matrix is assembled before admission. Concurrent collectors must deduplicate operation identifiers, retain one surface assignment and preserve provenance externally.

## Security and privacy

Only inventory/artifact digests, surface identifiers and operation identifiers are stored. Fixture sanitation and Oracle/implementation lane separation remain required; raw requests, responses, tokens and secrets are outside the model.

## Persistence and compatibility

The in-memory types own no persisted evidence envelope. `qa/openbao-acceptance/complete_surface_corpus_v1.json` freezes the OpenBao 2.6.2 denominator and is validated against its inventory SHA-256; signed external evidence formats must additionally bind provenance, signer and exact source identity.

## Observability

Required/observed surface counts, matching observation counts, missing surface identifiers, mismatch class and admitted profile may be reported. Raw Oracle requests, responses and secrets are not telemetry labels.

## Operations

Operators first validate the frozen 60-surface corpus, then collect the required cases against one exact Oracle/candidate pair. They publish a claim only after independent evidence admission. Revocation takes precedence when a regression, inventory drift or provenance defect appears.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::exact_denominator_and_minimum_count_are_mandatory`](../../crates/heptabao-compatibility/src/lib.rs) blocks admission when a surface lacks its declared number of observations.
- [`tests::repository_cannot_self_admit_compatibility`](../../crates/heptabao-compatibility/src/lib.rs) rejects an explicitly repository-controlled evidence binding.
- [`tests::side_effect_mismatch_blocks_admission`](../../crates/heptabao-compatibility/src/lib.rs) rejects matching responses whose side-effect digests differ.
- [`tests::unknown_surface_and_inventory_rebinding_fail_closed`](../../crates/heptabao-compatibility/src/lib.rs) checks unknown surfaces and evidence rebound to a different inventory.

`cargo +1.98.0 test -p heptabao-compatibility` proves exact-denominator enforcement, minimum observation counts, inventory/artifact binding, repository self-admission rejection and side-effect mismatch blocking. `python scripts/validate_compatibility_corpus.py` proves that all 60 inventoried surfaces are present exactly once and all 38 current scoped cases are mapped exactly once.

## Evolution and open boundaries

Fifty-four inventoried surfaces still have no executable fixture, and no surface has independent observation bound to the current exact head. Endpoint/error precedence, external auth, additional engines, streaming, HA, upgrade trains and full OpenBao observation remain repository and external evidence work tracked by `HB-V2-REP-016` and `HB-BLK-EXT-005`.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-compatibility`
- Crate path: `crates/heptabao-compatibility`
- Cargo manifest SHA-256: `acb3b12563e57626ecc37ad0f01c0a0b47c113e17a6fee76a3ccaa1e44a0712f`
- Rust source files: `1`
- Public lexical declarations: `28`
- Discovered test functions: `5`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
