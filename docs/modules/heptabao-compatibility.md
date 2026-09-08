# heptabao-compatibility

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns an exact compatibility surface denominator, differential response/side-effect observations and fail-closed compatibility admission. It does not generate Oracle observations or grant release authority.

## Public API and ownership

`SurfaceCatalog` owns the immutable inventory digest and minimum observation count for every declared surface. `CompatibilityMatrix` owns globally unique operation observations for that catalog. Each observation binds a surface identifier plus expected and actual response and side-effect digests; `EvidenceBinding` binds the exact inventory, Oracle artifact and candidate artifact.

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

`cargo +1.98.0 test -p heptabao-compatibility` proves exact-denominator enforcement, minimum observation counts, inventory/artifact binding, repository self-admission rejection and side-effect mismatch blocking. `python scripts/validate_compatibility_corpus.py` proves that all 60 inventoried surfaces are present exactly once and all 38 current scoped cases are mapped exactly once.

## Evolution and open boundaries

Fifty-four inventoried surfaces still have no executable fixture, and no surface has independent observation bound to the current exact head. Endpoint/error precedence, external auth, additional engines, streaming, HA, upgrade trains and full OpenBao observation remain repository and external evidence work tracked by `HB-V2-REP-016` and `HB-BLK-EXT-005`.
