# heptabao-compatibility

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns differential response/side-effect observations and fail-closed compatibility admission. It does not generate Oracle observations or grant release authority.

## Public API and ownership

`CompatibilityMatrix` owns uniquely keyed observations for one profile. Each observation binds expected and actual response and side-effect digests.

## State and data model

Observation results are match, response mismatch, side-effect mismatch or missing actual. A claim can be admitted only from a nonempty all-match matrix with independent origin.

## Invariants and authorization

Repository-controlled evidence cannot self-admit compatibility. A matching response with mismatched side effects still fails.

## Failure, retry and reconciliation

Missing or mismatched observations require new attributable measurement; they cannot be waived by retrying a validator.

## Concurrency and ordering

The matrix is assembled before admission. Concurrent collectors must deduplicate operation identifiers and preserve provenance externally.

## Security and privacy

Only digests and operation identifiers are stored. Fixture sanitation and Oracle/implementation lane separation remain required.

## Persistence and compatibility

No external evidence envelope is owned here; existing schemas and admission protocols bind provenance, signer and exact source identity.

## Observability

Coverage, mismatch class and admitted profile may be reported. Raw Oracle requests, responses and secrets are not telemetry labels.

## Operations

Operators publish a claim only after independent evidence admission. Revocation takes precedence when a regression or provenance defect appears.

## Tests and executable evidence

`cargo test -p heptabao-compatibility` proves repository self-admission rejection and side-effect mismatch blocking.

## Evolution and open boundaries

Endpoint inventory, error precedence, streaming, upgrade trains and full OpenBao matrices remain evidence-generation work.
