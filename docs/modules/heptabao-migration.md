# heptabao-migration

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns migration writer authority from planning through cutover or rollback. It does not copy bytes, compare datasets or execute provider-specific fencing.

## Public API and ownership

`MigrationState` owns source and target identifiers, phase, writer flags and generation. Its methods are the only allowed authority transitions.

## State and data model

The source begins as sole writer. It is fenced before copying. Target activation is allowed only after copy verification. Rollback after cutover requires target fencing first.

## Invariants and authorization

Source and target writer flags may never both be true. Identical endpoints and out-of-order transitions are rejected.

## Failure, retry and reconciliation

Transition errors occur before authority change. Provider fencing with unknown results must stop both writers and require authoritative readback before continuing.

## Concurrency and ordering

One migration coordinator serializes state. Source fence completion happens before copying and target fence completion happens before rollback.

## Security and privacy

The state machine contains endpoint identifiers only. Copy credentials, secret material and provider errors are outside this package and must not enter telemetry.

## Persistence and compatibility

No persisted migration record is owned. Production recovery must durably record every phase and fence receipt before executing the next transition.

## Observability

Recommended events are migration phase change, writer fenced, cutover, rollback and overlap rejection, with bounded state/outcome labels.

## Operations

Operators follow plan, source fence, copy, verify, activate. Any unexplained writer overlap is an incident and invalidates migration authority.

## Tests and executable evidence

`cargo test -p heptabao-migration` proves overlap-free cutover and mandatory target fencing before rollback.

## Evolution and open boundaries

Live incremental copy, checksums, throttling, abort recovery and cross-version format conversion remain provider and integration work.
