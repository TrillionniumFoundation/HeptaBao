# heptabao-domain

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded identifiers, canonical resource paths, monotonic ticks and repository-owned secret byte buffers. It does not provide authentication, policy evaluation, persistence, random generation, locked memory or cryptography.

## Public API and ownership

`Id`, `CanonicalPath`, `Tick` and `SecretValue` are the authoritative shared value objects. Callers own lifecycle and persistence; this package owns validation, redacted formatting and buffer clearing for `SecretValue`.

## State and data model

The package is stateless. Values are immutable after construction except for secret-buffer clearing during drop. Limits are explicit constants and therefore testable by every dependent package.

## Invariants and authorization

Identifiers are bounded lowercase ASCII names. Paths are absolute, segment canonical and traversal-free. The package performs no authorization and must not be used as evidence that a path is permitted.

## Failure, retry and reconciliation

Construction errors occur before any value is returned and are safe to correct and retry. Tick overflow is deterministic. This package has no after-entry or reconciliation state.

## Concurrency and ordering

All public values are ordinary owned Rust values and contain no interior mutability. Callers may share immutable references without a package-level serialization point.

## Security and privacy

`SecretValue` redacts debug output and clears its owned vector on drop. This reduces accidental disclosure but does not claim locked pages, side-channel resistance, allocator scrubbing or crash-dump protection.

## Persistence and compatibility

The package owns no persisted format. Consumers that serialize these values must define an explicit format version and must not serialize secret data through debug representations.

## Observability

The package emits no metrics or events. Validation errors contain only classifications and never include the rejected identifier, path or secret bytes.

## Operations

There is no runtime service to operate. Limit changes are compatibility changes and require dependent-package review plus the current repository validation and Rust test suite.

## Tests and executable evidence

`cargo test -p heptabao-domain` covers identifier/path rejection, segment-boundary prefix matching, secret debug redaction and tick overflow. The current workspace CI compiles and lints the same source.

## Evolution and open boundaries

Future work may add typed namespace/resource identifiers, but it must preserve canonical parsing and redaction. Operating-system memory protection and cryptographic key containers remain provider-level work.
