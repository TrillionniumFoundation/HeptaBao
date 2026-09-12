# heptabao-domain

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded identifiers, canonical resource paths, monotonic ticks and repository-owned secret byte buffers. It does not provide authentication, policy evaluation, persistence, random generation, locked memory or cryptography.

## Public API and ownership

### Current API contract and integration boundary

`Id::parse` owns a 1–64 byte lowercase ASCII/digit identifier with internal `-`/`_` allowed and neither at a boundary. `CanonicalPath::parse` owns an absolute path of at most 1024 bytes; `/` is valid, while empty segments, trailing `/`, `.`/`..` segments and unsupported characters are rejected. Path segments allow ASCII alphanumerics plus `-`, `_`, `.`, `:`. Parsing validates input and does not normalize encoded traversal or URL-escape sequences; the transport must decode and validate its own syntax before constructing a domain path.

`child(&Id)` constructs and revalidates a path; `matches_prefix` compares segment boundaries and treats `/` as universal. `relative_to` borrows its result from the path. Equality returns an empty relative path; a root prefix strips the leading slash, so `/app`.relative_to(`/`) returns `Some("app")`. A nonmatching or partial-segment prefix returns `None`. The caller must still bind the namespace separately.

`Tick::new` wraps a caller-supplied `u64`; only `checked_add(delta)` detects overflow (`TickOverflow`). No method proves monotonicity or a clock unit. `SecretValue::new(Vec<u8>)` takes ownership of 1 byte through 1 MiB; `expose()` lends a byte slice and `Clone` creates another owned secret copy. `Debug` redacts bytes, and `Drop` fills this vector with zeroes. This is not a guaranteed compiler-resistant wipe, locked memory or zeroization of caller-created copies.

The crate is a shared model primitive outside the current server dependency closure. Its dependent candidate services own authorization and effect boundaries; current server/durable-service representations are separate and require explicit conversion if integrated.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-domain`; Cargo SHA-256 `d0c3fb4ef5719cc4add370b5188355008b6c269c57cefdced1d7dd026c339ec8`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_ID_BYTES` | `crates/heptabao-domain/src/lib.rs:9` | `pub const MAX_ID_BYTES: usize = 64;` |
| `const` | `MAX_PATH_BYTES` | `crates/heptabao-domain/src/lib.rs:10` | `pub const MAX_PATH_BYTES: usize = 1024;` |
| `const` | `MAX_SECRET_BYTES` | `crates/heptabao-domain/src/lib.rs:11` | `pub const MAX_SECRET_BYTES: usize = 1024 * 1024;` |
| `enum` | `DomainError` | `crates/heptabao-domain/src/lib.rs:14` | `pub enum DomainError {` |
| `struct` | `Id` | `crates/heptabao-domain/src/lib.rs:51` | `pub struct Id(String);` |
| `fn` | `parse` | `crates/heptabao-domain/src/lib.rs:54` | `pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {` |
| `fn` | `as_str` | `crates/heptabao-domain/src/lib.rs:77` | `pub fn as_str(&self) -> &str {` |
| `struct` | `CanonicalPath` | `crates/heptabao-domain/src/lib.rs:95` | `pub struct CanonicalPath(String);` |
| `fn` | `parse` | `crates/heptabao-domain/src/lib.rs:98` | `pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {` |
| `fn` | `root` | `crates/heptabao-domain/src/lib.rs:128` | `pub fn root() -> Self {` |
| `fn` | `as_str` | `crates/heptabao-domain/src/lib.rs:132` | `pub fn as_str(&self) -> &str {` |
| `fn` | `child` | `crates/heptabao-domain/src/lib.rs:136` | `pub fn child(&self, child: &Id) -> Result<Self, DomainError> {` |
| `fn` | `matches_prefix` | `crates/heptabao-domain/src/lib.rs:145` | `pub fn matches_prefix(&self, prefix: &Self) -> bool {` |
| `fn` | `relative_to` | `crates/heptabao-domain/src/lib.rs:156` | `pub fn relative_to<'a>(&'a self, prefix: &Self) -> Option<&'a str> {` |
| `struct` | `Tick` | `crates/heptabao-domain/src/lib.rs:182` | `pub struct Tick(u64);` |
| `const` | `fn` | `crates/heptabao-domain/src/lib.rs:185` | `pub const fn new(value: u64) -> Self {` |
| `const` | `fn` | `crates/heptabao-domain/src/lib.rs:189` | `pub const fn as_u64(self) -> u64 {` |
| `fn` | `checked_add` | `crates/heptabao-domain/src/lib.rs:193` | `pub fn checked_add(self, delta: u64) -> Result<Self, DomainError> {` |
| `struct` | `SecretValue` | `crates/heptabao-domain/src/lib.rs:202` | `pub struct SecretValue {` |
| `fn` | `new` | `crates/heptabao-domain/src/lib.rs:207` | `pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError> {` |
| `fn` | `expose` | `crates/heptabao-domain/src/lib.rs:217` | `pub fn expose(&self) -> &[u8] {` |
| `fn` | `len` | `crates/heptabao-domain/src/lib.rs:221` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-domain/src/lib.rs:225` | `pub fn is_empty(&self) -> bool {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

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

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::identifier_and_path_validation_are_fail_closed`](../../crates/heptabao-domain/src/lib.rs) checks representative identifier and traversal rejection.
- [`tests::relative_paths_respect_segment_boundaries`](../../crates/heptabao-domain/src/lib.rs) checks root and non-root prefixes and rejects a partial segment.
- [`tests::tick_addition_detects_overflow`](../../crates/heptabao-domain/src/lib.rs) checks overflow returns a classified error.
- [`tests::secret_debug_output_is_redacted`](../../crates/heptabao-domain/src/lib.rs) checks diagnostic redaction, not physical-memory erasure.

`cargo test -p heptabao-domain` covers identifier/path rejection, segment-boundary prefix matching, secret debug redaction and tick overflow. The current workspace CI compiles and lints the same source.

## Evolution and open boundaries

Future work may add typed namespace/resource identifiers, but it must preserve canonical parsing and redaction. Operating-system memory protection and cryptographic key containers remain provider-level work.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-domain`
- Crate path: `crates/heptabao-domain`
- Cargo manifest SHA-256: `d0c3fb4ef5719cc4add370b5188355008b6c269c57cefdced1d7dd026c339ec8`
- Rust source files: `1`
- Public lexical declarations: `23`
- Discovered test functions: `4`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
