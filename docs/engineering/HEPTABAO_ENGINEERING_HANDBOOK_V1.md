# HeptaBao Engineering Handbook V1

This handbook contains cross-cutting engineering rules. Module guides must link here instead of copying these rules verbatim.

## Source and status truth

An exact Git commit and tree are the source identity. A branch, pull-request title, status file or successful run from another SHA is not equivalent evidence. Current project status is selected only by `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`.

Repository implementation, environment qualification and operational authority are different states. Source may be complete while production authority remains false.

## Identifiers and paths

Repository-owned identifiers are bounded ASCII values. Canonical resource paths:

- start with `/`;
- contain no empty, `.` or `..` segment;
- contain no control characters or query/fragment component;
- use segment-boundary prefix matching;
- are rejected rather than silently normalized when ambiguous.

## Failure and retry taxonomy

Every public operation must classify failures into one of these categories:

- **before entry** — the effect closure was not entered; a caller may retry according to the operation's idempotency policy;
- **deterministic rejection** — validation, authorization or state preconditions failed; retry is unsafe or pointless until input/state changes;
- **committed** — the authoritative mutation completed;
- **unknown after entry** — the effect closure may have executed; blind retry is forbidden and authoritative readback or reconciliation is required.

Errors exposed across a crate boundary must state the category. Generic transport errors must never erase an unknown-after-entry state.

## Secret-memory rules

Secret-bearing repository types must:

- redact `Debug` output;
- avoid secret material in `Display`, metrics, traces and error strings;
- zero repository-owned buffers on drop where the language representation allows it;
- avoid cloning unless the API contract explicitly requires an independent buffer;
- never use real credentials in tests, fixtures or CI.

These rules reduce exposure but do not claim locked memory, side-channel resistance or crash-dump protection.

## Authorization rules

Authorization is default deny. Authentication never implies authorization. Policy evaluation must use a canonical namespace and resource path, deterministic capability mapping and explicit identity/token policy expansion.

## State-machine rules

A state-changing API must document:

- all states and events;
- guards and resulting actions;
- invalid transitions;
- generation, term or fence changes;
- crash and replay behavior;
- tests for every security-relevant transition.

## Concurrency and ordering

Shared mutable state must name its serialization point. Code must avoid holding a lock across an external callback or unbounded operation. Writer authority must be represented by a generation, term or fence token and checked at the commit boundary.

## Persistence and format evolution

Persisted and wire-visible data must carry an explicit version. Readers reject unknown required fields or unsupported versions. Writers do not overwrite a newer generation. Migrations must define source/target writer authority and prohibit overlap.

## Observability

Telemetry uses stable event names and bounded low-cardinality labels. Label names or values that contain tokens, secrets, keys, unseal data, request bodies or secret paths are forbidden. Ambiguous outcomes must emit a recovery reference suitable for operator lookup without exposing secret content.

## Test evidence

The minimum test portfolio for a stateful module is:

- valid path;
- invalid input;
- invalid transition;
- authorization or authority failure;
- boundary/size case;
- failure before entry;
- unknown outcome after entry when applicable;
- restart/replay or migration behavior when persisted state is involved.

Test names and counts are derived from executable source. A hand-written list may explain intent but may not be the source of truth.

## Documentation discipline

Each workspace package has one guide under `docs/modules/<package>.md`. The guide contains module-specific information only and follows Module Documentation Standard V3. Shared text belongs in this handbook.

A code change that alters a public type, state transition, error category, persisted format, metric or operator action must update the module guide and capability matrix in the same change stack.

## Dependency and cryptography rules

No repository-owned ad-hoc cryptographic primitive may be introduced. Cryptographic algorithms and KMS/HSM integrations require a reviewed provider boundary, pinned dependency decision, test vectors and external qualification. A contract crate is not a qualified provider.

## Claims and release rules

No source file, test, workflow or administrator action may self-assert independent review, legal disposition, production suitability, compatibility or release authority. Those claims require the exact completion objects named by the external-admission protocol.
