# HeptaBao Master Development Plan V2.0

Status: `ACTIVE / REPOSITORY PRODUCT CLOSURE IN PROGRESS`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.0`

Baseline: PR #68 exact head `388661a4b3f6e009c219ff48820dfa4e27e27444`.

## 1. Purpose

V2.0 turns the existing safety-oriented storage, audit and recovery kernel into one reviewable product candidate. It closes repository-controlled gaps through executable source, tests and concise operator/developer documentation rather than through status prose alone.

The plan deliberately separates three kinds of completion:

1. **Repository implementation completion**: source, tests, documentation and CI exist and agree.
2. **Environment qualification completion**: real filesystems, controllers, KMS/HSMs, runners and failure laboratories have produced attributable evidence.
3. **Operational authority completion**: accountable legal, security, incident, release and independent-review actors have granted a scoped authority.

Only the first category can be completed solely by this repository. V2.0 must never relabel a repository artifact as independent or external evidence.

## 2. Canonical source rules

The current source of truth is, in descending order:

1. the exact Git commit and tree under review;
2. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`;
3. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`;
4. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml`;
5. executable Rust and Python tests;
6. module and operator documentation.

Branch names, pull-request titles, green checks from a different commit, local logs and generated status labels are not completion evidence.

## 3. Repository workstreams

### G0 — repository truth and documentation

Deliverables:

- one current portal and one canonical state document;
- one V3 module-documentation standard;
- one shared engineering handbook for cross-cutting rules;
- one capability matrix mapping every product domain to source, tests and documentation;
- one current repository validator that checks workspace membership, package identity, lockfile coverage, module-guide coverage, blocker evidence and current-entry consistency;
- one current CI workflow that runs formatting, all-target tests, strict Clippy, documentation and repository validation;
- historical plans remain immutable evidence and are not selected as current truth.

Definition of done:

- every workspace package has exactly one package manifest, source root and module guide;
- new guides contain module-specific state, invariants, failure semantics, observability, operations and executable evidence;
- shared boilerplate lives in the engineering handbook instead of being copied into every guide;
- test inventories are derived from source or executable test discovery, not maintained as a second hand-written list.

### G1 — control-plane vertical slice

Deliverables:

- canonical domain identifiers and paths;
- default-deny policy evaluation;
- identity, alias and group resolution;
- token issue, validation, renewal and revocation;
- lease issue, renewal, expiration and revocation;
- namespace creation and isolation;
- longest-prefix mount routing;
- plugin registration contracts;
- a versioned KV secrets engine with compare-and-set, delete, undelete and destroy semantics.

Definition of done:

- state transitions reject invalid or duplicate transitions;
- authorization is default deny;
- revoked or expired tokens and leases cannot be used;
- namespace and mount resolution are deterministic;
- sensitive values have redacted debug output and zeroization on drop where represented in repository-owned memory;
- each domain has focused unit tests and a V3 guide.

### G2 — mandatory end-to-end service path

Deliverables:

- one composition root joining token validation, identity expansion, policy evaluation, namespace and mount resolution, KV dispatch, commit classification and telemetry;
- an explicit before-entry failure versus after-entry unknown-outcome boundary;
- end-to-end tests for write, read, list, delete, denial, revocation, namespace isolation and ambiguous outcomes;
- no blind retry after an after-entry unknown outcome.

Definition of done:

- one test exercises the complete accepted request path;
- one test proves default denial before dispatch;
- one test proves an after-entry failure returns a recovery reference while retaining the committed state;
- one test proves the service does not execute the mutation twice.

### G3 — operations and recovery

Deliverables:

- operator outcome-classification API;
- telemetry event contract with sensitive-label rejection;
- retention, compaction and backup state contracts;
- single-node operator runbook;
- observability catalog containing stable event names and required dimensions;
- recovery procedures distinguish safe retry, authoritative readback and operator intervention.

Definition of done:

- every externally visible ambiguous state has a prescribed operator action;
- the runbook contains startup, bootstrap, backup, restore, reconcile, disk-pressure and key-rotation procedures;
- no metric or trace label may contain a token, key, secret or unseal material.

### G4 — HA, migration, client and compatibility contracts

Deliverables:

- HA term, role, membership and writer-fence contracts;
- migration state machine prohibiting source/target writer overlap;
- client retry classification;
- agent auto-auth state machine;
- proxy header-sanitization and forwarding policy;
- KMS/HSM custody and rotation contracts without inventing cryptography;
- compatibility claim and differential-result model.

Definition of done:

- contracts compile and have transition tests;
- the repository states clearly that contracts are not production providers or external qualification;
- compatibility remains false until an independently attributable endpoint and side-effect matrix is admitted.

### G5 — external completion and authority

This workstream is intentionally outside repository self-assertion. It includes final outbound licensing, independent security review, 24x7 incident ownership, isolated signer and KMS/HSM custody, restricted Oracle transfer, destructive storage/controller testing, independent reproduction and release authority.

Repository code may provide schemas, templates and validation, but it must keep these blockers open until authentic completion objects from eligible actors are admitted.

## 4. Change discipline

Every product change must update, in the same commit or stack:

- source;
- tests;
- the module guide;
- the capability matrix;
- blocker evidence when a blocker state changes.

A blocker may move to `IMPLEMENTED_REVIEW_REQUIRED` when source and tests exist. It may move to `CLOSED_REPOSITORY_SCOPE` only after exact-head CI and review evidence exist. External blockers may not use either repository state as a substitute for their declared completion class.

## 5. Required current checks

The V2 current workflow must execute at least:

```text
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

The exact command set is a minimum. A green run from a different source identity is not inherited.

## 6. Release boundary

V2.0 source completion does not create a production release. Until external completion and authority are admitted:

- `qualification=false`;
- `compatibility_claim=false`;
- `production_authority=false`;
- `migration_authority=false`;
- `release_authority=false`;
- `authority_effect=NONE`.
