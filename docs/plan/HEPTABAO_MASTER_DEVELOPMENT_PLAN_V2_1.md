# HeptaBao master development plan V2.1

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.1`  
Status: active, fail-closed  
Target base: `main`  
Authority effect: `NONE`

## 1. Objective

V2.1 has two repository-controlled objectives:

1. place the independently reviewed V2 repository tree on an ancestry path that can converge directly into the current default branch instead of treating a parallel integration tree as canonical;
2. close the gap between the in-process authorization/routing composition and an actually restart-safe, sealed, reconciliable single-node mutation runtime.

V2.1 does not convert repository CI into legal, production, compatibility, migration, or release authority.

## 2. Source lineage

The implementation branch must retain both identities:

- current `main` as its ancestry/base for a reviewable default-branch merge;
- approved V2 repository tree `89012e7d7991e084104e7030e4f8485c5667592e` as the source tree for the 40-package contract baseline.

A convergence commit may reuse the approved tree but may not claim that an earlier empty or 19-package default-branch snapshot already contained those sources. Exact-head CI and a real prospective merge into `main` are required after every source change.

## 3. Scope

### G0 — repository truth and default-branch convergence

Acceptance:

- PR base is `main`;
- root workspace, lockfile, capability matrix, blocker register, module index, and source tree agree;
- no transport-only chunk or write-capable materializer remains in the final candidate;
- installed current workflows are read-only and use pinned actions without persisted checkout credentials;
- the default branch is advanced only through reviewed merge policy.

### G1 — durable authorized-mutation vertical slice

Acceptance:

- `heptabao-durable-service` exists as a workspace package with one V3 guide;
- request identity is authenticated-principal and namespace scoped, exact-operation bound, bounded, and durably retained;
- write order is intent journal, sealed state publication, commit journal, replay ledger, then acknowledgement;
- state, journal, and ledger are Barrier protected with domain-separated context;
- restart recovers intent-only as aborted, published state as committed, and missing ledger as reconstructable;
- unknown-after-entry never becomes automatic retry;
- writer fencing, tamper rejection, namespace separation, capacity behavior, redaction, and plaintext-absence regressions pass.

### G2 — authenticated service adapter

Acceptance:

- there is exactly one dispatch path from token/identity/policy/namespace/mount validation into the durable mutation envelope;
- an unauthenticated or unauthorized caller cannot allocate durable idempotency state or mutate storage;
- the authorization decision digest and canonical operation binding cannot be changed between policy evaluation and durable intent;
- durable recovery references survive transport failure and are available through the operator API;
- audit-before-dispatch and response/audit-after-commit behavior is explicit and tested.

G2 remains open until the adapter source and end-to-end restart tests exist. The presence of separate `service-core` and `durable-service` crates is not sufficient.

### G3 — provider and destructive qualification

Acceptance requires real execution evidence, not contract types alone:

- production AEAD and at least one isolated KMS/HSM provider;
- production storage/journal/anchor provider conformance;
- kill/restart at every persistence boundary;
- disk full, permission loss, fsync/rename/directory-sync failure, torn/truncated data, clock anomaly, and power-cut campaigns;
- backup/restore to a new root, rollback-anchor conflict, and RPO/RTO evidence;
- operator runbooks with owners, SLOs, and escalation paths.

### G4 — HA, migration, compatibility, and release

Acceptance:

- Raft/HA implementation with leader/writer fencing, membership change, snapshot, quorum-loss and split-brain evidence;
- interruption-safe migration with no source/target writer overlap and tested rollback;
- complete endpoint/error/state-side-effect compatibility corpus admitted through an isolated Oracle lane;
- independent reproduction, product-security assessment, SBOM, provenance, signed artifacts, and release authority.

## 4. Mandatory validation command set

The exact candidate and its prospective merge must run:

```bash
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
python -m unittest discover -s tests/security -p 'test_*.py' -v
python scripts/validate_workflow_trust.py
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/plan -p 'test_module_documentation_v1_4_4.py' -v
python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
git diff --exit-code
```

No failing, skipped-required, empty, stale-head, or manually edited result is a closure receipt.

## 5. Gap-state rules

Repository blockers may move from `IMPLEMENTED_REVIEW_REQUIRED` to `CLOSED` only when the unchanged exact head has:

- implementation;
- module-specific documentation;
- executable positive and hostile tests;
- clean local/repository validation;
- terminal-success exact-head and prospective-merge CI;
- eligible non-author review of the current head.

External blockers remain `EXTERNAL_COMPLETION_REQUIRED` until signed or otherwise independently verifiable evidence is admitted by the applicable authority. A user grant of repository permissions is not a legal opinion, security audit, 24×7 operations roster, HSM ceremony, destructive power test, independent reproduction, compatibility admission, or release signature.

## 6. Current non-claims

Until all applicable external and implementation gates close:

```text
qualification=false
compatibility_claim=false
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```

The project may accurately describe repository-controlled implementation and test progress. It may not describe the candidate as a production OpenBao replacement merely because all repository unit tests are green.
