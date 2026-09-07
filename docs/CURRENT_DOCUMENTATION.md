# HeptaBao current documentation

Status: `V2.0 / REPOSITORY PRODUCT CANDIDATE UNDER REVIEW`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.0`

This page is the current documentation entry for the exact Git commit under review. It does not grant compatibility, production, migration or release authority. Historical V1.x material remains source-bound evidence only.

## Canonical current truth

Read these artifacts together, in this order:

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml` — selected plan, current workstreams, current document pointers and fail-closed claims.
2. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml` — all 40 workspace packages, domains, source paths, guides and implementation states.
3. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml` — repository-controlled and external completion blockers.
4. `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_0.md` — G0–G5 delivery and closure rules.
5. `scripts/validate_repository_v2.py` and `tests/repository/test_repository_v2.py` — executable agreement checks.

The exact Git commit and tree always outrank a generated or hand-written status statement.

## Current architecture and contracts

- `docs/architecture/HEPTABAO_V2_MANDATORY_REQUEST_PIPELINE.md`
- `docs/architecture/HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md`
- `docs/architecture/HEPTABAO_AUTHORITATIVE_DATA_OWNERSHIP_AND_TRANSACTION_MAP_V1.md`
- `docs/architecture/HEPTABAO_REQUEST_PIPELINE_HAPPENS_BEFORE_V1.md`
- `specs/HEPTABAO_REQUEST_PIPELINE_STATE_MACHINE_V1.yaml`
- `specs/HEPTABAO_OPERATION_REGISTRY_V1.yaml`
- `specs/HEPTABAO_MIGRATION_AUTHORITY_STATE_MACHINE_V1.yaml`
- `specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md`

The V2 mandatory pipeline joins the new product/control-plane contracts to inherited safety foundations. The present `heptabao-service-core` path is still an in-memory composition; complete journal/ledger/barrier-backed runtime integration is tracked as a repository-controlled closure item.

## Module documentation

- `docs/modules/README.md` — complete 40-package current index.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` — semantic standard for current/new packages.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md` — inherited source-bound standard for the 19 V1.4.7 packages.
- `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md` — shared failure, security, concurrency, documentation and change rules.

Every workspace package has exactly one `docs/modules/<package>.md` guide. The repository validator checks the package, lockfile, source, guide and test surfaces as one set.

## Operations, recovery and security

- `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`
- `docs/operations/HEPTABAO_OBSERVABILITY_CATALOG_V1.md`
- `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md`
- `docs/recovery/HEPTABAO_ANCHORED_RECOVERY_CONTRACT_V1.md`
- `docs/storage/HEPTABAO_DURABILITY_AND_CRASH_CONSISTENCY_CONTRACT_V1.md`
- `docs/storage/HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md`
- `docs/security/HEPTABAO_THREAT_MODEL_V1.md`
- `docs/security/HEPTABAO_V1_3_THREAT_MODEL_DELTA.md`
- `docs/security/HEPTABAO_SECURITY_INVARIANT_CLOSURE_V1.md`
- `SECURITY.md`

Operator and security documentation describes fail-closed actions. It is not a substitute for production provider qualification, incident staffing, external audit or supported-version admission.

## Compatibility and clean-room evidence

- `docs/compatibility/HEPTABAO_ORACLE_COMPATIBILITY_MATRIX_SPEC_V1.md`
- `oracle/README.md`
- `oracle/normalization/HEPTABAO_ORACLE_NORMALIZATION_POLICY_V1.yaml`
- `planning/HEPTABAO_CLEAN_ROOM_ACCESS_POLICY_V1.yaml`
- `planning/HEPTABAO_UPSTREAM_COMPATIBILITY_TRAINS_V1.yaml`
- `LICENSE-PLANNING.md`

The repository contains differential and admission contracts, but `compatibility_claim=false`. Restricted Oracle-lane control, legal disposition and independent admission remain external blockers.

## Current validation commands

```text
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

A current exact-head run is required. Historical green checks, local output and checks bound to another commit are not current admission evidence.

## Historical documentation chain

The following plans remain immutable historical evidence and are not selected as current truth:

- `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_1.md`
- `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md`
- `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_3.md`
- `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_4.md`
- V1.4.1 through V1.4.7 plan addenda, status files, receipts and exact-source manifests.

The V1.4.4 coverage manifest still describes its frozen 19-package baseline. It must not be interpreted as the current V2 package count.

## Authority boundary

```text
qualification=false
compatibility_claim=false
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```
