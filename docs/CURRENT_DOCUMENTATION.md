# HeptaBao current documentation

Status: `V2.1 / DURABLE VERTICAL-SLICE CANDIDATE UNDER REVIEW`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.1`

This is the current entry point for all 42 workspace packages. It records repository implementation truth but grants no compatibility, qualification, production, migration or release authority.

## Canonical current truth

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`
2. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`
3. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml`
4. `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md`
5. `scripts/validate_repository_v2.py`
6. `tests/repository/`

The exact Git commit and tree outrank generated status prose.

## Architecture

- `docs/architecture/HEPTABAO_V2_MANDATORY_REQUEST_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md`
- `docs/architecture/HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md`
- `specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md`

The V2.1 path joins authentication, authorization and audit to restart-safe durable intent/state/commit/ledger ordering. Production provider, network, HA, migration and compatibility qualification remain separate blockers.

## Module documentation

- `docs/modules/README.md` — complete index for all 42 workspace packages.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` — current semantic standard.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md` — inherited standard for historical V1.4.7 packages.
- `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md` — shared engineering contracts.

Every package has exactly one guide. The validator checks package, lockfile, source, guide, matrix and test surfaces as one set.

## Operations, security and compatibility

- `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`
- `docs/operations/HEPTABAO_OBSERVABILITY_CATALOG_V1.md`
- `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md`
- `docs/storage/HEPTABAO_DURABILITY_AND_CRASH_CONSISTENCY_CONTRACT_V1.md`
- `docs/security/HEPTABAO_THREAT_MODEL_V1.md`
- `docs/compatibility/HEPTABAO_ORACLE_COMPATIBILITY_MATRIX_SPEC_V1.md`
- `SECURITY.md`
- `LICENSE-PLANNING.md`

Compatibility remains false until an isolated Oracle corpus and independent admission exist.

## Current validation commands

```text
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

A current exact-head and real prospective-main-merge run are required. Historical green checks and local output are not admission evidence.

## Authority boundary

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```
