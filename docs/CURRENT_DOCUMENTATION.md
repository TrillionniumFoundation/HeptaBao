# HeptaBao current documentation

Status: `V2.1 / RUNNABLE SINGLE-NODE CANDIDATE UNDER REVIEW`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.1`

This is the current entry point for all 45 workspace packages. It records repository implementation truth but grants no compatibility, qualification, production, migration or release authority.

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
- `docs/architecture/HEPTABAO_V2_2_RAFT_RUNTIME.md`
- `docs/architecture/HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md`
- `specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md`

The V2.1 path joins authentication, authorization and audit to restart-safe durable intent/state/commit/ledger ordering. The server composes real TLS, persistent auth and encrypted KV/Transit/TOTP. The V2.2 repository slice adds durable three-voter consensus and ReadIndex. The current increment adds a checksum-pinned sandbox-wrapper process boundary, encrypted restart-safe plugin invocation intents and dynamic-lease projections, plus a machine-validated 60-surface OpenBao 2.6.2 compatibility denominator. Qualified operating-system sandbox/provider observations, production peer networking, destructive HA, complete fixtures, migration and independent compatibility qualification remain separate gates.

## Module documentation

- `docs/modules/README.md` — complete index for all 45 workspace packages.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` — current semantic standard.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md` — inherited standard for historical V1.4.7 packages.
- `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md` — shared engineering contracts.

Every package has exactly one guide. The validator checks package, lockfile, source, guide, matrix and test surfaces as one set.

## Runnable single-node increment

- `docs/modules/heptabao-server.md`
- `docs/modules/heptabao-plugin-host.md`
- `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md`
- `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`
- `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md`
- `docs/compatibility/HEPTABAO_SINGLE_NODE_ACCEPTANCE.md`
- `qa/openbao-acceptance/complete_surface_corpus_v1.json`
- `docs/migration/HEPTABAO_OPENBAO_MIGRATION.md`

## Operations, security and compatibility

- `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`
- `docs/operations/HEPTABAO_OBSERVABILITY_CATALOG_V1.md`
- `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md`
- `docs/storage/HEPTABAO_DURABILITY_AND_CRASH_CONSISTENCY_CONTRACT_V1.md`
- `docs/security/HEPTABAO_THREAT_MODEL_V1.md`
- `docs/security/HEPTABAO_REQUEST_CAPABILITY_BOUNDARY_V1.md`
- `docs/compatibility/HEPTABAO_ORACLE_COMPATIBILITY_MATRIX_SPEC_V1.md`
- `SECURITY.md`
- `LICENSE-PLANNING.md`

The raw authentication state and per-request `Principal` are deliberately non-exported. External callers enter only through `Service`, which creates one transaction-scoped capability and never returns it. Repository tests fail if that public boundary is reopened.

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

## Main-line reconciliation

`docs/operations/HEPTABAO_MAIN_RECONCILIATION_2026_09_08.md` records reconciliation with main `92894aa52de06f2f4ba7d5f234a0a55f93314474`: current 45-package implementation and mandatory validation remain intact; inherited legal/security obligations and the historical V1.4.6 recovery baseline remain applicable within their original scope. Archived runner-probe material is historical evidence and is not an admitted workflow.
