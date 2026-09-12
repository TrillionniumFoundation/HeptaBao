# HeptaBao current documentation

Status: `V2.1 / RUNNABLE SINGLE-NODE CANDIDATE UNDER REVIEW`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.1`

This is the current entry point for all 46 workspace packages. It records repository implementation truth but grants no compatibility, qualification, production, migration or release authority.

## Canonical current truth

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`
2. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`
3. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml`
4. `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md`
5. `scripts/validate_repository_v2.py`
6. `tests/repository/`

The exact Git commit and tree outrank generated status prose.

## Architecture

- `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md` — actual five-package runtime and internal state owners.
- `docs/modules/CURRENT_RUNTIME_MAP.md` — all 46 packages mapped to runtime integration, routes and named source tests.

The following retained increment/target documents describe their own historical or library scope:

- `docs/architecture/HEPTABAO_V2_MANDATORY_REQUEST_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_2_RAFT_RUNTIME.md`
- `docs/architecture/HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md`
- `specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md`

The runnable server composes real TLS, private persistent authentication/ACL, encrypted KV/Transit/TOTP, authenticated audit and optional per-process networked Raft. The workspace also contains separately tested plugin-host, identity, lease, telemetry, client and migration contracts/candidates. Those packages are not in the server's dependency closure and do not establish corresponding integrated product features. The 60-surface OpenBao 2.6.2 corpus is a denominator for acceptance evidence, not a compatibility claim. Independent security, external provider, migration, upgrade and destructive HA qualification remain separate gates.

## Module documentation

Current content binding is `planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`.
Read `docs/modules/CURRENT_SOURCE_BINDING.md` before using inherited V1.4.7
source tables; those tables are historical, not current API inventories.

- `docs/modules/README.md` — complete index for all 46 workspace packages.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` — current semantic standard.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md` — inherited standard for historical V1.4.7 packages.
- `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md` — shared engineering contracts.

Every package has exactly one guide. The validators check package, lockfile, source, guide, matrix and test surfaces as one set, reject API sections made solely of historical generated tables, and check the runtime dependency map and current critical API signatures. This is a drift guard, not automatic proof that all prose is semantically complete.

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
python scripts/validate_current_documentation_semantics.py
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

`docs/operations/HEPTABAO_MAIN_RECONCILIATION_2026_09_08.md` records reconciliation with main `92894aa52de06f2f4ba7d5f234a0a55f93314474`: the 45-package implementation observed in that historical reconciliation and its mandatory validation remain intact; inherited legal/security obligations and the historical V1.4.6 recovery baseline remain applicable within their original scope. Archived runner-probe material is historical evidence and is not an admitted workflow.

Current normative set: HEPTABAO-PLAN-2026-09-07-V2.1 and its V2 canonical-state, product-capability, blocker-register, and master-plan documents.

Supersession chain: V1.4.4 module documentation → V1.4.5 security invariants → V1.4.6 authoritative recovery → V1.4.7 post-merge truth → V2.0 canonical repository state → V2.1 active development plan.

The V1.4.6 authoritative recovery closure and V1.4.5 security invariant closure remain inherited historical evidence only; neither supersedes the active V2.1 plan or grants production authority.
