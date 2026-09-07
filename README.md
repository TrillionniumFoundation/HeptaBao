# HeptaBao

HeptaBao is an independent Rust implementation project for a secrets-management service. The current repository state is a **V2.0 repository product candidate under review**. It is not a supported production server, does not currently claim OpenBao compatibility, and has no production, migration or release authority.

Do not use this source to protect real secrets. Do not place live tokens, unseal shares, recovery keys, private keys, KMS credentials or production snapshots in issues, pull requests, CI, fixtures or ordinary development environments.

## Current repository state

The current workspace contains **40 packages**. It includes:

- inherited storage, barrier, audit journal, operation-ledger, recovery and rollback-anchor foundations;
- bounded policy, identity, token, lease, namespace, mount routing, plugin and versioned KV control-plane domains;
- a service composition root covering token validation, identity expansion, default-deny policy, namespace isolation, mount routing, KV dispatch, outcome classification and telemetry;
- HA, migration, client, agent, CLI, proxy, KMS and compatibility contracts;
- operator reconciliation, telemetry, retention, backup and current repository-assurance contracts.

The repository still does **not** contain a qualified production TLS listener, production AEAD/KMS/HSM provider, production database provider, fully integrated durable service runtime, independently admitted compatibility matrix, externally qualified HA deployment or supported release. Those boundaries are explicit blockers, not implied capabilities.

## Current source of truth

For the exact commit under review, use these files in order:

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`
2. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`
3. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml`
4. `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_0.md`
5. `docs/CURRENT_DOCUMENTATION.md`
6. executable Rust and Python tests

The plan ID is `HEPTABAO-PLAN-2026-09-07-V2.0`. Historical V1.x plans and receipts remain evidence for their exact source identities, but they are not the current product-state authority.

## Architecture boundary

The intended mandatory path is:

```text
strict transport/TLS boundary
    → authentication and token validation
    → identity and group expansion
    → default-deny policy decision
    → namespace and longest-prefix mount resolution
    → secrets-engine dispatch
    → durable journal/ledger/barrier commit classification
    → response audit, telemetry and operator reconciliation
```

The current in-repository composition proves the control-plane ordering and unknown-outcome rules. Full durable runtime integration and production-provider qualification remain separate work and must not be inferred from an in-memory test path.

## Build and current checks

The declared Rust toolchain is 1.98.0. From a clean exact checkout:

```bash
python -m pip install --disable-pip-version-check --requirement requirements-plan.txt
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

`v2-continuous-assurance.yml` runs the current repository validator, all-target tests, strict Clippy and documentation against an immutable source identity. A green run from another commit, a branch name, a local log or a generated status label is not inherited by the current head.

## Documentation

- Current documentation portal: `docs/CURRENT_DOCUMENTATION.md`
- Module index: `docs/modules/README.md`
- V3 module standard: `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md`
- Shared engineering rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`
- Mandatory request pipeline: `docs/architecture/HEPTABAO_V2_MANDATORY_REQUEST_PIPELINE.md`
- Single-node operator runbook: `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`
- Observability catalog: `docs/operations/HEPTABAO_OBSERVABILITY_CATALOG_V1.md`

Every workspace package must have exactly one module guide. V3 guides contain module-specific API ownership, state, invariants, failure/reconciliation, concurrency, security, persistence, observability, operations, tests and evolution boundaries. Shared boilerplate belongs in the engineering handbook.

## External blockers and authority

The following remain external completion requirements and cannot be self-asserted by repository automation or administrator permission:

- final outbound licensing and contributor/legal policy;
- independent security review;
- qualified private disclosure and 24×7 incident ownership;
- isolated signer and KMS/HSM custody;
- restricted clean-room Oracle transfer controls;
- destructive filesystem, controller, cloud and hardware qualification;
- independent reproduction and release admission.

Until authentic completion evidence is admitted:

```text
qualification=false
compatibility_claim=false
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```

See `LICENSE-PLANNING.md` and `SECURITY.md` before using, redistributing or evaluating this repository.
