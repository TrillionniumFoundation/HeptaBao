# HeptaBao module documentation index

Current executable ownership and route/test mapping: `docs/modules/CURRENT_RUNTIME_MAP.md` and `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md`. Five packages are in the current server runtime dependency closure; the remaining guides describe separate models, contracts, prototypes and tools.

Current status: `V2.3 / 46 WORKSPACE PACKAGES`

Plan ID: `HEPTABAO-PLAN-2026-09-07-V2.1`

The package set is derived from `Cargo.toml` and must exactly match `Cargo.lock`, `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`, source roots and this guide set. Shared rules live in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`; V3 guides follow `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md`.

## Current package index

| Package | Domain | Guide standard | Source state | Guide |
|---|---|---:|---|---|
| `heptabao-agent` | auto-auth renewal and token sink lifecycle | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-agent.md` |
| `heptabao-authbus-contracts` | authentication contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-authbus-contracts.md` |
| `heptabao-barrier-api` | barrier contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-barrier-api.md` |
| `heptabao-cli-contracts` | secret-safe CLI invocation contracts | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-cli-contracts.md` |
| `heptabao-client-contracts` | client retry classification | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-client-contracts.md` |
| `heptabao-compatibility` | differential compatibility admission | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-compatibility.md` |
| `heptabao-domain` | shared bounded domain values | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-domain.md` |
| `heptabao-durable-core` | durable commit contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-durable-core.md` |
| `heptabao-durable-service` | restart-safe sealed durable mutation runtime | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-durable-service.md` |
| `heptabao-filesystem-guard` | local filesystem fencing | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-filesystem-guard.md` |
| `heptabao-governance` | qualification and authority contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-governance.md` |
| `heptabao-ha-contracts` | HA term membership and writer fences | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-ha-contracts.md` |
| `heptabao-ha-service` | authenticated HA service routing, peer transport and replay fencing | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-ha-service.md` |
| `heptabao-raft-runtime` | durable three-voter consensus, ReadIndex and restart recovery | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-raft-runtime.md` |
| `heptabao-identity` | entity alias and group resolution | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-identity.md` |
| `heptabao-journal-api` | journal contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-journal-api.md` |
| `heptabao-journaled-core` | journaled durable composition | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-journaled-core.md` |
| `heptabao-key-lifecycle` | key lifecycle contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-key-lifecycle.md` |
| `heptabao-kms-contracts` | provider-neutral KMS lifecycle and outcomes | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-kms-contracts.md` |
| `heptabao-kv-engine` | versioned KV secrets engine | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-kv-engine.md` |
| `heptabao-lease` | lease lifecycle | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-lease.md` |
| `heptabao-migration` | migration writer authority | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-migration.md` |
| `heptabao-mount-router` | namespace scoped mount routing | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-mount-router.md` |
| `heptabao-namespace` | hierarchical namespace isolation | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-namespace.md` |
| `heptabao-operation-ledger` | operation reconciliation ledger | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-operation-ledger.md` |
| `heptabao-operator-api` | operator outcome classification | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-operator-api.md` |
| `heptabao-oracle-observer` | clean-room observation contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-oracle-observer.md` |
| `heptabao-p0-server` | loopback memory server | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-p0-server.md` |
| `heptabao-platform-bakeoff` | dependency bakeoff contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-platform-bakeoff.md` |
| `heptabao-platform-contracts` | runtime TLS and Raft provider contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-platform-contracts.md` |
| `heptabao-plugin-contracts` | plugin lifecycle and outcome contracts | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-plugin-contracts.md` |
| `heptabao-plugin-host` | sandbox-wrapper process boundary and dynamic lease coordination | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-plugin-host.md` |
| `heptabao-policy` | default deny path authorization | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-policy.md` |
| `heptabao-protocol` | protocol and request contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-protocol.md` |
| `heptabao-proxy` | local proxy credential and header boundary | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-proxy.md` |
| `heptabao-recovery-core` | authoritative recovery | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-recovery-core.md` |
| `heptabao-retention` | retention and backup lifecycle | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-retention.md` |
| `heptabao-rollback-anchor` | rollback anchor fencing | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-rollback-anchor.md` |
| `heptabao-runtime-service` | authorized audit-to-durable mutation adapter | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-runtime-service.md` |
| `heptabao-server` | runnable TLS single-node encrypted secrets service | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-server.md` |
| `heptabao-service-core` | mandatory end to end service composition | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-service-core.md` |
| `heptabao-single-node-journal` | local durable journal | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-single-node-journal.md` |
| `heptabao-single-node-store` | local durable store | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-single-node-store.md` |
| `heptabao-storage-api` | storage contracts | V2 | `INHERITED_IMPLEMENTED` | `docs/modules/heptabao-storage-api.md` |
| `heptabao-telemetry` | bounded telemetry contract | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-telemetry.md` |
| `heptabao-token` | token lifecycle | V3 | `IMPLEMENTED_REVIEW_REQUIRED` | `docs/modules/heptabao-token.md` |

## Validation

```text
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

A package change updates source, tests, guide, capability matrix and blocker evidence together. Documentation coverage is not production qualification or compatibility admission.

## Current source facts and preserved history

All current workspace packages are bound by
`planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json` and the read-only V2 validator.
See `docs/modules/CURRENT_SOURCE_BINDING.md` for details, regeneration and the
commit/tree receipt boundary. The V1.4.7 inventory and generated guide blocks
are preserved historical snapshots, not current source authority; their older
45-package observation must not be interpreted as this candidate's package set.
