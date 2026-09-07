# HeptaBao module developer documentation

Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
Coverage: **19 / 19 Cargo workspace crates**.

| Crate | Owner role | Maturity | Developer guide |
|---|---|---|---|
| `heptabao-authbus-contracts` | `identity-authentication-security` | `FOUNDATION_IMPLEMENTED_NOT_PRODUCTION_AUTHORITY` | [heptabao-authbus-contracts.md](./heptabao-authbus-contracts.md) |
| `heptabao-barrier-api` | `cryptography-barrier-core-security` | `PROVIDER_NEUTRAL_API_IMPLEMENTED` | [heptabao-barrier-api.md](./heptabao-barrier-api.md) |
| `heptabao-durable-core` | `core-storage-barrier` | `SINGLE_NODE_FOUNDATION_IMPLEMENTED` | [heptabao-durable-core.md](./heptabao-durable-core.md) |
| `heptabao-filesystem-guard` | `storage-platform-security` | `V1_4_3_CANDIDATE_TECHNICAL_SOURCE` | [heptabao-filesystem-guard.md](./heptabao-filesystem-guard.md) |
| `heptabao-governance` | `program-governance-security` | `GOVERNANCE_SENTINEL_IMPLEMENTED` | [heptabao-governance.md](./heptabao-governance.md) |
| `heptabao-journal-api` | `audit-journal-core-security` | `PROVIDER_NEUTRAL_API_IMPLEMENTED` | [heptabao-journal-api.md](./heptabao-journal-api.md) |
| `heptabao-journaled-core` | `core-audit-storage` | `SINGLE_NODE_JOURNALED_FOUNDATION_IMPLEMENTED` | [heptabao-journaled-core.md](./heptabao-journaled-core.md) |
| `heptabao-key-lifecycle` | `cryptography-custody-core-security` | `STATE_MACHINE_FOUNDATION_IMPLEMENTED` | [heptabao-key-lifecycle.md](./heptabao-key-lifecycle.md) |
| `heptabao-operation-ledger` | `core-audit-reconciliation` | `DURABLE_STATE_MACHINE_FOUNDATION_IMPLEMENTED` | [heptabao-operation-ledger.md](./heptabao-operation-ledger.md) |
| `heptabao-oracle-observer` | `compatibility-clean-room-security` | `OBSERVATION_FOUNDATION_UNQUALIFIED` | [heptabao-oracle-observer.md](./heptabao-oracle-observer.md) |
| `heptabao-p0-server` | `protocol-core-development` | `P0_DEVELOPMENT_MEMORY_ONLY` | [heptabao-p0-server.md](./heptabao-p0-server.md) |
| `heptabao-platform-bakeoff` | `platform-qualification-security` | `BAKEOFF_TOOLING_FOUNDATION` | [heptabao-platform-bakeoff.md](./heptabao-platform-bakeoff.md) |
| `heptabao-platform-contracts` | `platform-runtime-tls-distributed-systems` | `CONTRACT_AND_PROBE_FOUNDATION` | [heptabao-platform-contracts.md](./heptabao-platform-contracts.md) |
| `heptabao-protocol` | `protocol-ingress-security` | `STRICT_P0_PROTOCOL_FOUNDATION` | [heptabao-protocol.md](./heptabao-protocol.md) |
| `heptabao-recovery-core` | `recovery-storage-audit-security` | `ANCHORED_RECOVERY_FOUNDATION_IMPLEMENTED` | [heptabao-recovery-core.md](./heptabao-recovery-core.md) |
| `heptabao-rollback-anchor` | `storage-cryptography-distributed-systems` | `PROVIDER_NEUTRAL_ANCHOR_FOUNDATION` | [heptabao-rollback-anchor.md](./heptabao-rollback-anchor.md) |
| `heptabao-single-node-journal` | `audit-storage-platform` | `SINGLE_NODE_DURABLE_FOUNDATION` | [heptabao-single-node-journal.md](./heptabao-single-node-journal.md) |
| `heptabao-single-node-store` | `storage-platform-security` | `SINGLE_NODE_DURABLE_FOUNDATION` | [heptabao-single-node-store.md](./heptabao-single-node-store.md) |
| `heptabao-storage-api` | `storage-core-api` | `PROVIDER_NEUTRAL_API_IMPLEMENTED` | [heptabao-storage-api.md](./heptabao-storage-api.md) |

The coverage object and validator are authoritative for structural completeness. Target modules that do not yet exist in the Cargo workspace remain product gaps and are tracked by the master plan rather than being represented as implemented modules.
