# Current crate, runtime, route and test map

This map describes the current source, bound by `planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`, not a target architecture or a test-pass receipt. There are **46 workspace packages**, of which **5** are in the normal path-dependency closure of `heptabao-server`. The other **41** remain independently useful contracts, models, prototypes or tooling; their tests do not establish that the corresponding feature is integrated into the running service. Dev dependencies are not runtime edges. Dependencies external to the workspace are omitted here and remain pinned by Cargo.lock.

The architecture and current owner boundaries are in [the current runtime architecture](../architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md). The current HTTP interface is described by [server](heptabao-server.md), [authentication](../auth/HEPTABAO_SINGLE_NODE_AUTH.md) and [engines](../engines/HEPTABAO_SINGLE_NODE_ENGINES.md). Paths below omit `/v1/`. A package's guide gives additional concrete negative/recovery tests; the one source anchor in each row is an executable starting point, not complete coverage.

| Package | Runtime | Responsibility and route | Source test |
|---|---|---|---|
| `heptabao-agent` | no | Credential/cache lifecycle model; no running sidecar or server route | `crates/heptabao-agent/src/lib.rs::authentication_renewal_and_revocation_are_monotonic` |
| `heptabao-authbus-contracts` | no | Request-bound assertion verifier contracts; no Authbus login mount | `crates/heptabao-authbus-contracts/src/lib.rs::valid_assertion_authenticates_but_does_not_authorize` |
| `heptabao-barrier-api` | no | Provider-neutral envelope/AAD contract; no server seal route | `crates/heptabao-barrier-api/src/lib.rs::envelope_round_trips_strictly` |
| `heptabao-cli-contracts` | no | Command classification/output contract; no OpenBao-compatible CLI binary | `crates/heptabao-cli-contracts/src/lib.rs::secret_bearing_arguments_fail_closed` |
| `heptabao-client-contracts` | no | Client retry/request-ID model; no network SDK | `crates/heptabao-client-contracts/src/lib.rs::unknown_after_entry_never_becomes_automatic_retry` |
| `heptabao-compatibility` | no | Oracle comparison/normalization tooling; no server route | `crates/heptabao-compatibility/src/lib.rs::repository_cannot_self_admit_compatibility` |
| `heptabao-domain` | no | Namespace/request domain identifiers; server uses separate internal models | `crates/heptabao-domain/src/lib.rs::identifier_and_path_validation_are_fail_closed` |
| `heptabao-durable-core` | no | Inherited generation-store/barrier composition; no server route | `crates/heptabao-durable-core/src/lib.rs::prepared_mutation_binds_target_before_authoritative_commit` |
| `heptabao-durable-service` | yes | Current encrypted persistence, replay ledger, compaction and backup; reached by Service mutations and sys/storage/raft maintenance | `crates/heptabao-durable-service/src/lib.rs::put_restart_read_and_duplicate_are_durable` |
| `heptabao-filesystem-guard` | yes | Linux exclusive directory descriptor fence used by durable-service; no independent route | `crates/heptabao-filesystem-guard/src/lib.rs::root_is_descriptor_bound_and_leaf_names_are_closed` |
| `heptabao-governance` | no | Qualification fact validation; no runtime authority or server route | `crates/heptabao-governance/src/lib.rs::qualification_never_grants_authority` |
| `heptabao-ha-contracts` | no | Leader/follower routing contract model; server uses concrete ha-service/raft-runtime | `crates/heptabao-ha-contracts/src/lib.rs::stale_writer_fence_is_rejected_after_term_change` |
| `heptabao-ha-service` | yes | Current mTLS peer transport/pinned certificates; generic HaService remains separate; internal peer listener | `crates/heptabao-ha-service/src/lib.rs::leader_executes_and_follower_forwards_with_deduplication` |
| `heptabao-identity` | no | Entity/alias/group model; no identity HTTP backend | `crates/heptabao-identity/src/lib.rs::aliases_groups_and_direct_policies_expand_deterministically` |
| `heptabao-journal-api` | no | Provider-neutral journal append/recovery contract; no server audit route | `crates/heptabao-journal-api/src/lib.rs::sequence_is_checked_and_non_zero` |
| `heptabao-journaled-core` | no | Inherited journal/state reconciliation composition; no server route | `crates/heptabao-journaled-core/src/lib.rs::intent_precedes_state_commit_and_duplicate_never_mutates_again` |
| `heptabao-key-lifecycle` | no | Journaled key-epoch metadata; server Shamir/rekey is separate | `crates/heptabao-key-lifecycle/src/lib.rs::bootstrap_stage_rotate_retire_and_revoke_replay` |
| `heptabao-kms-contracts` | no | Custody wrap/unwrap interface; no integrated KMS auto-unseal route | `crates/heptabao-kms-contracts/src/lib.rs::key_lifecycle_is_fail_closed_and_monotonic` |
| `heptabao-kv-engine` | no | Standalone KV version model; current secret/* routes use server/engines/kv.rs | `crates/heptabao-kv-engine/src/lib.rs::compare_and_set_and_version_lifecycle_are_enforced` |
| `heptabao-lease` | no | In-memory lease model; no general sys/leases backend | `crates/heptabao-lease/src/lib.rs::lease_lifecycle_is_monotonic` |
| `heptabao-migration` | no | Inventory/manifest/reconciliation model and evidence tooling; no automatic production importer | `crates/heptabao-migration/src/durable.rs::inventory_is_closed_sorted_dependency_checked_and_hashed` |
| `heptabao-mount-router` | no | Standalone mount routing model; sys/mounts uses server engine state | `crates/heptabao-mount-router/src/lib.rs::longest_prefix_wins_within_namespace` |
| `heptabao-namespace` | no | Standalone namespace model; server uses its internal namespace validation/state | `crates/heptabao-namespace/src/lib.rs::hierarchy_and_longest_prefix_resolution_are_deterministic` |
| `heptabao-operation-ledger` | no | Inherited durable transition/retry ledger; no direct HTTP endpoint | `crates/heptabao-operation-ledger/src/lib.rs::legal_mutation_chain_replays_and_requires_lookup_after_commit` |
| `heptabao-operator-api` | no | Operator outcome/recovery-reference model; current sys/internal/recovery/* uses Service | `crates/heptabao-operator-api/src/lib.rs::unknown_after_entry_forbids_retry_until_readback` |
| `heptabao-oracle-observer` | no | Synthetic/black-box observation and side-effect checks; no server route | `crates/heptabao-oracle-observer/src/lib.rs::synthetic_contract_has_no_authority` |
| `heptabao-p0-server` | no | Earlier in-memory init/seal/KV development prototype; not current HTTPS process | `crates/heptabao-p0-server/src/lib.rs::fresh_server_starts_fail_closed_and_sealed` |
| `heptabao-platform-bakeoff` | no | Dependency prototype selection/evidence tooling; no server route | `crates/heptabao-platform-bakeoff/src/lib.rs::validated_candidate_has_no_authority` |
| `heptabao-platform-contracts` | no | Runtime/TLS/consensus adapter contracts; no concrete server adapter | `crates/heptabao-platform-contracts/src/lib.rs::registry_metadata_has_no_authority` |
| `heptabao-plugin-contracts` | no | Plugin registration/capability contracts; no plugin HTTP backend | `crates/heptabao-plugin-contracts/src/lib.rs::lifecycle_is_monotonic_after_revocation` |
| `heptabao-plugin-host` | no | Separate supervised plugin host and durable invocation/lease candidates; not loaded by server | `crates/heptabao-plugin-host/src/durable.rs::issued_secret_is_released_only_after_durable_metadata_and_survives_reopen` |
| `heptabao-policy` | no | Standalone policy model; current sys/policies/acl/* uses server/auth.rs | `crates/heptabao-policy/src/lib.rs::authorization_is_default_deny_and_segment_bounded` |
| `heptabao-protocol` | no | P0 request parser/envelope/audit contracts; current HTTPS parser is server/http.rs | `crates/heptabao-protocol/src/lib.rs::strict_request_parses_and_classifies` |
| `heptabao-proxy` | no | Forward/retry model; current HA transport is server/ha_forward.rs | `crates/heptabao-proxy/src/lib.rs::inbound_credentials_are_replaced_by_the_server_token` |
| `heptabao-raft-runtime` | yes | Current ProcessRaftNode consensus, log/state machine and ReadIndex; reached through server HA forwarding, ReadIndex and snapshot/compaction | `crates/heptabao-raft-runtime/src/process/node.rs::process_timers_allow_tls_and_durable_io_without_using_lease_reads` |
| `heptabao-recovery-core` | no | Externally anchored recovery contract/composition; current backup route is separate | `crates/heptabao-recovery-core/src/lib.rs::anchor_fence_is_held_across_target_publication` |
| `heptabao-retention` | no | Operation/lease retention model; no server background retention service | `crates/heptabao-retention/src/lib.rs::policy_and_compaction_plan_are_bounded` |
| `heptabao-rollback-anchor` | no | Remote anchor/checkpoint contract; no deployed rollback-protection provider | `crates/heptabao-rollback-anchor/src/lib.rs::checkpoint_advances_and_exact_observation_is_detected` |
| `heptabao-runtime-service` | no | Separate admitted durable mutation composition; not the current HTTP dispatcher | `crates/heptabao-runtime-service/src/lib.rs::invalid_credential_cannot_allocate_durable_request_identity` |
| `heptabao-server` | yes | Current executable: TLS/Service auth, seal/rekey, KV, Transit, TOTP, maintenance and optional network HA; /v1/* | `crates/heptabao-server/src/service_tests.rs::result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen` |
| `heptabao-service-core` | no | Standalone in-memory service composition; not current Service | `crates/heptabao-service-core/src/lib.rs::accepted_request_runs_identity_policy_namespace_mount_and_engine` |
| `heptabao-single-node-journal` | no | Inherited immutable-record file journal; current durable-service journal is separate | `crates/heptabao-single-node-journal/src/lib.rs::create_append_replay_and_reopen_round_trip` |
| `heptabao-single-node-store` | no | Inherited generation-bundle file store; current durable-service store is separate | `crates/heptabao-single-node-store/src/lib.rs::create_commit_load_and_reopen_round_trip` |
| `heptabao-storage-api` | no | Provider-neutral generation/CAS contract; no server route | `crates/heptabao-storage-api/src/lib.rs::generation_is_non_zero_and_checked` |
| `heptabao-telemetry` | no | Standalone label validation/MemoryTelemetry; no current server metrics exporter | `crates/heptabao-telemetry/src/lib.rs::sensitive_or_high_cardinality_labels_are_rejected` |
| `heptabao-token` | no | Standalone token model; current auth/token/* uses server/auth.rs | `crates/heptabao-token/src/lib.rs::token_lifecycle_enforces_expiry_renewal_and_revocation` |

Run a row with `cargo +1.98.0 test --locked -p <package> <test-name>` (illustrative placeholders). Discovery counts in the inventory describe source functions, not assertions, acceptance surfaces, successful executions or production readiness.

`python scripts/validate_current_documentation_semantics.py` checks every row against workspace manifests, the server's actual dependency closure and a discovered Rust test in that same package. Changing a dependency or deleting/renaming the selected test requires reviewing this map. These checks cannot prove semantic completeness, so code review must still compare handler behavior with the corresponding human guide.

Qualification, compatibility, production, migration and release authority remain false.
