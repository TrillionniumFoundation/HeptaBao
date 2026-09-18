# Current OpenBao replacement acceptance boundaries

This is an execution map subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`,
not another global plan, a compatibility claim or an independently signed receipt.
The canonical capability matrix, blocker register and fixed corpus remain the
acceptance authorities. Git and each CI event determine the actual source head,
tree and prospective-main merge; no mutable branch name or old green run is used
as a product-completion fact here.

## One candidate, one current format

Read [the current state-format contract](../architecture/HEPTABAO_CURRENT_STATE_FORMAT.md)
and [actual runtime map](../modules/CURRENT_RUNTIME_MAP.md). The source/doc guard
checks the current Service discriminator and backend inventory, while the existing
module validator checks all 46 guides and runtime test/API anchors. Historical
V1.4.7 tables remain historical; a standalone Rust model is not a server feature.
Hepta's consumer pin is a separate integration boundary and must be requalified
before advancing to a new server candidate. This repository does not update it
or infer a production caller from source presence.

## Required executable profiles

The read-only `codex-openbao-replacement-ci.yml` runs both the exact PR head and
the actual prospective merge. The existing locked Rust workspace tests, strict
Clippy, rustdoc, immutable-source checks, TLS, three-process HA, encrypted-link
network partition and private client/OTP/idle-lifecycle checks are retained.

The same workflow now requires the following previously separate executable
profiles. These are mandatory checks, not successful execution claims. A missing
prerequisite, timeout, nonzero exit, empty/failed comparison or source drift blocks
the corresponding run. Continue-running other diagnostic steps does not erase
an earlier job failure. Runtime directories, synthetic passwords, tokens, unseal
shares, TLS private keys and plaintext migration exports must not be uploaded.

| Boundary | Existing executable | Meaning and remaining limit |
|---|---|---|
| Fixed compatibility corpus | `run_official_comparison.py` | Same declared scoped cases against the checksum-pinned official 2.6.2 binary; not the full behavior of every surface. |
| Cubbyhole / ACL | `core_isolation.py` | Token-private storage, final-use isolation and winning ACL specificity. |
| Identity | `identity_live.py` | Selected live identity and policy behavior, not the whole MFA/external-identity framework. |
| Response wrapping | `response_wrapping.py` | Selected real single-use response wrapping behavior, not all wrapping formats. |
| PKI | `pki_live.py` | Selected internal-root/role/issue/revoke behavior, not complete CA/ACME/OCSP operations. |
| JWT remote keys | `remote_jwks_compare.py` | Real HTTPS and RSA/P-256/Ed25519 key behavior; not browser OIDC code flow or identical cache semantics. |
| Real PostgreSQL | `postgres_live.py` | Actual PostgreSQL 17 SQL, login, renewal, NOLOGIN revocation, termination of an existing session, restart reconciliation and idle expiry. Never substitute a wire model. |
| HTTP audit | `audit_http_live.py` | Real host-enrolled TLS collector, local-file-first delivery, redirect denial, outage fail-closed and restart recovery; dynamic OpenBao audit-device option parity remains open. |
| Raft administration | `raft_membership_live.py --dead-cleanup` | Five real same-host processes, committed membership, persisted-snapshot catch-up and observed cleanup grace; not five physical hosts. |
| Bounded migration | `live_migration_rehearsal.py` | Real TLS KV history transfer, lost-acknowledgement reconciliation, restart, process-fenced source→target cutover and target→same-source-root rollback rehearsal; not full-instance or post-cutover-write migration. |

All named Python profiles live under `qa/openbao-acceptance/`. Oracle input
acquisition uses `scripts/prepare_openbao_oracle.py`, the existing release/archive/
binary hashes and HTTPS. It never imports upstream implementation source. An
official binary is not the same thing as an independently controlled observer.
The PostgreSQL prerequisite is installed from signed PGDG packages in disposable
CI; exact installed versions are printed by the job. Its fixture creates only a
fresh private loopback cluster and accepts no external DSN or existing data path.

The Python cryptographic dependency is explicitly pinned in `requirements-plan.txt`;
clean Python environments must not silently depend on packages preinstalled in a
hosted runner. This changes test prerequisites, not the production Rust crypto
provider. PostgreSQL test credentials use an owner-only, temporary passfile and
verified TLS; inherited PG connection/environment settings are not trusted.

## Fixed surface denominator

The following source projection is checked against corpus rows rather than its
summary counters. `IMPLEMENTED_SCOPED` means only that the listed corpus cases
exist. `DEFINED_NOT_IMPLEMENTED` means no implemented fixture in this fixed corpus;
it does not deny a separately documented partial native implementation. New
bounded profiles above never silently reclassify the fixed denominator. Neither
state means full behavior coverage, independent admission or production readiness.

<!-- BEGIN CURRENT REPLACEMENT SURFACES -->
| `HB-SURFACE-CORE-REQUEST-PIPELINE` | `core_system` | `IMPLEMENTED_SCOPED` | `core.unknown_route_denied` |
| `HB-SURFACE-SYSTEM-BACKEND` | `core_system` | `IMPLEMENTED_SCOPED` | `system.init_status` |
| `HB-SURFACE-MOUNT-REGISTRY` | `core_system` | `IMPLEMENTED_SCOPED` | `kv.mount`, `transit.mount` |
| `HB-SURFACE-POLICY-ACL` | `core_system` | `IMPLEMENTED_SCOPED` | `token.policy`, `token.write_denied`, `token.denial_no_effect` |
| `HB-SURFACE-IDENTITY` | `core_system` | `IMPLEMENTED_SCOPED` | `identity.entity_create`, `identity.entity_read`, `identity.entity_disable`, `identity.entity_disabled`, `identity.entity_delete`, `identity.entity_deleted` |
| `HB-SURFACE-TOKEN` | `core_system` | `IMPLEMENTED_SCOPED` | `token.create`, `token.revoke`, `token.create_expiring`, `token.expired_denied` |
| `HB-SURFACE-CUBBYHOLE-WRAPPING` | `core_system` | `IMPLEMENTED_SCOPED` | `wrapping.create`, `wrapping.unwrap`, `wrapping.replay_denied` |
| `HB-SURFACE-LEASE-EXPIRATION` | `core_system` | `IMPLEMENTED_SCOPED` | `pki.lease_expire_issue`, `pki.lease_expire_lookup` |
| `HB-SURFACE-AUTH-TOKEN` | `auth_methods` | `IMPLEMENTED_SCOPED` | `token.read_allowed`, `token.revoked_denied`, `token.invalid_denied` |
| `HB-SURFACE-AUTH-USERPASS` | `auth_methods` | `IMPLEMENTED_SCOPED` | `userpass.login` |
| `HB-SURFACE-AUTH-APPROLE` | `auth_methods` | `IMPLEMENTED_SCOPED` | `approle.login` |
| `HB-SURFACE-AUTH-CERT` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-JWT-OIDC` | `auth_methods` | `IMPLEMENTED_SCOPED` | `remote_jwks_live.real_rsa_signature_login`, `remote_jwks_live.same_assertion_replay_rejected`, `remote_jwks_live.p256_rotation_login`, `remote_jwks_live.disabled_subject_login_rejected`, `remote_jwks_live.restart_current_key_login` |
| `HB-SURFACE-AUTH-KUBERNETES` | `auth_methods` | `IMPLEMENTED_SCOPED` | `kubernetes_online.online_review_to_real_token`, `kubernetes_online.reviewer_request_binding`, `kubernetes_online.disabled_identity_denies_new_login`, `kubernetes_online.finite_replay_denied`, `kubernetes_online.all_egress_requests_match_review_contract` |
| `HB-SURFACE-AUTH-LDAP` | `auth_methods` | `IMPLEMENTED_SCOPED` | `ldap_bounded.config_roundtrip`, `ldap_bounded.login_and_revocation`, `ldap_bounded.filter_injection_rejected` |
| `HB-SURFACE-AUTH-RADIUS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-KERBEROS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-KV` | `secret_engines` | `IMPLEMENTED_SCOPED` | `kv.write_v1`, `kv.read_v1`, `kv.write_v2`, `kv.read_old_version`, `kv.cas_rejected`, `kv.cas_no_effect`, `kv.list`, `kv.soft_delete`, `kv.deleted_read`, `kv.deleted_metadata`, `kv.undelete`, `kv.restored_read`, `kv.destroy_v1`, `kv.destroyed_read`, `kv.destroyed_metadata`, `kv.metadata_write`, `kv.metadata_read` |
| `HB-SURFACE-SECRET-TRANSIT` | `secret_engines` | `IMPLEMENTED_SCOPED` | `transit.create_key`, `transit.read_key`, `transit.encrypt_v1`, `transit.decrypt_v1`, `transit.rotate`, `transit.read_rotated_key`, `transit.encrypt_v2`, `transit.decrypt_v2`, `transit.decrypt_old_after_rotation` |
| `HB-SURFACE-SECRET-TOTP` | `secret_engines` | `IMPLEMENTED_SCOPED` | `totp.roundtrip` |
| `HB-SURFACE-SECRET-PKI` | `secret_engines` | `IMPLEMENTED_SCOPED` | `pki.mount`, `pki.root`, `pki.role`, `pki.role_read`, `pki.issue`, `pki.lease_lookup`, `pki.cert_lookup`, `pki.lease_revoke`, `pki.revoked_lease_absent`, `pki.crl_json` |
| `HB-SURFACE-SECRET-PKIEXT` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-SSH` | `secret_engines` | `IMPLEMENTED_SCOPED` | `ssh_otp_live.ssh.mount`, `ssh_otp_live.ssh.role`, `ssh_otp_live.ssh.issue`, `ssh_otp_live.ssh.verify_exact_target`, `ssh_otp_live.ssh.replay_denied`, `ssh_otp_live.ssh.revoke`, `ssh_otp_live.ssh.revoked_denied`, `ssh_otp_live.ssh.wrapped_issue`, `ssh_otp_live.ssh.unwrapped_otp_works` |
| `HB-SURFACE-SECRET-DATABASE` | `secret_engines` | `IMPLEMENTED_SCOPED` | `postgres_pipeline_simulated.verified_scram_configuration`, `postgres_pipeline_simulated.configuration_never_returns_password`, `postgres_pipeline_simulated.no_arbitrary_sql`, `postgres_pipeline_simulated.issue_after_durable_intent_and_readback`, `postgres_pipeline_simulated.model_observed_matches_returned_credentials`, `postgres_pipeline_simulated.renew_external_expiry_then_commit`, `postgres_pipeline_simulated.precise_revoke`, `postgres_pipeline_simulated.lost_post_apply_response_no_secret` |
| `HB-SURFACE-SECRET-KUBERNETES` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-OPENLDAP` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-RABBITMQ` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-POSTGRESQL` | `database_providers` | `IMPLEMENTED_SCOPED` | `postgres_live.native_pg_tls_scram_config`, `postgres_live.credential_really_logs_into_postgresql`, `postgres_live.slow_provider_does_not_block_unrelated_kv_write`, `postgres_live.renewed_credential_survives_service_restart`, `postgres_live.revoke_terminates_existing_database_session`, `postgres_live.revoke_really_prevents_pg_login`, `postgres_live.provider_outage_is_pending_not_success`, `postgres_live.restart_reconcile` |
| `HB-SURFACE-DB-MYSQL` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-CASSANDRA` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-INFLUXDB` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-VALKEY` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-FILE` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_file_live.list`, `audit_file_live.path_present`, `audit_file_live.read_binding`, `audit_file_live.enable_idempotent`, `audit_file_live.disable_rejected` |
| `HB-SURFACE-AUDIT-HTTP` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_http_live.sys_audit_lists_file_and_http`, `audit_http_live.api_cannot_rebind_http_audit_destination`, `audit_http_live.audited_mutation_succeeds`, `audit_http_live.every_local_audit_record_delivered_to_http_collector`, `audit_http_live.http_audit_records_do_not_expose_secret_or_bearer`, `audit_http_live.collector_outage_fails_request_closed`, `audit_http_live.collector_recovery_restores_audited_service` |
| `HB-SURFACE-AUDIT-SOCKET` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-SYSLOG` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-STORAGE-POSTGRESQL` | `storage_backends` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-STORAGE-RAFT` | `storage_backends` | `IMPLEMENTED_SCOPED` | `raft_membership_live.native_learner_join_acknowledged`, `raft_membership_live.snapshot_caught_up_learner_unseals`, `raft_membership_live.membership_persists_across_old_leader_restart`, `raft_membership_live.failover_after_membership_changes` |
| `HB-SURFACE-PLUGIN-AUTH` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-SECRET` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-DATABASE` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-KMS` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-MTLS` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_mtls.peer_identity_and_cluster_authentication` |
| `HB-SURFACE-CLUSTER-FORWARDING` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_forwarding.standby_mutation_forwarding_and_context` |
| `HB-SURFACE-CLUSTER-READ-STANDBY` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_read_standby.readindex_committed_state_and_partition_fence` |
| `HB-SURFACE-CLUSTER-STEPDOWN` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_step_down.explicit_leadership_transfer_and_old_writer_fence` |
| `HB-SURFACE-CLUSTER-AUTOPILOT` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `raft_membership_live.continuous_stabilization_promotes_voter`, `raft_membership_live.dead_voter_removed_after_real_contact_threshold`, `raft_membership_live.minimum_three_voters_preserved`, `raft_membership_live.autopilot_policy_persists_across_restart` |
| `HB-SURFACE-EDGE-HTTP-TLS` | `client_operator` | `IMPLEMENTED_SCOPED` | `edge_tls.health` |
| `HB-SURFACE-CLI-ROOT` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AGENT` | `client_operator` | `IMPLEMENTED_SCOPED` | `agent_proxy_helper_live.agent.real_login_ready`, `agent_proxy_helper_live.agent.private_sink`, `agent_proxy_helper_live.agent.real_renewal`, `agent_proxy_helper_live.agent.graceful_stop_invalidates_sink` |
| `HB-SURFACE-PROXY` | `client_operator` | `IMPLEMENTED_SCOPED` | `agent_proxy_helper_live.proxy.real_secret_read`, `agent_proxy_helper_live.proxy.rejects_supplied_root_token`, `agent_proxy_helper_live.proxy.uses_live_server_authorization`, `agent_proxy_helper_live.proxy.clean_shutdown_removes_only_owned_socket` |
| `HB-SURFACE-OPENAPI-UI` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-OPERATIONS` | `client_operator` | `IMPLEMENTED_SCOPED` | `operations.seal_status` |
| `HB-SURFACE-NAMESPACE-TREE` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-NAMESPACE-SEAL` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PROFILES-WORKFLOWS` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SELF-INIT` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-MIGRATION-LOGICAL` | `migration` | `IMPLEMENTED_SCOPED` | `live_migration_rehearsal.history_and_metadata_readback`, `live_migration_rehearsal.target_sigkill_preserves_all_versions`, `live_migration_rehearsal.checkpoint_resume_without_duplicate_version`, `live_migration_rehearsal.rollback_source_same_root_preserves_original_history` |
| `HB-SURFACE-MIGRATION-SNAPSHOT` | `migration` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-MIGRATION-CUTOVER` | `migration` | `DEFINED_NOT_IMPLEMENTED` | None |
<!-- END CURRENT REPLACEMENT SURFACES -->

## Full replacement requires more than these profiles

Every claimed surface requires a real product caller, API parameter and error
precedence coverage, authority and namespace isolation, side-effect readback,
replay/expiry/revocation behavior, crash/reopen and applicable migration/upgrade
coverage. An API returning the same error on both sides is not a positive behavior
match. Broad surfaces such as Identity, PKI, plugins and database providers cannot
be closed with one happy-path case. The complete fixed denominator may not be
reduced to fit the currently implemented subset.

Repository implementation still has to close unsupported authentication methods,
full Identity/MFA/OIDC, missing engines/providers/audit devices, plugin loading,
KMS auto-unseal, remaining CLI/Agent/Proxy/OpenAPI/UI and namespace/workflow
semantics. The per-profile guides name narrower implemented subsets; no absence
or completion claim should be inferred solely from a crate name.

## Migration, recovery and production security exits

Read [the bounded KV migration contract](../migration/HEPTABAO_OPENBAO_MIGRATION.md).
Logical KV transfer does not convert OpenBao encrypted storage, Transit ciphertext,
Raft snapshot bytes, identity/auth state, policies, active leases or external
provider effects. The current transfer has no atomic all-object cutover. Full
replacement needs an independently verified asset inventory, per-class adapters,
write-freeze and single-writer proof, verified readback and recovery/rollback
rehearsal. Do not manufacture missing historical versions or drop revocation
state to make an old binary or snapshot acceptable.

The current HeptaBao backup and native snapshot status are not OpenBao `raft.snap`.
Mixed-version upgrades, force restore, different-seal disaster recovery, large
states, physical disk/power faults and independent multi-host histories remain
separate exits. Restoring state containing database provider effects remains
blocked until external effect/tombstone reconciliation can prevent resurrection.

Production KMS/HSM or signer custody, an external monotonic rollback boundary,
independent product/distributed-systems security review, qualified vulnerability
disclosure and operational response, and independent Oracle reproduction require
authentic external completion objects. Existing external-admission verification
must check signature, trusted issuer, source/artifact binding, scope, freshness
and revocation. Repository tests may exercise rejection of forged evidence;
they must not issue their own independent approval.

No flag is promoted by this document or by a green repository workflow:
`qualification=false`, `compatibility_claim=false`, `production_authority=false`,
`migration_authority=false`, `release_authority=false`. Preserve failed execution
records and distinguish `not implemented`, `not executed`, `failed`, `scoped pass`
and `independently admitted` instead of collapsing them into a completion percent.

## Next-stage execution navigation

The existing plan's per-surface requirements are in
`docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`, backed by
`planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json`. This is not a competing global
plan. Current capacity behavior and the remaining scalable-storage exit are in
`docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`. Observed historical passes do
not transfer to a changed candidate; preserve exact source and scope.


## Retained PR96 Transit execution

`qa/openbao-acceptance/transit_migration_live.py` remains a required real
source-decrypt/destination-encrypt/readback profile. Its checkpoint and lost-ack
limits are described in `docs/migration/HEPTABAO_TRANSIT_REENCRYPTION.md`.
`planning/HEPTABAO_SURFACE_WORK_V1.json` is the retained profile/corpus-binding
catalog; the replacement execution map supplies deeper per-surface requirements.
Neither catalog advances the fixed corpus or substitutes for an execution receipt.
