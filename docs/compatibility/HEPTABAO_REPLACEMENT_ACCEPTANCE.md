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
| Surface | Category | Fixture state | Scoped fixture cases |
|---|---|---|---|
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
| `HB-SURFACE-AUTH-CERT` | `auth_methods` | `IMPLEMENTED_SCOPED` | `cert_auth_live.mTLS_listener_rejects_missing_client_chain`, `cert_auth_live.mTLS_listener_requires_client_chain`, `cert_auth_live.initialize_over_mTLS`, `cert_auth_live.unseal_over_mTLS`, `cert_auth_live.cert_auth_mount`, `cert_auth_live.cert_policy`, `cert_auth_live.cert_role_with_chain_selectors`, `cert_auth_live.cert_login_chain_eku_and_selectors`, `cert_auth_live.cert_metadata_subject_san_ou_extension`, `cert_auth_live.root_secret_for_readback`, `cert_auth_live.cert_token_policy_read`, `cert_auth_live.cert_renewal_reauthenticates_same_leaf`, `cert_auth_live.same_CA_wrong_leaf_denied_by_role_digest`, `cert_auth_live.client_auth_EKU_rejects_server_only_certificate`, `cert_auth_live.untrusted_chain_rejected_by_TLS`, `cert_auth_live.restart_starts_sealed`, `cert_auth_live.restart_unseal_over_mTLS`, `cert_auth_live.cert_renewal_reauthenticates_after_restart` |
| `HB-SURFACE-AUTH-JWT-OIDC` | `auth_methods` | `IMPLEMENTED_SCOPED` | `remote_jwks_live.real_rsa_signature_login`, `remote_jwks_live.same_assertion_replay_rejected`, `remote_jwks_live.p256_rotation_login`, `remote_jwks_live.disabled_subject_login_rejected`, `remote_jwks_live.restart_current_key_login` |
| `HB-SURFACE-AUTH-KUBERNETES` | `auth_methods` | `IMPLEMENTED_SCOPED` | `kubernetes_online.online_review_to_real_token`, `kubernetes_online.reviewer_request_binding`, `kubernetes_online.disabled_identity_denies_new_login`, `kubernetes_online.finite_replay_denied`, `kubernetes_online.all_egress_requests_match_review_contract` |
| `HB-SURFACE-AUTH-LDAP` | `auth_methods` | `IMPLEMENTED_SCOPED` | `ldap_bounded.config_roundtrip`, `ldap_bounded.login_and_revocation`, `ldap_bounded.filter_injection_rejected`, `ldap_openldap_live.real_openldap_bind_mints_token`, `ldap_openldap_live.live_directory_group_grants_policy`, `ldap_openldap_live.live_group_revocation_removes_policy_on_next_login`, `ldap_openldap_live.group_mapping_survives_restart`, `ldap_openldap_live.provider_outage_fails_closed`, `ldap_openldap_live.provider_success_cannot_bypass_local_revocation` |
| `HB-SURFACE-AUTH-RADIUS` | `auth_methods` | `IMPLEMENTED_SCOPED` | `radius_bounded.config_roundtrip`, `radius_bounded.pap_accept_with_message_authenticator`, `radius_bounded.reject_bad_authenticator`, `radius_bounded.reject_bad_response_authenticator`, `radius_bounded.timeout_fails_closed` |
| `HB-SURFACE-AUTH-KERBEROS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-KV` | `secret_engines` | `IMPLEMENTED_SCOPED` | `kv.write_v1`, `kv.read_v1`, `kv.write_v2`, `kv.read_old_version`, `kv.cas_rejected`, `kv.cas_no_effect`, `kv.list`, `kv.soft_delete`, `kv.deleted_read`, `kv.deleted_metadata`, `kv.undelete`, `kv.restored_read`, `kv.destroy_v1`, `kv.destroyed_read`, `kv.destroyed_metadata`, `kv.metadata_write`, `kv.metadata_read` |
| `HB-SURFACE-SECRET-TRANSIT` | `secret_engines` | `IMPLEMENTED_SCOPED` | `transit.create_key`, `transit.read_key`, `transit.encrypt_v1`, `transit.decrypt_v1`, `transit.rotate`, `transit.read_rotated_key`, `transit.encrypt_v2`, `transit.decrypt_v2`, `transit.decrypt_old_after_rotation` |
| `HB-SURFACE-SECRET-TOTP` | `secret_engines` | `IMPLEMENTED_SCOPED` | `totp.roundtrip` |
| `HB-SURFACE-SECRET-PKI` | `secret_engines` | `IMPLEMENTED_SCOPED` | `pki.mount`, `pki.root`, `pki.role`, `pki.role_read`, `pki.issue`, `pki.lease_lookup`, `pki.cert_lookup`, `pki.lease_revoke`, `pki.revoked_lease_absent`, `pki.crl_json` |
| `HB-SURFACE-SECRET-PKIEXT` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-SSH` | `secret_engines` | `IMPLEMENTED_SCOPED` | `ssh_otp_live.ssh.mount`, `ssh_otp_live.ssh.role`, `ssh_otp_live.ssh.issue`, `ssh_otp_live.ssh.verify_exact_target`, `ssh_otp_live.ssh.replay_denied`, `ssh_otp_live.ssh.revoke`, `ssh_otp_live.ssh.revoked_denied`, `ssh_otp_live.ssh.wrapped_issue`, `ssh_otp_live.ssh.unwrapped_otp_works` |
| `HB-SURFACE-SECRET-DATABASE` | `secret_engines` | `IMPLEMENTED_SCOPED` | `postgres_pipeline_simulated.verified_scram_configuration`, `postgres_pipeline_simulated.configuration_never_returns_password`, `postgres_pipeline_simulated.no_arbitrary_sql`, `postgres_pipeline_simulated.issue_after_durable_intent_and_readback`, `postgres_pipeline_simulated.model_observed_matches_returned_credentials`, `postgres_pipeline_simulated.renew_external_expiry_then_commit`, `postgres_pipeline_simulated.precise_revoke`, `postgres_pipeline_simulated.lost_post_apply_response_no_secret` |
| `HB-SURFACE-SECRET-KUBERNETES` | `secret_engines` | `IMPLEMENTED_SCOPED` | `kubernetes_cluster_live.real_kubernetes_secrets_mount`, `kubernetes_cluster_live.real_kubernetes_secrets_config`, `kubernetes_cluster_live.real_kubernetes_secrets_role`, `kubernetes_cluster_live.real_kubernetes_tokenrequest_issues_secret`, `kubernetes_cluster_live.kubernetes_secret_lease_is_bounded_nonrenewable`, `kubernetes_cluster_live.issued_kubernetes_secret_token_is_real`, `kubernetes_cluster_live.kubernetes_secret_role_readback_redacts_manager`, `kubernetes_cluster_live.kubernetes_secret_config_role_survive_restart`, `kubernetes_cluster_live.deleted_serviceaccount_invalidates_secret_tokens`, `kubernetes_cluster_live.recreated_serviceaccount_gets_new_secret_token` |
| `HB-SURFACE-SECRET-OPENLDAP` | `secret_engines` | `IMPLEMENTED_SCOPED` | `openldap_secret_live.real_manager_bind_and_issue`, `openldap_secret_live.owner_renewal_and_other_owner_denied`, `openldap_secret_live.provider_and_service_restart_recovery`, `openldap_secret_live.tombstone_revoke_denies_old_password`, `openldap_secret_live.delayed_add_is_fenced`, `openldap_secret_live.provider_outage_pending_reconcile`, `openldap_secret_live.idle_expiry_reconciles`, `openldap_secret_live.no_plaintext_secret_persistence` |
| `HB-SURFACE-SECRET-RABBITMQ` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-POSTGRESQL` | `database_providers` | `IMPLEMENTED_SCOPED` | `postgres_live.native_pg_tls_scram_config`, `postgres_live.credential_really_logs_into_postgresql`, `postgres_live.slow_provider_does_not_block_unrelated_kv_write`, `postgres_live.renewed_credential_survives_service_restart`, `postgres_live.revoke_terminates_existing_database_session`, `postgres_live.revoke_really_prevents_pg_login`, `postgres_live.provider_outage_is_pending_not_success`, `postgres_live.restart_reconcile` |
| `HB-SURFACE-DB-MYSQL` | `database_providers` | `IMPLEMENTED_SCOPED` | `mysql_live.real_mysql_8_4_ready`, `mysql_live.mysql_plugin_configuration_readback`, `mysql_live.mysql_readonly_issue_reaches_provider`, `mysql_live.mysql_readonly_select_succeeds`, `mysql_live.mysql_readonly_write_denied`, `mysql_live.mysql_readwrite_statement_matrix`, `mysql_live.mysql_transaction_rollback_is_observed`, `mysql_live.mysql_dynamic_credential_renew_reaches_provider`, `mysql_live.mysql_provider_state_survives_restart`, `mysql_live.mysql_service_state_survives_restart`, `mysql_live.mysql_revoke_removes_provider_login`, `mysql_live.mysql_outage_retains_revoke_intent`, `mysql_live.mysql_restart_reconciles_pending_revoke` |
| `HB-SURFACE-DB-CASSANDRA` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-INFLUXDB` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-VALKEY` | `database_providers` | `IMPLEMENTED_SCOPED` | `valkey_live.valkey_tls_acl_configuration`, `valkey_live.issued_user_reads_bound_key`, `valkey_live.issued_readonly_user_cannot_write`, `valkey_live.issued_user_key_escape_denied`, `valkey_live.acl_user_survives_valkey_restart`, `valkey_live.renew_after_both_restarts`, `valkey_live.readwrite_can_set`, `valkey_live.stale_writer_aborted_after_revoke`, `valkey_live.revoke_terminates_existing_session`, `valkey_live.revocation_fence_survives_provider_restart`, `valkey_live.idle_expiry_removes_native_credential`, `valkey_live.provider_outage_retains_revoke_intent`, `valkey_live.restart_reconciles_pending_native_revoke`, `valkey_live.reconciled_revoke_survives_both_restarts` |
| `HB-SURFACE-AUDIT-FILE` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_file_live.list`, `audit_file_live.path_present`, `audit_file_live.read_binding`, `audit_file_live.duplicate_enable_rejected`, `audit_file_live.disable_rejected` |
| `HB-SURFACE-AUDIT-HTTP` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_http_live.sys_audit_lists_file_and_http`, `audit_http_live.api_cannot_rebind_http_audit_destination`, `audit_http_live.audited_mutation_succeeds`, `audit_http_live.every_local_audit_record_delivered_to_http_collector`, `audit_http_live.http_audit_records_do_not_expose_secret_or_bearer`, `audit_http_live.collector_outage_fails_request_closed`, `audit_http_live.collector_recovery_restores_audited_service` |
| `HB-SURFACE-AUDIT-SOCKET` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_socket_live.sys_audit_lists_file_and_socket`, `audit_socket_live.api_cannot_rebind_socket_destination`, `audit_socket_live.audited_mutation_succeeds`, `audit_socket_live.socket_tail_matches_local_before_fault`, `audit_socket_live.socket_records_do_not_expose_secret_or_bearer`, `audit_socket_live.bounded_socket_outage_uses_mandatory_file_device`, `audit_socket_live.socket_outage_is_observable`, `audit_socket_live.collector_receives_new_records_after_recovery` |
| `HB-SURFACE-AUDIT-SYSLOG` | `audit_devices` | `IMPLEMENTED_SCOPED` | `audit_syslog_live.sys_audit_lists_file_and_syslog`, `audit_syslog_live.syslog_device_reports_facility_and_tag_only`, `audit_syslog_live.api_cannot_rebind_syslog_device`, `audit_syslog_live.audited_mutation_succeeds`, `audit_syslog_live.syslog_tail_matches_local_authenticated_audit`, `audit_syslog_live.syslog_records_do_not_expose_secret_or_bearer`, `audit_syslog_live.syslog_outage_uses_mandatory_file_device`, `audit_syslog_live.syslog_outage_is_observable`, `audit_syslog_live.collector_recovery_preserves_service`, `audit_syslog_live.mandatory_file_audit_continues_through_syslog_fault` |
| `HB-SURFACE-STORAGE-POSTGRESQL` | `storage_backends` | `IMPLEMENTED_SCOPED` | `postgres_storage_live.fresh_postgresql_17_cluster_and_unprivileged_storage_owner`, `postgres_storage_live.opaque_binary_value_roundtrip`, `postgres_storage_live.shallow_ordered_hierarchical_listing`, `postgres_storage_live.multi_record_commit_publishes_together`, `postgres_storage_live.repeatable_read_retains_snapshot`, `postgres_storage_live.lost_commit/lost_commit_reply_reports_unknown_outcome`, `postgres_storage_live.lost_commit_effect_is_durable_at_postgresql`, `postgres_storage_live.wrong_password/untrusted_tls_or_credentials_rejected`, `postgres_storage_live.missing_primary_key/altered_storage_constraints_rejected`, `postgres_storage_live.committed_storage_survives_postgresql_sigkill_restart` |
| `HB-SURFACE-STORAGE-RAFT` | `storage_backends` | `IMPLEMENTED_SCOPED` | `raft_membership_live.native_learner_join_acknowledged`, `raft_membership_live.snapshot_caught_up_learner_unseals`, `raft_membership_live.membership_persists_across_old_leader_restart`, `raft_membership_live.failover_after_membership_changes` |
| `HB-SURFACE-PLUGIN-AUTH` | `plugin_classes` | `IMPLEMENTED_SCOPED` | `plugin_auth_live.login`, `plugin_auth_live.denied`, `plugin_auth_live.plugin_authority_fields_rejected`, `plugin_auth_live.server_owned_policy`, `plugin_auth_live.restart_login`, `plugin_auth_live.digest_fence`, `plugin_auth_live.issued_token_revoked_on_disable` |
| `HB-SURFACE-PLUGIN-SECRET` | `plugin_classes` | `IMPLEMENTED_SCOPED` | `plugin_secret_live.read`, `plugin_secret_live.write_fenced`, `plugin_secret_live.unauthorized_no_entry`, `plugin_secret_live.restart_binding`, `plugin_secret_live.digest_fence` |
| `HB-SURFACE-PLUGIN-DATABASE` | `plugin_classes` | `IMPLEMENTED_SCOPED` | `plugin_database_live.catalog_lists_admitted_database_plugin`, `plugin_database_live.unknown_database_plugin_config_fails_closed`, `plugin_database_live.database_plugin_configuration_readback`, `plugin_database_live.dynamic_credential_issue_reaches_plugin`, `plugin_database_live.issued_secret_matches_plugin_digest`, `plugin_database_live.dynamic_credential_renew_reaches_plugin`, `plugin_database_live.database_plugin_binding_survives_service_restart`, `plugin_database_live.changed_plugin_executable_is_fenced_before_revoke`, `plugin_database_live.digest_fence_does_not_claim_external_revoke`, `plugin_database_live.restored_plugin_completes_pending_revoke`, `plugin_database_live.revoked_plugin_credential_is_inactive` |
| `HB-SURFACE-PLUGIN-KMS` | `plugin_classes` | `IMPLEMENTED_SCOPED` | `plugin_kms_live.catalog_lists_kms`, `plugin_kms_live.catalog_checksum_bound`, `plugin_kms_live.wrong_version_no_entry`, `plugin_kms_live.disabled_key_no_entry`, `plugin_kms_live.wrap`, `plugin_kms_live.unwrap`, `plugin_kms_live.generate_data_key`, `plugin_kms_live.provider_custody_survives_service_restart`, `plugin_kms_live.provider_key_outside_service_state`, `plugin_kms_live.changed_plugin_fails_before_entry`, `plugin_kms_live.post_entry_timeout_fences_host`, `plugin_kms_live.catalog_reports_reconciliation_required`, `plugin_kms_live.fenced_host_rejects_blind_retry`, `plugin_kms_live.restart_readmits_without_replaying_unknown` |
| `HB-SURFACE-CLUSTER-MTLS` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_mtls.peer_identity_and_cluster_authentication` |
| `HB-SURFACE-CLUSTER-FORWARDING` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_forwarding.standby_mutation_forwarding_and_context` |
| `HB-SURFACE-CLUSTER-READ-STANDBY` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_read_standby.readindex_committed_state_and_partition_fence` |
| `HB-SURFACE-CLUSTER-STEPDOWN` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `ha_step_down.explicit_leadership_transfer_and_old_writer_fence` |
| `HB-SURFACE-CLUSTER-AUTOPILOT` | `cluster_ha` | `IMPLEMENTED_SCOPED` | `raft_membership_live.continuous_stabilization_promotes_voter`, `raft_membership_live.dead_voter_removed_after_real_contact_threshold`, `raft_membership_live.minimum_three_voters_preserved`, `raft_membership_live.autopilot_policy_persists_across_restart` |
| `HB-SURFACE-EDGE-HTTP-TLS` | `client_operator` | `IMPLEMENTED_SCOPED` | `edge_tls.health` |
| `HB-SURFACE-CLI-ROOT` | `client_operator` | `IMPLEMENTED_SCOPED` | `client_live.client.write_version`, `client_live.client.read_value`, `client_live.client.list_key`, `client_live.client.capability_root`, `client_live.client.wrap_redacts`, `client_live.client.replay_error_no_data` |
| `HB-SURFACE-AGENT` | `client_operator` | `IMPLEMENTED_SCOPED` | `agent_proxy_helper_live.agent.real_login_ready`, `agent_proxy_helper_live.agent.private_sink`, `agent_proxy_helper_live.agent.real_renewal`, `agent_proxy_helper_live.agent.graceful_stop_invalidates_sink` |
| `HB-SURFACE-PROXY` | `client_operator` | `IMPLEMENTED_SCOPED` | `agent_proxy_helper_live.proxy.real_secret_read`, `agent_proxy_helper_live.proxy.rejects_supplied_root_token`, `agent_proxy_helper_live.proxy.uses_live_server_authorization`, `agent_proxy_helper_live.proxy.clean_shutdown_removes_only_owned_socket` |
| `HB-SURFACE-OPENAPI-UI` | `client_operator` | `IMPLEMENTED_SCOPED` | `openapi_live.root_openapi_entries`, `openapi_live.candidate_has_only_standard_openapi_operation_keys`, `openapi_live.non_root_visibility_fails_closed`, `openapi_live.revoked_token_denied`, `openapi_live.openapi_restart_stable` |
| `HB-SURFACE-OPERATIONS` | `client_operator` | `IMPLEMENTED_SCOPED` | `operations.seal_status` |
| `HB-SURFACE-NAMESPACE-TREE` | `namespace_workflow` | `IMPLEMENTED_SCOPED` | `namespace_tree_live.namespace.create_parent`, `namespace_tree_live.namespace.read_parent`, `namespace_tree_live.namespace.parent_shape`, `namespace_tree_live.namespace.list_root`, `namespace_tree_live.namespace.list_parent_metadata`, `namespace_tree_live.namespace.create_child`, `namespace_tree_live.namespace.read_child`, `namespace_tree_live.namespace.child_shape`, `namespace_tree_live.namespace.list_direct_children_only`, `namespace_tree_live.namespace.child_not_flattened_into_root_list`, `namespace_tree_live.namespace.patch_child`, `namespace_tree_live.namespace.read_patched_child`, `namespace_tree_live.namespace.merge_patch_semantics`, `namespace_tree_live.namespace.delete_child`, `namespace_tree_live.namespace.child_absent`, `namespace_tree_live.namespace.delete_parent`, `namespace_tree_live.namespace.recreate_parent`, `namespace_tree_live.namespace.read_recreated_parent`, `namespace_tree_live.namespace.recreate_changes_identity`, `namespace_tree_live.namespace.cleanup_parent` |
| `HB-SURFACE-NAMESPACE-SEAL` | `namespace_workflow` | `IMPLEMENTED_SCOPED` | `namespace_seal_live.create_namespace`, `namespace_seal_live.seal_status`, `namespace_seal_live.sealed_child_fails_closed`, `namespace_seal_live.sealed_descendant_inherits_parent_fence`, `namespace_seal_live.unauthorized_seal_control_denied`, `namespace_seal_live.parent_unseal`, `namespace_seal_live.namespace_seal_survives_restart`, `namespace_seal_live.post_restart_fence` |
| `HB-SURFACE-PROFILES-WORKFLOWS` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SELF-INIT` | `namespace_workflow` | `IMPLEMENTED_SCOPED` | `self_init_live.self_init_starts_uninitialized`, `self_init_live.self_init_race_exclusion`, `self_init_live.self_init_one_time_bootstrap`, `self_init_live.self_init_custody_material_not_persisted_plaintext`, `self_init_live.self_init_lost_ack_recovers_same_response`, `self_init_live.self_init_wrong_nonce_denied`, `self_init_live.self_init_parameter_replay_denied`, `self_init_live.self_init_without_nonce_cannot_reinitialize`, `self_init_live.self_init_threshold_unseal`, `self_init_live.self_init_declared_policy`, `self_init_live.self_init_declared_transient_token`, `self_init_live.self_init_declared_effect_readback`, `self_init_live.self_init_root_ack`, `self_init_live.self_init_ack_idempotent`, `self_init_live.self_init_recovery_artifact_removed`, `self_init_live.self_init_transient_root_revoked`, `self_init_live.self_init_root_unusable_after_revoke`, `self_init_live.self_init_child_unusable_after_root_revoke`, `self_init_live.self_init_restart_stays_sealed`, `self_init_live.self_init_restart_unseal`, `self_init_live.self_init_revocation_survives_restart`, `self_init_live.self_init_reinit_after_ack_rejected`, `self_init_live.self_init_persisted_credentials_absent` |
| `HB-SURFACE-MIGRATION-LOGICAL` | `migration` | `IMPLEMENTED_SCOPED` | `live_migration_rehearsal.history_and_metadata_readback`, `live_migration_rehearsal.target_sigkill_preserves_all_versions`, `live_migration_rehearsal.checkpoint_resume_without_duplicate_version`, `live_migration_rehearsal.rollback_source_same_root_preserves_original_history` |
| `HB-SURFACE-MIGRATION-SNAPSHOT` | `migration` | `IMPLEMENTED_SCOPED` | `migration_snapshot_live.official_openbao_2_6_2_tls_oracle_ready`, `migration_snapshot_live.official_snapshot_saved`, `migration_snapshot_live.authentic_snapshot_inspected`, `migration_snapshot_live.tampered_archive_rejected`, `migration_snapshot_live.state_size_limit_rejected`, `migration_snapshot_live.unknown_archive_path_rejected` |
| `HB-SURFACE-MIGRATION-CUTOVER` | `migration` | `IMPLEMENTED_SCOPED` | `live_migration_rehearsal.cutover_source_process_fenced_before_target_acceptance`, `live_migration_rehearsal.cutover_target_serves_verified_migrated_history`, `live_migration_rehearsal.cutover_target_still_rejects_source_active_token`, `live_migration_rehearsal.cutover_target_still_rejects_source_revoked_token`, `live_migration_rehearsal.cutover_target_still_rejects_source_wrapping_token`, `live_migration_rehearsal.rollback_target_process_fenced_before_source_reactivation`, `live_migration_rehearsal.rollback_reactivates_source_authority_only_after_target_fence`, `live_migration_rehearsal.rollback_does_not_resurrect_source_revoked_token`, `live_migration_rehearsal.rollback_source_wrapping_authority_restored_only_after_target_fence` |
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
