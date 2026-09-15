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
| Raft administration | `raft_membership_live.py --dead-cleanup` | Five real same-host processes, committed membership, persisted-snapshot catch-up and observed cleanup grace; not five physical hosts. |
| Bounded migration | `live_migration_rehearsal.py` | Real TLS KV history transfer, lost-acknowledgement reconciliation, restart, dry-run and idempotency; not full-instance cutover. |

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
| Surface ID | Category | Corpus fixture state | Declared case IDs |
|---|---|---|---|
| `HB-SURFACE-CORE-REQUEST-PIPELINE` | `core_system` | `IMPLEMENTED_SCOPED` | `core.unknown_route_denied` |
| `HB-SURFACE-SYSTEM-BACKEND` | `core_system` | `IMPLEMENTED_SCOPED` | `system.init_status` |
| `HB-SURFACE-MOUNT-REGISTRY` | `core_system` | `IMPLEMENTED_SCOPED` | `kv.mount`, `transit.mount` |
| `HB-SURFACE-POLICY-ACL` | `core_system` | `IMPLEMENTED_SCOPED` | `token.policy`, `token.write_denied`, `token.denial_no_effect` |
| `HB-SURFACE-IDENTITY` | `core_system` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-TOKEN` | `core_system` | `IMPLEMENTED_SCOPED` | `token.create`, `token.revoke`, `token.create_expiring`, `token.expired_denied` |
| `HB-SURFACE-CUBBYHOLE-WRAPPING` | `core_system` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-LEASE-EXPIRATION` | `core_system` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-TOKEN` | `auth_methods` | `IMPLEMENTED_SCOPED` | `token.read_allowed`, `token.revoked_denied`, `token.invalid_denied` |
| `HB-SURFACE-AUTH-USERPASS` | `auth_methods` | `IMPLEMENTED_SCOPED` | `userpass.login` |
| `HB-SURFACE-AUTH-APPROLE` | `auth_methods` | `IMPLEMENTED_SCOPED` | `approle.login` |
| `HB-SURFACE-AUTH-CERT` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-JWT-OIDC` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-KUBERNETES` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-LDAP` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-RADIUS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUTH-KERBEROS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-KV` | `secret_engines` | `IMPLEMENTED_SCOPED` | `kv.write_v1`, `kv.read_v1`, `kv.write_v2`, `kv.read_old_version`, `kv.cas_rejected`, `kv.cas_no_effect`, `kv.list`, `kv.soft_delete`, `kv.deleted_read`, `kv.deleted_metadata`, `kv.undelete`, `kv.restored_read`, `kv.destroy_v1`, `kv.destroyed_read`, `kv.destroyed_metadata`, `kv.metadata_write`, `kv.metadata_read` |
| `HB-SURFACE-SECRET-TRANSIT` | `secret_engines` | `IMPLEMENTED_SCOPED` | `transit.create_key`, `transit.read_key`, `transit.encrypt_v1`, `transit.decrypt_v1`, `transit.rotate`, `transit.read_rotated_key`, `transit.encrypt_v2`, `transit.decrypt_v2`, `transit.decrypt_old_after_rotation` |
| `HB-SURFACE-SECRET-TOTP` | `secret_engines` | `IMPLEMENTED_SCOPED` | `totp.roundtrip` |
| `HB-SURFACE-SECRET-PKI` | `secret_engines` | `IMPLEMENTED_SCOPED` | `pki.mount`, `pki.root`, `pki.role`, `pki.role_read`, `pki.issue`, `pki.lease_lookup`, `pki.cert_lookup`, `pki.lease_revoke`, `pki.revoked_lease_absent`, `pki.crl_json` |
| `HB-SURFACE-SECRET-PKIEXT` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-SSH` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-DATABASE` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-KUBERNETES` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-OPENLDAP` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SECRET-RABBITMQ` | `secret_engines` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-POSTGRESQL` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-MYSQL` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-CASSANDRA` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-INFLUXDB` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-DB-VALKEY` | `database_providers` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-FILE` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-HTTP` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-SOCKET` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AUDIT-SYSLOG` | `audit_devices` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-STORAGE-POSTGRESQL` | `storage_backends` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-STORAGE-RAFT` | `storage_backends` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-AUTH` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-SECRET` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-DATABASE` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PLUGIN-KMS` | `plugin_classes` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-MTLS` | `cluster_ha` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-FORWARDING` | `cluster_ha` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-READ-STANDBY` | `cluster_ha` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-STEPDOWN` | `cluster_ha` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-CLUSTER-AUTOPILOT` | `cluster_ha` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-EDGE-HTTP-TLS` | `client_operator` | `IMPLEMENTED_SCOPED` | `edge_tls.health` |
| `HB-SURFACE-CLI-ROOT` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-AGENT` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PROXY` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-OPENAPI-UI` | `client_operator` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-OPERATIONS` | `client_operator` | `IMPLEMENTED_SCOPED` | `operations.seal_status` |
| `HB-SURFACE-NAMESPACE-TREE` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-NAMESPACE-SEAL` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-PROFILES-WORKFLOWS` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-SELF-INIT` | `namespace_workflow` | `DEFINED_NOT_IMPLEMENTED` | None |
| `HB-SURFACE-MIGRATION-LOGICAL` | `migration` | `DEFINED_NOT_IMPLEMENTED` | None |
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
