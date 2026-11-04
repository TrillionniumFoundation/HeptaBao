# Exact-source OpenBao 2.7.1 replacement scope audit — r2

**Correction from r1:** The original snapshot row overgeneralized an inner Service 503 into a whole-front-door refusal. This r2 corrects that scope using the actual deferred HTTP entry and existing real-Raft redirect tests. The original r1 is retained unchanged; this is a source correction, not a new runtime pass.

This is a source and declared-evidence audit of the normal candidate. It does not authorize production replacement and does not run any new physical-host or provider tests.

The five active deployment tasks—formal KV2 storage, physical HA, AuthBus, per-host cutover, and cleanup—are necessary. Finishing them alone cannot satisfy the repository's existing complete-replacement contract. The selected normal V6 profile still has explicit provider, state-owner and API refusals. These are concrete implementation boundaries; they are different from an `OPEN` bookkeeping entry whose behavior may already have scoped tests.

## Candidate and primary-source binding

- Published normal source: `054d17cd50951efa46d78db3911ad1d277a0c584`.
- Physical normal source: `33cafa4c6e29f0bde1553e041550d21b4c725d9c`, tree `cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`.
- CI candidate read: `0dc39624d1266a6fca98760757b9482bf6f98a7a`.
- The admission manifest, denominator validator, V6 storage configuration guard and native auth route file have identical Git blobs in the two published refs checked here. The CI test repair replaces the stale KV1 refusal input with unsupported KV3 and leaves SSH refusal in place.

The [2.7.1 manifest](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/planning/OPENBAO_271_ADMISSION_SUPERSET_V1.json) requires exact-candidate executable evidence for **11 release gates, 15 security deltas and 11 feature/correctness deltas**. Its declared authority remains `NOT_ADMITTED`, with every listed entry `OPEN` and no receipt attached. Its [validator](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/scripts/validate_openbao_271_release_denominator.py) checks required declared IDs and selected source bindings; its own contract expressly excludes exhaustive upstream coverage and executable compatibility.

Those counts are declarations, not a fresh aggregate of the November evidence. The old observation about r670's 2560 KiB refusal must not be presented as a current failure after newer formal full34 evidence. Likewise, a still-open row must not erase a new valid scoped result.

## Confirmed current V6 boundaries

| Boundary | Exact current-source fact | Consequence for complete replacement |
|---|---|---|
| Provider configuration | `validate_native_profile` rejects V6 combined with `postgres_durable`, `openbao_wrapper`, `plugin_auth`, `plugin_database`, `plugin_kms`, `external_kms` or `plugin_secrets`. Its accepted custody is Shamir/local-file custody. | Real provider integration implemented in other profiles cannot be counted as admitted on this scalable V6 deployment. |
| Auth state | V6 eligibility requires empty JWT, Kubernetes, OIDC, LDAP, RADIUS, Kerberos and plugin-auth state; no identity MFA or password-policy state. Root mount types are token/AppRole/cert/userpass; child scope has a narrower service-token/AppRole/cert contract. | AppRole/TLS lifecycle success does not prove migration and continued operation of the remaining auth methods, MFA, password policies or their tokens. |
| Secret-engine owners | Root storage eligibility admits KV1/KV2, local Transit without external state, TOTP and PKI's local profile. Other backends fail eligibility. | SSH, database, Kubernetes, OpenLDAP and plugin secret effects need their own closed V6 storage/publication owners; generic engine code elsewhere does not create those owners. |
| SSH mount | The native mount test explicitly expects HTTP 501 for `type: ssh`; the native KV2 owner rejects types outside its KV contract. | This is a concrete negative capability boundary. The recent test correction recognizes supported KV1; it does not add SSH support. |
| Namespace composition | Transit, TOTP, PKI, wrapping and selected observations are explicitly root-local. Child dispatch permits a named set of CG/auth/identity/KV/metadata/remount/missing-route owners and returns 501 outside it. | The newly passed scoped namespace cases remain valid. They do not admit every engine/auth combination or namespace-seal model. |
| System operations | The native route guard rejects unowned restore/replication/raft/rekey/raw/migrate operations, with explicit native snapshot and Raft-observation exceptions. Manual-unseal `migrate=true` and PGP rekey `backup=true` have explicit unimplemented responses. | A supported snapshot path must not be expanded into every restore, seal migration, rekey or administrative operation. |
| Standby typed large-KV2 upload | The real deferred HTTP entry calls `begin_native_kv2_large_before`, which reaches the original Service standby refusal before any body transfer or peer forwarding; the response is 503. | This HeptaBao-specific large-upload route has no direct OpenBao endpoint oracle. Leader-local full34 success does not establish upload forwarding. Ordinary KV forwarding remains a separate admitted path. |
| Standby native snapshot transport | The real HTTP entry calls `begin_native_snapshot_before` first and emits HTTP 307 from its `Redirect` result, using the actual current leader and configured API origin without reading, replaying or spooling the upload. The later Service streaming 503 is an inner guard, not evidence that this front door lacks redirection. | Existing tests exercise real Raft leader changes plus HTTP parse/write and admission semantics. No new socket-level, pinned-OpenBao 2.7.1 wire comparison was executed by this audit; that remaining evidence scope must not be reported as an implementation absence. |

Primary sources for the table:

- [server_storage.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/server_storage.rs), `validate_native_profile`, lines 58–86; Git blob `cfcd4469d1357547ef279d35451d1dd6d3c857a4`.
- [auth_native_v6_routes.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/auth_native_v6_routes.rs), `native_v6_storage_profile`, lines 112–194; Git blob `3d3997809257b760bf7dd026a13cd2e5adb7706b`.
- [engines.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/engines.rs), `supports_native_v6_root_storage`, lines 188–207; Git blob `277c5f7d26788bdca525ac7d8a00f3a25577f18d`.
- [service.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/service.rs), standby branches 4042–4060; namespace and owner guards 4845–5052; seal migration at 8679; PGP rekey backup at 9371; Git blob `3c572c63f073a0c2babc66d0550a25ea35dd887f`.
- [http_snapshot.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/http_snapshot.rs), `execute` 257–280 and redirect writer 83–103; Git blob `782498e4622e074f9f3aeaf5d85c6368e70c5c93`. [service_snapshot_redirect_tests.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/service_snapshot_redirect_tests.rs), real-Raft admission tests, Git blob `cf2e8fc89233e157e76201161e31926924181037`; source inspected, not rerun here. [service_snapshot_transfer.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/service_snapshot_transfer.rs), admission 373–482, Git blob `b502ba68bde9e965d5f56a296853f3b13382df12`; [http_snapshot_redirect_tests.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/http_snapshot_redirect_tests.rs), actual parser/writer plus real-Raft tests, Git blob `1cfe4dac5c4068dc40ae11b18aa7c00443035299`.
- [http_native_kv2_large.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/http_native_kv2_large.rs), actual deferred entry, Git blob `20afd1b5f6003b1df2dcde0e73ce8c9de08bc293`; [service_native_kv2_large.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/service_native_kv2_large.rs), `begin_native_kv2_large_before` 251–277, Git blob `eca7d8c28bd2490e248ed30b828d2ba17f798e8a`.
- [engine_native_kv2_mount.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/crates/heptabao-server/src/engine_native_kv2_mount.rs), mount owner 104–126; [current CI test](https://github.com/TrillionniumFoundation/HeptaBao/blob/0dc39624d1266a6fca98760757b9482bf6f98a7a/crates/heptabao-server/src/service_native_kv2_mount_tests.rs), `native_kv2_mount_acl_cas_and_backend_refusals_keep_registry_and_graphs`.

These facts do not mean LDAP, RADIUS, PostgreSQL, control groups, ML-DSA, Pebble or plugins have no code anywhere in the repository. The codebase has substantial separate implementations and scoped tests. The precise issue is admission of their complete behavior on the selected normal candidate and storage profile.

## Existing release denominator beyond the five deployment tasks

The [frozen complete-replacement gate definition](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/planning/OPENBAO_REPLACEMENT_ADMISSION_V1.yaml) names the inherited requirements. The 2.7.1 superset replaces the old oracle version and adds its release deltas; the old 2.6.2 file alone cannot authorize 2.7.1.

| Existing mandatory gate | What has to be admitted, beyond a convenient fixture count |
|---|---|
| `exact_head_native` | Exact candidate repository/security/fmt/test/clippy/doc/build, acceptance and single-node evidence. |
| `prospective_main_merge` | The same complete gate set on an immutable prospective merge. |
| `module_evidence_integrity` | All 46 module dossiers with checkout-independent source binding and real executable anchors. |
| `scalable_state_storage` | Scalable record storage, meaningful above-ceiling corpus, crash/restart/HA and format migration. The new formal full34 evidence directly contributes here. |
| `replay_identity_lifecycle` | Quorum-ordered long-lived retirement/compaction, snapshots, duplicates and stale-retry non-resurrection, without a fixed lifetime ceiling. |
| `complete_surface_admission` | Whole-surface evidence for each required surface; partial runtime, tooling and fixture substitution are expressly excluded. |
| `external_provider_semantics` | Exact-candidate behavior against real compatible external services, including supported database, LDAP, KMS/seal and plugin surfaces. |
| `full_asset_migration` | All in-scope configuration, policies, identities, auth mounts, secret engines, key versions, leases, revocation state and data, with cutover and rollback preserving revoked-capability denial. |
| `multi_host_fault_upgrade` | Independent hosts, leader/process loss, partition/heal, restart/snapshot, storage faults and declared mixed-version/rolling-upgrade windows. A same-version 128-case pass is relevant but is not a claim about every upgrade window. |
| `openbao_2_7_1_oracle` | Protocol/status/error precedence, authorization, persistence and externally visible effects across the admitted surface, using the pinned official 2.7.1 baseline. |
| `security_release_supply_chain` | Artifact provenance, dependency/license/security review, secret-safe logs, platform qualification and reproducibility. |

The current [surface-work ledger](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/planning/HEPTABAO_SURFACE_WORK_V1.json) lists 59 inherited surfaces: 2 `runtime_complete`, 52 `runtime_partial`, 5 `tooling_partial`, and **0 declared `whole_surface_admitted`**. The [corpus](https://github.com/TrillionniumFoundation/HeptaBao/blob/054d17cd50951efa46d78db3911ad1d277a0c584/qa/openbao-acceptance/complete_surface_corpus_v1.json) lists 472 scoped cases, not 472 whole surfaces or a current independent release receipt. These are the stored ledger's declarations; they do not replace review of newer evidence.

## 2.7.1-specific evidence still must be bound

The exact manifest requires the 15 named security scenarios, including SecretID expiry before tidy, form-data AppRole parsing, TLS-bound certificate quotas, Kubernetes renewal after revocation, canonical path authorization, audit redaction/failure, plugin confinement/root namespace restrictions, namespace policy-cache isolation, ACME SAN validation and OIDC UI behavior.

Its 11 feature/correctness scenarios are PostgreSQL horizontal scale; real KMS/HSM PKI/Transit; post-quantum TLS and ML-DSA interoperability; Pebble durability/migration; indexed consistency; control-group second-party approval; persistent gRPC invalidation; discovery provider ports; SDK lease-watcher backoff; persistence of the disabled barrier-rotation field; and the Linux package's Pebble default. This audit identifies the required receipts; it does not classify every scenario as unimplemented.

The machine-readable companion `audit.public.json` contains all exact IDs, current declared statuses, immutable source URLs/Git blobs, confirmed boundary classifications and their limitations. No provider request, physical host test, new acceptance rule or production mutation is part of this audit.

