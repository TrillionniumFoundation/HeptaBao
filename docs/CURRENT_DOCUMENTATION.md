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

- `docs/architecture/HEPTABAO_CURRENT_STATE_FORMAT.md` — the current discriminator, legacy read admission, commit promotion and rollback boundaries.

- `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md` — actual runtime dependency closure and internal state owners.
- `docs/modules/CURRENT_RUNTIME_MAP.md` — all 46 packages mapped to runtime integration, routes and named source tests.

The following retained increment/target documents describe their own historical or library scope:

- `docs/architecture/HEPTABAO_V2_MANDATORY_REQUEST_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_2_RAFT_RUNTIME.md`
- `docs/architecture/HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md`
- `specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md`

The runnable server composes real TLS, private persistent authentication/ACL, bounded live login/Identity/internal-group policies, encrypted KV/Transit/TOTP, authenticated audit and optional per-process networked Raft. The workspace also contains separately tested identity, lease, telemetry, client and migration contracts/candidates. Those packages are not in the server's dependency closure and do not establish corresponding integrated product features. The 60-surface OpenBao 2.6.2 corpus is a denominator for acceptance evidence, not a compatibility claim. Independent security, external provider, migration, upgrade and destructive HA qualification remain separate gates.

## Module documentation

Current source authority is the exact Git commit/tree exercised by CI. `planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json` is a retained reproducible diagnostic snapshot, not a second source authority.
Read `docs/modules/CURRENT_SOURCE_BINDING.md` before using inherited V1.4.7
source tables; those tables are historical, not current API inventories.

- `docs/modules/README.md` — complete index for all 46 workspace packages.
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` — current semantic standard.
- `planning/HEPTABAO_MODULE_CLOSURE_REGISTRY_V1.yaml` and `docs/module-closure/` —
  one source-bound design, boundary, failure-semantics and acceptance dossier
  for every package, checked by `scripts/validate_module_closure.py`.
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

## Core isolation and current Identity implementation

- `docs/engines/HEPTABAO_CUBBYHOLE.md` — integrated token-private storage, ACL
  specificity, final-use durability, expiry/tidy boundaries and execution.
- `docs/engines/HEPTABAO_IDENTITY_RUNTIME.md` — actual server-owned Identity
  endpoints, indexes, merge/lineage, bounded verified-login binding and live
  internal-group policies; full external-auth/MFA/OIDC remain open.

These documents do not change the 60-surface denominator or assert completion
of the combined Cubbyhole/wrapping or full Identity compatibility surfaces.
`qa/openbao-acceptance/identity_live.py` is the selected official-binary
Identity differential profile; `identity_upgrade.py` tests the version-1 to
version-2 binary boundary and intentional old-binary refusal.
`scripts/current_compatibility_coverage.py`
derives the current compatibility guide counters from corpus rows; neither
entry point can issue independent or production admission.

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

## Replacement execution map

[Current replacement acceptance boundaries](compatibility/HEPTABAO_REPLACEMENT_ACCEPTANCE.md)
binds the fixed corpus to required real-service, Oracle, migration and cluster
profiles without granting independent or production authority.

## Current validation commands

```text
python scripts/validate_repository_v2.py
python scripts/validate_current_documentation_semantics.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
# qrcode is vendored third-party code: workspace tests/build it, product Clippy owns first-party Rust.
cargo +1.98.0 clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

A current exact-head and real prospective-main-merge run are required. Historical green checks and local output are not admission evidence.

Development feedback is intentionally fail-fast: once source identity, formatting,
repository truth, or an earlier mandatory runtime profile fails, the expensive
downstream qualification profiles do not continue merely to collect unrelated
diagnostics. The workflow-trust lane owns workflow/source trust checks; the current
full replacement qualification owns the complete Rust fmt/test/Clippy/rustdoc gates
for both exact head and prospective merge. `scripts/validate_delivery_gate_ownership.py`
guards that separation so removing duplicate execution cannot silently remove a
native product gate.

Online authentication, Kubernetes protocol and RADIUS renewal HA receipts now
require named safety checks and a terminal completion check instead of a fixed
observation total. Additional successful observations do not invalidate a run;
missing phases, duplicate names, non-boolean results and exceptions still fail.
AppRole renewal and child-token lifetime comparisons also require their named
lifecycle checks. A fabricated list with the former expected row count cannot
qualify; their request, TTL, revocation, wrapping and restart assertions remain.
Their first runs under these gates pass [154 AppRole observations per side](../qa/openbao-acceptance/evidence/approle-renewal-d2c669d.json)
and [202 child-token observations per side](../qa/openbao-acceptance/evidence/token-child-lifetime-d2c669d.json).
JWT role TTL inheritance, null updates, issued caps and local renewal pass
[345 observations per side](../qa/openbao-acceptance/evidence/jwt-native-ttl-4d5b6b8.json)
against the pinned OpenBao 2.6.2 binary. The comparison exposed a one-second
renewal overrun after rounded remote issuance. Native expiry now bounds both
the granted duration and the absolute issue-time deadline; the conservative
post-I/O authorization clock is unchanged. This profile tunes its mounts and
does not establish untuned system-default parity.
A real schema-31 binary creates the roles, tokens and store used in the
[323-check schema-32 upgrade](../qa/openbao-acceptance/evidence/jwt-native-ttl-upgrade-43e6353.json).
Read-only reopen preserves application artifacts; explicit role changes adopt
inheritance, issued caps survive renewal/restart, and the old binary refuses
the committed new format without altering application artifacts. Earlier
failed receipts remain in the external-SSD workspace: one caught duplicate
observation labels, another incorrectly required an active lease to reach its
absolute cap. The corrected checks preserve exact captured limits and reject
any grant or expiry beyond them.
Fresh system defaults and Token API mount lifetimes now pass
[194 observations per side](../qa/openbao-acceptance/evidence/token-mount-ttl-f2650f4.json),
including the prior-grant renewal rule, changing mount maxima, root special
cases, wrapping and restart. The [387-check real schema-32 upgrade](../qa/openbao-acceptance/evidence/token-defaults-upgrade-f2650f4.json)
preserves old one-hour defaults and ambiguous issued caps, distinguishes old
missing grant history from new recorded grants, verifies read-only byte
preservation and refused downgrade, and checks a separate fresh 32-day store.
The [202-observation child-token comparison](../qa/openbao-acceptance/evidence/token-child-lifetime-f2650f4.json)
also passes on this candidate. AppRole credential defaults and missing legacy
SecretID metadata remain separate work; these results do not close full auth
compatibility or production qualification.
AppRole native zero defaults and SecretID issuance facts pass
[161 observations per side](../qa/openbao-acceptance/evidence/approle-native-defaults-d26ed9d.json),
with six separate candidate checks for immediate expiry rejection. OpenBao's
periodic SecretID tidy permits a different expiry window; that difference is
explicit and is excluded from the matching observations. The
[231-check real schema-33 upgrade](../qa/openbao-acceptance/evidence/approle-native-defaults-upgrade-d26ed9d.json)
retains old positive roles and issued credentials, preserves missing historical
metadata honestly, tests new clipped issuance and unlimited defaults, and checks
refused downgrade and recovery. The existing
[154-observation AppRole renewal comparison](../qa/openbao-acceptance/evidence/approle-renewal-d26ed9d.json)
also passes. Source constraints, batch tokens and other unimplemented AppRole
parameters remain outside these profiles.
The strengthened forged-origin tests pass [49 RADIUS HA checks](../qa/openbao-acceptance/evidence/radius-cidrs-ha-d2c669d.json)
and [49 LDAP HA checks](../qa/openbao-acceptance/evidence/ldap-cidrs-ha-d2c669d.json):
the forged headers now carry the allowed address while the actual socket uses a
denied address, exercising the intended boundary.
Schema-30 regressions record [36 authentication HA checks](../qa/openbao-acceptance/evidence/online-auth-ha-5181b4c.json),
[71 Kubernetes protocol checks](../qa/openbao-acceptance/evidence/kubernetes-online-5181b4c.json)
and [57 native RADIUS HA checks](../qa/openbao-acceptance/evidence/radius-renewal-ha-5181b4c.json).
An initial RADIUS attempt failed during fixture bootstrap before business checks;
the diagnostic and normal reruns both passed. Its cause remains unestablished,
and the earlier failure record is retained in the external-SSD test workspace.

Historical H01/H02, V1.3, V2.4 and V2.5 admission diagnostic workflows remain
manual-only for reproducible evidence. Their obsolete branch push triggers and
the duplicate V2 Linux assurance schedule are retired. Pull requests use the
current replacement qualification and workflow-trust lanes. The V2.5
multi-platform workflow retains its nightly schedule because ARM64 and macOS
coverage differs from the Linux PR gate; its obsolete branch trigger is retired.

## Current scalability, cutover and release-candidate evidence

The bounded whole-state runtime remains a scalability blocker rather than a
record-oriented storage claim. The current capacity live profile records logical
state growth, durable bytes, write latency and Linux RSS so candidate changes can
be compared with measured write amplification instead of only raising constants.
HTTP and authenticated HA request workers also use a bounded deadline when
waiting for the single Service writer; stateful execution is still serialized.

The live OpenBao migration rehearsal now exercises a process-fenced cutover and
rollback boundary: the official source process is stopped before target
acceptance, and the target is stopped before the same source data root is
restarted. This remains a bounded synthetic rehearsal and does not grant cutover
or rollback authority for a production estate.

The multi-platform repository workflow now builds the exact release candidate
twice in isolated target roots, requires byte-identical server binaries, and
generates/revalidates a deterministic SPDX 2.3 candidate SBOM bound to the exact
Git SHA, Cargo.lock package denominator and binary SHA-256. These are
repository-controlled release inputs, not a signature, independent attestation or
release authority.

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

## Service and client runtime increments

- `docs/auth/HEPTABAO_RESPONSE_WRAPPING.md`: real single-use response capture, forwarding, recovery and schema 3.
- `docs/auth/HEPTABAO_CAPABILITIES.md`: live policy inspection without consuming a subject token.
- `docs/engines/HEPTABAO_SSH_OTP.md`: online OTP issuance/verification and scoped registered lease lifecycle.
- `clients/python/README.md`: installable real HTTPS SDK and explicit private-output CLI.

These extend the existing source owner without changing the 46 Cargo-package
count. The fixed compatibility corpus remains separate from selected new official
binary profiles. Source/test presence and local fixture execution do not establish
full compatibility, multi-platform/host safety, independent acceptance or release.

## Operational Agent, Unix proxy, SSH verifier and idle expiry

The actual process entry points, pending-checkpoint recovery, file/TLS trust,
server lifetime worker and explicit unimplemented scope are specified in
[`operations/HEPTABAO_AGENT_PROXY_HELPER.md`](operations/HEPTABAO_AGENT_PROXY_HELPER.md).
The Python processes do not reclassify standalone Rust contract/model crates as
server dependencies. Current module status and all independent gates are unchanged.

## Schema 4 external boundaries and qualification distinction

- [PostgreSQL provider, renewable lease and reconcile](engines/HEPTABAO_POSTGRESQL_PROVIDER.md): actual PostgreSQL 17 acceptance remains blocked without the server binaries; wire models are labelled explicitly.
- [Remote JWKS / Discovery-backed JWT](auth/HEPTABAO_REMOTE_JWT_KEYS.md): fresh verified HTTPS keys, not browser OIDC code flow.
- [Raft membership / persisted snapshots / Autopilot](operations/HEPTABAO_RAFT_ADMINISTRATION.md): same-version pre-enrolled native consensus operations, not full restore/migration parity.

These current implementation notes supersede earlier absence-of-implementation statements only for their exact bounded profiles. Original 60-surface admission statuses and independent authority remain unchanged.

## Section-six execution increment

The current work inventory is `planning/HEPTABAO_SURFACE_WORK_V1.json`, checked by
`scripts/surface_work.py`. It retains every original surface/case binding and links
existing real executables; it is subordinate to the active V2.1 plan, not a second
plan or completion evidence. Technical contracts and open work are described in
`docs/plan/HEPTABAO_SECTION6_EXECUTION.md`. The current runtime increment adds
audited capacity observation, safe journal checkpoint maintenance and an explicit
Transit ciphertext re-encryption tool. It does not remove the aggregate state or per-epoch identity
limits, import raw OpenBao snapshots, update application ciphertext references,
or advance Hepta's independently requalified consumer pin.

## Next-stage execution navigation

The existing plan's per-surface requirements are in
`docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md`, backed by
`planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json`. This is not a competing global
plan. Current capacity behavior and the remaining scalable-storage exit are in
`docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`. Observed historical passes do
not transfer to a changed candidate; preserve exact source and scope.

Current live metadata/capacity preflight: `docs/migration/HEPTABAO_MIGRATION_PREFLIGHT.md`.
It does not replace bounded KV transfer, full asset conversion or cutover admission.

## Current online authentication increment

[Online Kubernetes / OIDC authentication](auth/HEPTABAO_ONLINE_AUTHENTICATION.md) adds actual Service-owned
TokenReview and confidential authorization-code/S256 PKCE sessions, plus a native
loopback callback CLI. The separate remote-JWT profile above remains a bearer
verifier, not code flow. Application writes use the discriminator in the current state-format contract. The new profiles
retain root-controlled enrollment, live Identity, audit and durable/HA publication.
They do not implement complete auth/MFA/browser UI compatibility, scalable storage,
independent acceptance or production authority.


## Integrated remote continuation

`docs/plan/HEPTABAO_SECTION6_INTEGRATION_20260915.md` records the reconciled PR96
and local online-auth inputs, both capacity response contracts, unified durable
maintenance, retained Transit tooling, the actual Kubernetes API/etcd/RBAC gate
and exact direct-Python-version validation. Source presence and workflow wiring
are not execution receipts. The separate record-store source is not included.
