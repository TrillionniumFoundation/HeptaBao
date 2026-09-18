# HeptaBao

HeptaBao is an independent Rust secrets-management implementation project. The current source of truth is the **V2.1 runnable single-node candidate under review** (`HEPTABAO-PLAN-2026-09-07-V2.1`). It is not a supported production server, does not claim OpenBao compatibility, and has no production, migration or release authority.

Do not use this source to protect real secrets. Do not place live credentials, unseal shares, recovery keys, private keys, KMS material or production snapshots in issues, pull requests, CI or ordinary development environments.

## Current repository state

The current workspace package set is derived from `Cargo.toml` and cross-checked against `Cargo.lock`, the capability matrix and module index. It includes the reviewed V2 control-plane contracts plus `heptabao-durable-service` and `heptabao-runtime-service`, which join authenticated authorization and accepted-before-entry audit to restart-safe Barrier-protected mutation, reconciliation and duplicate suppression.

The `heptabao-server` binary adds bounded TLS, an AES-GCM encrypted durable state, persistent token/userpass/AppRole authentication, ACL and KV/Transit/TOTP engines. See `docs/modules/heptabao-server.md` and `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md` for exact scope and actual verification.

The current candidate includes a repository-owned durable three-voter Raft consensus core with ReadIndex, restart and quorum-loss tests; a checksum-pinned sandbox-wrapper plugin boundary with encrypted restart-safe invocation intents and lease projections; and an exact 60-surface OpenBao 2.6.2 compatibility denominator that rejects partial or repository-controlled admission. The current source now also contains an authenticated HA service boundary with mTLS peer identity binding, durable replay fencing, leader-forwarding contracts, snapshot/membership framing and bounded peer transport. The `heptabao-raft-runtime` ↔ `heptabao-ha-service` ↔ `heptabao-server` per-process composition is present in this candidate, but production admission and destructive three-process HA qualification remain open, as do qualified operating-system sandbox and provider implementations, complete identity/MFA/external-auth methods, full-format migration adapters, fixtures for the remaining compatibility surfaces, current exact-head independent Oracle observation and destructive multi-platform qualification. These are explicit blockers, not implied capabilities.

## Current integrated runtime additions

The source also implements [single-use response wrapping](docs/auth/HEPTABAO_RESPONSE_WRAPPING.md),
[live capability inspection](docs/auth/HEPTABAO_CAPABILITIES.md), and
[SSH OTP with scoped local leases](docs/engines/HEPTABAO_SSH_OTP.md). The
[Python HTTPS SDK and private-output CLI](clients/python/README.md) is runnable,
not only a contract. These remain bounded development profiles, not full OpenBao
compatibility or production readiness. The wrapping increment introduced schema 3; current schema 5 also refuses unsafe old-binary fallback;
no mixed-version rollout is implied. No real SSH host/PAM, CA, general provider
worker, full Agent/Proxy or independent acceptance is created by these additions.

The [operational consumer implementation](docs/operations/HEPTABAO_AGENT_PROXY_HELPER.md)
adds a bounded AppRole auto-auth/renewal process, generation-checked private sink,
Linux Unix-socket proxy, host/user/role-bound OTP helper, and idle Service lease
maintenance through the existing audited durable/Raft writer. These are scoped
executables, not full Agent/Proxy/SSH parity, PAM/sshd deployment or general
external-provider revocation. The current Service state is schema 5; see `docs/architecture/HEPTABAO_CURRENT_STATE_FORMAT.md`.

## Current capacity and migration prerequisites

The [capacity interface and recovery path](docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md)
expose actual bounded-state/replay/journal headroom and checkpoint the journal only
on a proven before-entry budget rejection. The old 768 KiB monolithic ceiling is
retired: schema-5 state is chunked under one shared **16 MiB** local/HA admission
bound. The active replay ledger is bounded to **32,000 identities per epoch**;
explicit replay retirement is now represented in replicated schema-5 state and
applied through the Raft state path. Whole-state serialization/publication and
multi-host retirement qualification remain open, so these are bounded mechanisms,
not production scale. [Live migration preflight](docs/migration/HEPTABAO_MIGRATION_PREFLIGHT.md)
observes real source catalogs and target headroom without copying or cutover.
The [per-surface execution map](docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md)
retains all original 60 surfaces and their work packages without issuing passes.

## Current source of truth

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml`
2. `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`
3. `planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml`
4. `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md`
5. `docs/CURRENT_DOCUMENTATION.md`
6. executable Rust and Python tests

Historical V1.x and V2.0 artifacts remain exact-source evidence but are not current state authority.

Inherited repository gates remain visible: V1.4.6 authoritative recovery closure, V1.4.5 security invariant closure, and the V1.4.4 module-documentation baseline are historical, non-current baselines. Current Cargo workspace documentation is closed over the package set derived from `Cargo.toml`; package membership is validated structurally rather than by a duplicated prose count. This candidate remains not production-deployable.

## Mandatory path

```text
bounded transport
→ authentication
→ authorization
→ accepted-before-entry audit
→ immutable authorized durable envelope
→ intent journal
→ sealed state publication
→ commit journal
→ replay ledger
→ result audit
→ response or reconcile-only outcome
```

Security bindings use domain-separated SHA-256, which is not a signature. Persisted confidentiality and authenticity belong to the injected Barrier and separately qualified KMS/HSM custody.

## Build and current checks

```bash
python -m pip install --disable-pip-version-check --requirement requirements-plan.txt
python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
```

The read-only V2.1 workflows validate the immutable exact PR head and the real prospective merge into `main`; old-head success is never inherited.

## Documentation

Current source facts are derived from the exact Git tree by `scripts/current_source_inventory.py`; `planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json` is only the fail-closed receipt-policy marker.
See `docs/modules/CURRENT_SOURCE_BINDING.md` for reproducible current API/test
projections and the separation from frozen V1.4.7 evidence.

- `docs/CURRENT_DOCUMENTATION.md`
- `docs/modules/README.md`
- `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md`
- `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`
- `docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md`
- `docs/architecture/HEPTABAO_V2_2_RAFT_RUNTIME.md`
- `docs/modules/heptabao-plugin-host.md`
- `qa/openbao-acceptance/complete_surface_corpus_v1.json`
- `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`

Every workspace package has exactly one module guide. V3 guides contain module-specific API ownership, state, invariants, failure/reconciliation, concurrency, security, persistence, observability, operations, tests and evolution boundaries.

## External blockers and authority

Final licensing, independent product-security review, qualified private disclosure and 24×7 operations, isolated signer/KMS/HSM custody, restricted Oracle transfer, destructive qualification and independent reproduction require authentic external evidence. Repository administrator permission cannot manufacture those facts.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Current external-provider and cluster-administration additions

The [PostgreSQL provider and renewable-lease profile](docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md) now has a native TLS/SCRAM client, encrypted pre-entry intents, provider-side sequence/tombstone SQL, readback and restart reconciliation. The baseline candidate `0ddbb3a3abae30f14d9267fa56c6dd67d8de08f5` executed real PostgreSQL acceptance in repository-controlled CI run `34924284502`, on both head and prospective-merge jobs. See `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md`. This is a baseline observation, not a pass for later source or independent qualification; protocol-model tests alone do not qualify database credentials or revocation. [Remote JWKS and OIDC Discovery-backed JWT](docs/auth/HEPTABAO_REMOTE_JWT_KEYS.md) use host-enrolled verified HTTPS and fresh login-time keys, not browser OIDC code flow. [Raft administration](docs/operations/HEPTABAO_RAFT_ADMINISTRATION.md) changes native committed membership, observes persisted snapshots and applies bounded Autopilot stabilization/cleanup. These additions require **Service schema 4**. The current read, mutation and rollback rules are consolidated in `docs/architecture/HEPTABAO_CURRENT_STATE_FORMAT.md`; earlier formats are not downgrade permissions. Full OpenBao compatibility and production authority remain false.

## Current online authentication increment

[Online Kubernetes / OIDC authentication](docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md) adds actual Service-owned
TokenReview and confidential authorization-code/S256 PKCE sessions, plus a native
loopback callback CLI. The separate remote-JWT profile above remains a bearer
verifier, not code flow. Current application writes use schema 5. The new profiles
retain root-controlled enrollment, live Identity, audit and durable/HA publication.
They do not implement complete auth/MFA/browser UI compatibility, scalable storage,
independent acceptance or production authority.

## Section-six execution increment

The current work inventory is `planning/HEPTABAO_SURFACE_WORK_V1.json`, checked by
`scripts/surface_work.py`. It retains every original surface/case binding and links
existing real executables; it is subordinate to the active V2.1 plan, not a second
plan or completion evidence. Technical contracts and open work are described in
`docs/plan/HEPTABAO_SECTION6_EXECUTION.md`. The current runtime increment adds
audited capacity observation, safe journal checkpoint maintenance and an explicit
Transit ciphertext re-encryption tool. It does not raise the aggregate state/ID
limits, import raw OpenBao snapshots, update application ciphertext references,
or advance Hepta's independently requalified consumer pin.


## Integrated remote continuation

`docs/plan/HEPTABAO_SECTION6_INTEGRATION_20260915.md` records the reconciled PR96
and local online-auth inputs, both capacity response contracts, unified durable
maintenance, retained Transit tooling, the actual Kubernetes API/etcd/RBAC gate
and exact direct-Python-version validation. Source presence and workflow wiring
are not execution receipts. The separate record-store source is not included.
