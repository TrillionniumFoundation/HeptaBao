# Single-node service increment: execution status

Plan: `HEPTABAO-PLAN-2026-09-07-V2.1`, revision 2.1.2. This document reports implementation and observed local checks. Current authority remains in the canonical planning files; all qualification, compatibility, production, migration and release claims remain false.

## Implemented scope

The current `heptabao-server` binary is a real TLS service with durable AES-256-GCM encrypted state, persistent token/userpass/AppRole and pinned-key JWT authentication, custom auth mounts, default-deny ACL and namespace/mount-separated KV v1/v2, Transit and TOTP engines. It starts sealed, supports bounded Shamir threshold initialization/unseal and verified rekey, rotates an HMAC-chained audit with a signed retention checkpoint, and withholds sensitive responses after uncertain persistence or audit failure. Root maintenance supports compaction and the local HeptaBao encrypted-backup format. Optional HA configuration composes a real voter per process with mTLS peers and ReadIndex. These implementations remain candidates under review.

The workspace currently has 46 packages, with five in the server's runtime path-dependency closure. Use `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md` and `docs/modules/CURRENT_RUNTIME_MAP.md` for actual package/handler/test ownership; contracts elsewhere do not establish integrated features.

The durability repair replaces ambiguous tuple serialization, rejects legacy ambiguous state, uses process-scoped writer locks, validates snapshot/journal/ledger frontiers and conservatively classifies real post-entry I/O failures as unknown. Finite token use is a separate durable admission transaction, so a later denied or oversized request cannot restore an already admitted use.

## Historical observed local evidence (September 2026 initial increment)

| Check | Observed result | Scope |
|---|---|---|
| Real TLS process smoke, initial run | 23/23 passed | init/seal/unseal, KV, namespace isolation, finite use, SIGKILL/reopen, disk ciphertext and audit redaction |
| Durable/runtime tests | 27 passed before final memory-erasure review | includes real SIGKILL, partial append/EFBIG, snapshot/ledger I/O failures and stale snapshot rejection |
| Auth tests | 13 passed | real PBKDF2, token lifetime/use/cascade, AppRole, namespace/ACL, bounded cleanup and strict JSON |
| KV/Transit/TOTP tests | 20 passed | CAS/no-effect, batch semantics, namespace/AAD, AEAD tampering, RFC 4231 and RFC 6238 vectors |
| Service composition review | 7 passed | consumption persistence, failed transaction rollback, unknown persistence, audit tampering and withheld response |
| First independent OpenBao comparison | Found and corrected a real difference | official 2.6.2 Transit create/rotate returns HTTP 200 with metadata; previous candidate/test assumed 204 |

The initial differential run is intentionally recorded as a failure. The corrected differential run subsequently passed all 38 selected cases on both implementations with no mismatched observations. Its exact binary-bound receipt is `qa/openbao-acceptance/evidence/openbao-2.6.2-comparison-20260908.json`. The final process smoke passed 31 scenarios including TOTP replay rejection after SIGKILL and fail-closed handling of unsupported wrapping/MFA headers and secret-bearing query parameters. Its fixture uses a separate test CA and a CA:false server leaf. Real OpenBao → HeptaBao KV migration passed 18 checkpoints, including lost acknowledgment, repeated import and restart recovery; see `qa/openbao-acceptance/evidence/live-migration-20260908.json`. Unit counts may overlap the workspace total and must not be summed as independent scenarios.

## Historical repository verification

For the initial source described below, the Rust workspace passed 291 tests across 48 test binaries. Full workspace formatting, strict Clippy and Rust documentation builds passed. Final HTTP security changes additionally passed all four parser/socket tests and strict server Clippy. In a clean checkout of source commit `a8b3c1795a45486e75386fa2c3a8225c14293845`, all 11 Python gate groups passed: 286 tests (repository 26, security 78, module plan 7, external completion 7, platform 130, Oracle 20, acceptance harness 18). That historical repository validator confirmed 43 package/source/lock/guide/matrix entries; the current workspace has 46, and those old counts are not a current pass receipt. CI on the eventual remote head and its prospective main merge remains a separate gate.

## Historical independent Oracle provenance

The comparison uses the official OpenBao 2.6.2 Linux amd64 release, verified against its official checksums, running a separate ordinary `bao server` with TLS and file storage. It uses an independent cluster and synthetic mounts. Archive SHA-256: `8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa`; executable SHA-256: `8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00`. This is an independent implementation comparison run by the development team, not independent operator/security certification.

## Remaining acceptance gates

| Area | Remaining work |
|---|---|
| OpenBao API/auth | Full error precedence/envelopes and ACL dialect; full identity/OIDC/JWKS/PEM configuration, Kubernetes, LDAP, certificates, cloud auth and broader MFA. The bounded pinned-key JWT profile is implemented, not full OpenBao JWT compatibility |
| Engines | PKI, SSH, database/cloud credentials, full Transit options and dynamic lease revoke/renew workflows |
| HA | Independent destructive qualification, membership/enrollment, rolling upgrades and complete admin compatibility for the implemented per-process Raft/mTLS/ReadIndex path; unsupported admin operations remain explicit failures |
| Migration | Only explicit KV v2 history supported by the migration tool; deleted/destroyed/pruned histories, auth/identity/leases/Transit keys and full cutover remain blocked |
| Operations | Qualify implemented compaction/backup/restore, audit rotation and bounded rate limiting; complete upgrade/remote archival/rollback anchoring, operator reconciliation, KMS/HSM and destructive platform evidence |

No percentage of full OpenBao replacement is inferred from package count or these passing subsets. Current state is a runnable, bounded development candidate requiring further implementation and independent review.

## Current validation boundary

The current source inventory and per-module test anchors replace historical package/test counts for navigation. Run `python scripts/validate_repository_v2.py`, `python scripts/validate_current_documentation_semantics.py` and the current workspace gates. Their receipts must name the actual candidate commit/tree; historical September 8 receipts above retain their original limited scope. Source fixes and documentation do not close compatibility or production authority.
