# R10 CI: restore the unsupported-owner fixtures

This is a source-only candidate against 49503322c7f446e5eb41e7744f1fdbd7f1192ecc. It changes four test functions and no product code, response policy, deadline or test denominator. No Rust formatting, compilation or execution has been performed for this candidate.

## Why the four failures are stale fixture assumptions

The current product explicitly admits the root SSH owner in both EngineState::supports_native_v6_root_storage and the actual native_plain_namespace_engine_profile. Service selects the typed native SSH registry and request owner; engine_native_ssh.rs creates a checked registry Enable owner for type=ssh. The existing normal File-profile SSH tests use public activation, real signatures, cold reopen and archive restore. A successful SSH mount or activation therefore no longer represents an unsupported owner crossing a guard.

The four CI failures alone are not a reason to loosen the guard. All original 501, 409 and ColdSeedError::GraphRejected expectations remain in the candidate.

| Original test | Replacement fixture | Retained protection |
|---|---|---|
| native_pki_formal_selectors_retain_acme_external_and_foreign_owner_fences | Foreign mount type Kubernetes | 501; graph equality; PKI ACL and real remount-owner refusal; cold PKI issuance |
| native_transit_acl_source_create_capability_cas_and_refusal_scope | Foreign mount type Kubernetes | 501; create/update ACL, sudo, exact CAS refusal and native owner/graph equality |
| configured_native_activation_rejects_unsupported_live_engine_without_retiring_v5 | Local private PKI CA with enabled, nondefault ACME configuration | 409; no native root; same retained configuration; additionally exact zeroizing legacy engine-owner bytes before/after |
| cold_dr_unsupported_engine_archive_refused_without_destination_or_source_loss | The same real private PKI CA/ACME profile in an actual authenticated experimental native archive | Both route refusals remain 501; real ColdSeedError::GraphRejected; no destination; all State/graph/private-owner bytes, generation, identity, archive/seal/Shamir bytes and source proofs retained |

## Why these remain real unsupported owners

Kubernetes has no native registry/request owner in the selected profile. A new non-KV2 mount falling through native mount management is rejected with 501 by engine_native_kv2_mount.rs:125–126. Both native profile eligibility functions reject its Backend variant.

The stateful fixture does not use an empty mount. It generates a real local elliptic-curve PKI private CA, sets the local cluster URL and enables ACME through the existing local configuration APIs. Pki::native_local_profile explicitly requires the complete ACME configuration to be default. Enabled ACME violates that actual product condition; the configured normal storage guard and cold complete-graph validation retain their unsupported-owner refusal. The normal PKI owner does not select this nondefault mount or its config/acme route.

Only local configuration and key-generation APIs are used. No ACME account, order, challenge, DNS resolution, provider request or external key is introduced. The former SSH CA's secret-state retention coverage is maintained by a real private PKI CA in the full serialized/authenticated owner. The cold test's original full native graph visitor and State clone/projection are byte-identical, as are its recovery rejection and all post-recovery source-retention comparisons. No live NativeReadView is flattened by the new legacy-only comparison: native_root absence is asserted before that serialization.

## Required execution gate

After source review, run Rust formatting and the four original named tests under the unchanged normal feature/profile and original per-request budgets. Retain the original CI failure. If the replacement fails, diagnose its actual result; do not turn its negative status into success or substitute a simpler empty owner. Existing normal SSH tests retain their independent positive scope; this test-only patch adds no product capability claim.
