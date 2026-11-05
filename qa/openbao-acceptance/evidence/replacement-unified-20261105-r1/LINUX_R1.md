# ROG / Linux R1: same candidate, full independent denominator

This is a failed qualification record. It adds independent Linux evidence to the frozen [Mac R1 record](README.md); neither result authorizes migration or cleanup.

## Source and build

- Candidate commit: `9208e0765f566f3bd7908e6567d2e39008156b9b`.
- Tree: `3a353adca3300eb46dbe8622c36eaa1f6d3fa7ce`.
- Producer: identity-verified physical ROG, native x86_64-unknown-linux-gnu, normal default server features, Rust 1.98.0.
- Normal server SHA256: `0b0fdb70734ffc1f0a4af94b61c72533e3531f94e2d77a90b3b4b394556422f8`.
- Normal native-build receipt SHA256: `e913792f5cea1105b3cff442a2e92e77e167cfb0a54981e12ca2035a38fbff02`.
- Server libtest SHA256: `2ace358d0edcb4182e3c84f1ce1f094c689e679ff95b91924fd3c283660dea32`.
- HA libtest SHA256: `bc928e5c2072bbaed1d17bdd5aa4036f2b2ae084ada028a8c05f62c31b795fb6`.
- Libtest build receipt SHA256: `40c6aa1d318184b548fb03146fee23a1f42a2579452360480552cd9e8c5bd26b`.

The retained binaries were produced by actual successful Cargo invocations. The server and HA libtests consumed 1271.118 seconds of the original shared 1800-second build budget. Compilation resource observations are not workload performance measurements.

## Result: 174 / 176

| Suite | Passed | Required | Terminal |
|---|---:|---:|---|
| Server | 165 | 167 | failed / exit 1 |
| Original sixty, included above | 59 | 60 | redirect failure retained |
| HA service | 9 | 9 | succeeded / exit 0 |
| Total | **174** | **176** | **failed** |

All 176 required tests were present in the real inventories and attempted once. No missing tests, retries or deadline changes. Source and retained binaries remained unchanged. All owned direct children were reaped and their groups observed empty.

The two failures were:

1. `http::snapshot::redirect_tests::native_http_redirect_has_exact_safe_location_and_no_upload_read_or_response_body`: exit 101, 0.045042 s; expected safe bodyless 307, but native synchronization logged 503 for the legacy HA fixture.
2. `service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor`: exit 101, 3.733237 s; public pending-restore reconciliation returned a standard JSON envelope without the required top-level `restore_performed=false` and `retry_allowed=false` markers. The first missing-marker assertion failed. The previous actual 204 restore, replay epoch, retained version 1 and expected absence of later version 2 had already passed. The logged version-2 404 was expected by this historical-restore test, not evidence of unexpected data loss.

The five tests that encountered a formal TLS deadline on Mac had these Linux outcomes:

| Test suffix | Linux R1 result | Seconds |
|---|---|---:|
| formal_native_standby_snapshot_read_restore_validation_and_no_forward_use_real_owners | passed | 1.518403 |
| formal_native_standby_snapshot_finite_tokens_redirect_without_consumption | passed | 1.981698 |
| formal_native_standby_ttl_snapshot_commits_real_leader_floor_and_survives_cold_restart | passed | 1.431471 |
| formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor | failed: missing reconciliation marker | 3.733237 |
| formal_native_http_consistency_forward_restricts_local_snapshot_and_no_forward_kv | passed | 1.879483 |

These component-test durations are diagnostic observations, not a Mac-versus-Linux service performance benchmark.

## Complete evidence

- [Linux aggregate](linux-regression-result.public.json): SHA256 `6804101a1d42b186f1a082e2f9f7d12a58b1ca3dddd0019f74926d0e979d2c5e`.
- [Independent executor observations](linux-runtime-terminals.public.json).
- [Complete Linux evidence archive](r1-linux-regression-evidence.tar.gz): 319355 bytes, SHA256 `16d0ebff9f80a641b3711b0abb7b570fe85f33cfdeb087a356f80fa4c8ba049b`.

The archive contains 734 original synthetic-test logs, public receipts, manifests and controller files plus `MANIFEST.public.json`. Manifest SHA256: `1b9e0636a9174a9bc019b51aa2e8a28e45eb3051deb248cf5faf560829a8dc61`. Each member was independently read back and hashed. It contains no production credential-store or production backup payload.

Authoritative executor jobs:

- Build: `rog / 1a1aa2cb2b5-fc05-3eae`, succeeded / exit 0.
- Server: `rog / 1a1aa427890-fc05-3ffb`, failed / exit 1.
- HA: `rog / 1a1aa4640c1-fc05-4042`, succeeded / exit 0.

All three published confirmed terminal state, complete durable output, no log truncation and no outer timeout. The root operator independently reread these states.

## Gates remain closed

`full34_allowed=false`, `ha_live_allowed=false`, `full_replacement_qualified=false`, `production_changed=false`, `old_assets_deleted=false`.

This record preserves the failure without replacing it with later diagnostic results. New candidate fixes require new source/binary identities and a complete new regression run, followed by the separately required formal KV2, physical-host HA, AuthBus, real-client and backup/rollback gates.
