# HTTP signed-zero preservation after the KV API projection

## Actual source and failure

This incremental candidate is based on commit `b24c6de7831a7389e39ac069277a9e85e858ef98`, tree `3356f0a94616e9e1804f497239f33546e16db577`. The original Mac additional HTTP run completed **1 of 3 tests passed**. Both real HTTPS tests failed at the raw signed-zero response check; their logs and the complete original summary are retained byte-for-byte under `actual-b24c6de-mac/`. The history test did not reach successful snapshot download or restore. In the refusal test, the preceding denied/invalid archive requests reached their assertions before the same signed-zero check failed. This candidate does not replace that failed run with a passing claim.

The seed sends the literal request bytes `{"options":{"cas":0},"data":{"n":-0}}` over verified loopback TLS. It does not construct the number with `json!`. The failing assertion reads the complete raw response body before `WireResponse::json()` is called. The defect is therefore not an input or output normalization performed by the test client.

## Narrow production change

The lossless token decoder already retains the negative sign internally. The ordinary KV read projection already produces the exact OpenBao API number `-0`. `logical_envelope_for_projection` then reconstructed all eight response fields with `json!`, which serializes and reparses the already projected arbitrary-precision Number. For `-0`, the maintained serde JSON integer parsing path produces positive zero. The final HTTP encoder already has the correct signed-zero handling, but no longer receives the sign.

This patch constructs that same closed eight-field envelope directly from its existing Values. It leaves field defaults, Auth field selection, type checks, route-specific projection, maximum encoded size, HTML escaping, final numeric formatting, source ownership, Actor/clock checks, response audit, snapshot admission, and namespace/seal restrictions in place. It does not change the general JSON parser, KV payload owners, snapshot/archive bytes, or response wrapping authority. User objects with private-looking serde keys remain objects.

## Stronger wire check and the existing storage canonical contract

The HTTPS test now borrows the actual nested payload as `RawValue` and requires its complete bytes to equal `{"n":-0}`. This is stronger than the previous substring prefix check, which could also accept `-0.0` on the public wire.

The existing lossless decoder has always represented input `-0` as the finite Number `-0.0`, preserving its sign. The storage witness fingerprints the typed canonical JSON, not the original source spelling and not the public binary64 API projection. Its exact expected representation here is therefore `{"n":-0.0}`: **10 bytes**, SHA-256 `a8a313cade05001e69f7ddb5db01e1e2d06fb8f6913ab492cc4506d4e65d465a`. The old new-HTTPS fixture expected the 8-byte input spelling at this later storage boundary. That expectation had not yet executed because the public response check failed first. The corrected expectation remains a fixed independent byte count and digest; it rejects both `{"n":0}` and `{"n":0.0}`. No payload is changed to make the test pass, no precision assertion is removed, and the request seed is byte-identical.

The long decimal, wide integer, historical deletion/destruction state, all version metadata, source-bound witness, actual snapshot download/upload, subsequent write, cold reopen, Auth/namespace/seal refusal paths, TLS verification, and complete-body parsing stay unchanged. The two HTTPS test names and their original 15-second per-request budget stay unchanged. No product deadline or test count is expanded.

## Execution still required

No Rust compiler or real HTTPS test was executed in the local review workspace. Local work verified source Git blobs, original failure bytes/hashes, the fixed canonical hash, unchanged request seed/test identities/deadlines, and the exact two-file patch.

Run the existing additional-3 adapter against the next actual producer libtest, source/manifest pins, and original target lock:

- `http::snapshot_accept_tests::native_snapshot_https_json_accept_download_restore_and_cold_keep_exact_history`
- `http::snapshot_accept_tests::native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals`
- `http::snapshot::tests::binary_route_only_supports_chunking_and_snapshot_accept_remains_binary`

Also run the one affected existing numeric helper explicitly, with `--exact --test-threads=1` and the original 1800-second command budget:

- `auth::wrapping::raw_reply::tests::raw110_go_float_boundaries_preserve_complete_numeric_projection`

The helper now supplies the already projected Number `-0` directly, proves that both the source and resulting envelope retain it, keeps a user private-looking map as an object, checks the final wire token, and verifies the response bound still rejects one byte below the encoded size. It creates no new test name. The original 55-test and 31-check cohorts are unchanged and remain independently identified; this patch alone is not evidence of complete OpenBao replacement.
