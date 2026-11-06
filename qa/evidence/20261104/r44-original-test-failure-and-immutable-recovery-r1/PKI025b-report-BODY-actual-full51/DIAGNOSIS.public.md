# Original 025b BUILD report — limited diagnosis

The original unique BUILD exited1. Its full49,775-byte report was reconstructed from the one completed binary operation and five original immutable pages, externally whole archived before parsing, and matched the original terminal SHA and independent INFO version/full9.

Normal release, ordinary no-default check, file-profile libtest build and default-profile libtest build all returned exit0 without timeouts. The three post-release compile commands shared2,161.133432406001 seconds within their original3,600-second cap. This is a genuine compilation advance over the previous33b failed release attempt; it is not a full149/166 test pass.

The first file-profile family started. Its first test process, native_jwt_local_service_token_identity_renewal_and_cold_reopen, exited0. The second, native_jwt_rejects_remote_batch_and_bad_signature_without_candidate_delta, exited101 after0.07728586898883805s. Both exact listings exited0. The runner then stopped with AssertionError and an empty failure string. Only2 test processes are recorded; later tests/families are unexecuted in this attempt. The specific failed Rust assertion still requires the original second-test logs.

The report contains8 direct-child cleanup records, all reaped with empty remaining groups, matching the8 normal-release/compile/list/test commands. Retained evidence before and after is byte-equivalent in the parsed lossless report and marked unchanged. The final source_unchanged, binaries_unchanged and release_artifacts_unchanged fields are absent because the successful tail was not reached; they are not filled by inference. The launcher lock remains an admission probe, not an observed lifetimeCargo lock. No target reuse or rerun is authorized here.

87 pure checks reconstruct this body chain and these limited report statements. No new Native or product execution occurs in the verifier. Original31-call terminal packet8ab6851525ce0843e95db8f5a19ea4582b084ce8 and INFO23 packet26581e676cae80a0433de0d793c27bcb6d724c58 remain separate immutable predecessors.
