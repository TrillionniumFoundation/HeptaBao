# Cold normal timing: minimal Rust validation input

Status: source only. No Rust command has executed.

The reviewed production patch remains immutable in tree fa8372f2c54e416b30daa9ec5130cfd6a196e90b. This package adds a cfg(test) module declaration and two small tests of the actual generic helper. The code has no Clone/Copy implementation for its owned marker, so both success and error identity can be checked without replacement or cloning. Nested source/inner Results are checked independently.

The third selection is the entire unchanged native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file test from exact3cb (also exact495). It calls the production loader after an actual owned ciphertext removal and validates repair, unchanged root/journal generation, rejection of changed markers, and refusal to overwrite corrupt bytes. Its original per-operation request scope is 15 seconds. No copied materialize-match simulation is introduced.

Original normal44 and additional7 inventories, runtime groups and budgets remain intact. The proposed incremental group will contain these three cases and Compat's six H2 cases, under a separate shared 600-second cap after the original 51 pass. Each exact listing retains at most 30 seconds and is clamped to that group's remaining budget. The final request remains unavailable until root freezes the combined source and reviews the exact carrier.

The prior executed runner uses normal default features, the pinned Rust 1.98.0 toolchain path, offline/locked Cargo, release1800/libtest3600, original six groups600 each and additional7 shared600. Its original target ownership and cleanup are to be preserved. This plan does not claim a SHA for rustfmt/cargo/rustc when none has been provided; root is recovering the original formatter tool proof.

## Test-only return correction

The first new-test draft is retained in the previous tree. This successor only changes the two new test functions to return TestResult, propagates capture failures with ?, and uses explicit fixed map_err / err().ok_or for the deliberately owned markers. Pointer identity, call counts, exact order and deadline assertions are unchanged. No lint suppression is introduced. Production read source and the entire existing real recovery test remain byte-identical to the prior package. Rustfmt and Rust compilation have still not run.
