# Actual continuation checkpoint — 2026-11-06

The current full-replacement gate is **not qualified**. No production traffic was switched and no legacy Bao service, binary, data or backup was deleted.

## JWT fixture repair and actual Mac diagnosis

Only `native_jwt_role_operations_keep_the_existing_legacy_acl_contract` changes in the Rust test file. The role retains `default` and `native-jwt`; the old fixture's `no_default_policy=true` removes default, including an explicitly requested default. A local setup within this one test grants the full retained policy set without making the actor root. Independent missing-default, missing-native-policy and missing-sudo denials remain 403 with unchanged Auth/Identity state and no credential publication. Positive update/delete still require 204. All 15 test names and all file bytes outside the changed function are unchanged.

The [source and live proof](../native-jwt-default-policy-20261106-r1/source-and-live-proof.public.json) binds the final test blob and the actual Mac TLS/native_v6_file diagnosis. Its original normal-release 09c14 binary passed 49/49 API checks; pinned Rust formatter and check succeeded on a new copy. The runtime terminal is succeeded/exit 0, complete and durable, with no timeout. All seven original child handles were retired, no direct children remained, and input identities/hashes were unchanged.

This diagnoses the existing binary and validates formatting. The changed Rust test and complete successor 107-case selection still require a new build and execution. Original failed campaigns remain failed: Mac 09c14 executed 103 cases, with 102 passed, one JWT failure, and four TLS cases unexecuted. ROG r8 also ended at the native-jwt15 group; its original result is retained on ROG and is being reconciled separately.

## X230 admission checks

The [X230 result](../x230-current-candidate-20261106-r1/admission-tests.result.public.json) records a new reconstruction with 24/24 actual admission-only tests, succeeded/exit 0 and complete durable output. It rejects the exact real failed Mac receipt both in its parser and before fixture launch. Positive-parser receipts are explicitly fictional unit fixtures. No candidate or oracle binary was launched, and neither full34 nor comparison69 was executed by these admission tests. The prior disconnected workspace's 22-test observation is not transferred to this new source version.

## Reconciliation of the old Mac QA wrapper

[Read-only evidence](mac-r2-recovery/readonly-result.public.json) binds the original bootstrap-only ledger, fixed QA plist and full arguments to the current libproc birth identity. The old business operation did not record an admitted wrapper/exec identity, and its outcome remains failed/unknown.

The separately reviewed cleanup-only r1 job `1a1b11278be-fc05-7587` ended with known exit 1 at `typed_process_metadata`, before journal creation and before any TERM, KILL or bootout. The exact original terminal/output and source are retained here. This is a new failed cleanup attempt, not an old business replay or a successful cleanup. A newly observed process-state literal is being diagnosed before any further recovery action.

## Remaining execution gates

- Complete successor source/build/artifact binding and all 107 original cases on Mac and ROG.
- Current-candidate X230 full34 plus the bounded official OpenBao 2.7.1 comparison, followed by the separately required fresh-directory DR and physical HA evidence.
- Current independent trusted AuthBus credentials and actual AppRole/TLS/KV/policy/renewal/revocation, then each registered client’s credential I/O, restart and rollback.
- Only after those client and registered backup/restore paths are migrated may legacy cleanup be released. The accepted finite inventory scope is unchanged.
