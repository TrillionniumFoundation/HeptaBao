# NEW Phase B admission diagnosis: bounded normal observation candidate

This is a new source-only candidate. It does not change a source branch, installed service, binary, deadline, repair rule, or the sealed Phase B run. Root review, actual formatting, build identity, and a separately reviewed fresh fixture are still required before any runtime.

## Evidence and phase boundary

The original run is `1a1a8177aec-fc05-2da5`, product commit `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`. B01 was the sole official CLI command. It exited 2 and produced no archive. Its outcome remains unknown in the original result; no later command or restore ran.

Six exact original files were inspected without a directory search or process start: node1/2/3 `native-start0.stderr.private.log` and `native-start0.stdout.private.log`. Their total size was 5,263 bytes. All three stderr chunks were bound to file_info version, complete EOF, size, chunk SHA256 and whole SHA256. All stdout files were exactly empty. The public projection contains only 17 validated structures from three fixed prefixes. Seven other lines remain private. Two earlier incorrect basename metadata requests returned ENOENT and remain in the packet; neither establishes absence of the actual logs.

Node1's unique non-health failure records:
- `sync_inner_error`, status503, loaded=true, recovery=false, record_root=false.
- ordinary request, forwarded=false, elapsed16,501us.
- original entry remaining14,996,924,359ns and exit remaining14,980,422,592ns.
- zero timing phases and no normal `HBHA-NATIVE-SYNC-FAIL` line.

The official CLI stderr's securely classified static error is `native HA committed root is unavailable`. No raw stderr or credentials are published.

The admission boundary is established by the actual normal source: `begin_native_snapshot_before` sets the snapshot flag/clock and calls `begin_request_before`. That function emits this ordinary failure timing only for `RequestExecution::Complete(response)`; External passes no status. `http_snapshot::execute` returns Complete before `execute_snapshot_transfer` and final writer reacquisition. Thus the observed B01 failure preceded external archive export/finalization. This does not prove which pre-sync branch failed or establish HTTP ALPN/framing.

## Snapshot flag and permit contract

The exact `NativeFreshIngressBinding::check` compares fingerprint, clock, start, original deadline/current scope, nonce, data directory, once-issued binding, original StateIdentity/generation, actual native owner, durable ownership/recovery and absence of pending authorities. It does **not** inspect `native_snapshot_transport`.

`NativeIngressSelectionPermit::capture/check` preserves that binding and the same LocalHaEnvironment. `check_initial_read` consumes initial_read_started exactly once; it compares non_readonly_entered, the exact original deadline, local root, and current request deadline. It also does **not** inspect the snapshot flag. The LocalHaEnvironment checks exact HA owner, seal/barrier/data identity, storage profile and recovery/audit conditions, without a snapshot transport flag veto.

There is consequently no demonstrated direct contradiction between pre-setting `native_snapshot_transport` and these permit checks. A failure in permit capture itself would return before the inner sync call; the captured generic committed-root error is from the later observed read result. No guard should be removed based on the current evidence.

## Unresolved inner branches and proposed observations

The ordinary committed reader creates NativeV6FailureObservation unconditionally at entry. A failed ordinary read would normally record a phase and error digest on drop. The fresh-ingress reader lacks that observer. The empty buckets and absent line strongly support the fresh-ingress branch but do not prove the particular returned error.

The candidate adds the existing observer only to `HaProcess::native_v6_committed_fresh_ingress_read`. It assigns these fixed phases:

| Phase | Original operation under observation |
| --- | --- |
| fresh_ingress_permission | check_initial_read and its original deadline check |
| fresh_ingress_runtime | enabled runtime, actual node, storage handle |
| fresh_ingress_storage_operation | existing begin_native_operation |
| fresh_ingress_read_index | actual native_v6_committed_root_read under the original deadline |
| fresh_ingress_enrollment | validation of the actual selected enrollment |
| fresh_ingress_same_root_closure | complete historical physical pass and actual successor read |
| fresh_ingress_original_repair | existing first exact-root repair after NeedsOriginalRepair |
| fresh_ingress_changed_root_recover | existing full catch-up when the first actual root differs |
| fresh_ingress_final_witness | existing final committed-read verification |

One fixed code `fresh_ingress_read_refused` hashes the original returned String with the already implemented digest path. It never prints the String. Successful None, Ready and Superseded results call the existing complete method and emit no failure line. Panics retain the existing fixed scope-not-completed behavior. The observer records bounded in-memory timing on the normal path; there is no claim of zero overhead.

The full source outside this one function is byte-identical. Within it, nine exact insertion/replacement operations reverse to the original function. Business call arguments, the order of checks and mutations, all ? propagation, all selected-root values, and all original deadlines are unchanged. The same permission.refuse_reselection occurs on every Err. This is an observation candidate, **not a fix of the underlying 503**.

## Superseded and repair branches remain intact

The current same-root closure:
1. verifies membership and original operation/read bounds;
2. performs a complete historical ciphertext DATA pass;
3. treats non-witness refusal, partial physical failure, and deadline failure as errors;
4. performs an actual new quorum selection;
5. permits Superseded only after application generation advanced and the old witness is actually refused;
6. keeps the exact original operation/read bounds, storage, original root and affine attempt.

NeedsOriginalRepair remains the first original repair, and marks permission non-readonly before entry. Changed-root recovery likewise refuses reselection before its original full catch-up. The patch neither catches these errors nor converts an error into Superseded, repair, retry or success. The current logs provide no branch result for these paths.

## Review and future validation boundary

1. Review the complete candidate and six-hunk diff against the actual R10 runtime blob. The newly published test-only parent6d3040 changes four test files only; this runtime source is identical to R10.
2. If accepted, run actual Rust formatting and normal compile/test under the same default features/toolchain/profile, with separate source/artifact identity. Do not turn on private diagnostic features.
3. Reuse the existing permit/selection/unknown negative tests and exact original deadlines. A source edit-inverse check is not a runtime test.
4. For runtime diagnosis, use a new independent synthetic cluster/root/credentials, a newly bound normal artifact and the original Phase B CLI save contract. The old B01 request, root, token, unknown result, and intent cannot be resumed or replayed.
5. Retain each300s action, CLI/HTTP15s, readiness45s, election60s, forwarding8s, inner ReadIndex bound, and existing cleanup budgets. Unknown or partial still stops all later CLI/mutation/cold work. No extra deadline or new repair attempt is granted by an observed error.
6. Keep the separate JSON dictionary-key input-fence observer defect separate from this product diagnostic. Fixing that final comparison cannot make old B01 successful.

Only a captured static phase and reason digest from a separately approved fresh run may justify the next product change. The attached reason catalog contains six exact public-source strings and hashes; none is asserted to be the old error. A digest absent from the catalog stays unidentified until its canonical source is traced.

## Durable evidence identities

Old logs and canonical callsite packet: tree `266023792a9e066915c32a88648746c34fb66a59`.
Original result: 270785B / SHA256 `cd2d1d89271b0342755935f366cf41b25ad49e1cd560a1ab7a1eb7b698e9d184`.
Candidate runtime: 61578B / SHA256 `cf0e9e69bf295591d3a904458500bfcf7b01acaa0987ae1da8761f76b9ee136d`.
Review diff: 3162B / SHA256 `b76f91a684305d452be25d6735b4ad2fc82ee33086dda33c890223a497e713a7`.

Full replacement, native CLI restore, and production qualification all remain false.
