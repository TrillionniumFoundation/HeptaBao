# Snapshot repair cold ReadIndex setup — R1

## Status

This is a narrow test-preparation repair against exact HeptaBao commit `9770bdd4ca77aa832ec8083a054760637e92cfa1`, tree `f32f1acf9a794844719b6df225df3d23f2389e02`. It has not been compiled or executed locally. The original Mac CI and X230 failures remain failures. Only an actual subsequent run that completes the fresh target-readiness gate and the unique real cold unseal can establish that this change resolves the observed preparation race.

The production ReadIndex, application witness, ciphertext recovery, Service unseal, snapshot repair, persistence, authorization and deadline paths remain unchanged. The runtime source gains only one `#[cfg(test)]` data observation method. The snapshot test changes its preparation sequence and strengthens its assertions. No original test function is added, removed or renamed: the repair file remains four cases, the snapshot group seven, and the original runner 55.

## Two actual failures, same stage

| Actual environment | Preserved result | Concrete rejection |
| --- | --- | --- |
| Mac CI on exact 9770 | 54/55; snapshot group 6/7 | Cold `sys/unseal` returns 503 after the ReadIndex reports quorum or local-applied witness unavailable. |
| X230 running the exact 9770 Linux capsule | 54/55; snapshot group 6/7 | The same cold `sys/unseal` returns 503 after the ReadIndex reports leadership changed. |

The failed case in both is:

`service::native_v6_ha_pipeline_tests::snapshot_repair_tests::native_ha_snapshot_repair_all_donors_missing_preserves_four_conditions_and_cold_reopens`

Its complete original snapshot logs, the Mac verdict and the X230 execution summary are included as raw byte-preserving evidence. Mac log SHA-256: `7d0138dd52013bd914aa5c7fe2896c878b6e5d8df971d38d7e1c86dde6f0e833`. X230 log SHA-256: `2f3f90d51457c8ea6c60ade3d8714001c31b6fd1e353bf41b1b000128a88aa87`. X230 summary SHA-256: `67d2d42b445831c0394cddbcc30e639c4f3582c9c641e5637c6021e9708d8e20`.

The original target sequence is `stop old leader -> ready_leader on the surviving processes -> start old leader -> immediately unseal old leader`. The first readiness observation excludes the stopped old process. It proves the survivor leader/quorum is ready; it cannot prove that a process subsequently reopened from its old Raft files has caught up with the current term and obtained its own applied ReadIndex witness. Both actual errors occur at this unguarded boundary, before a successful cold Service install. The existing refusal protects against accepting a stale or unproved root.

This is the identified test preparation ordering defect. It is not evidence that all future cold failures are timing errors. A failure to obtain the new exact witness within the original budget remains a failure needing further product or runtime investigation; this change does not convert it to a pass or increase its time allowance.

## Why the usual native read is insufficient for a pure preparation check

Exact `ha_native_v6_runtime.rs` blob `b47635bfdc97166d42a2c851742c80d6b0c5e6a5` shows that `native_v6_committed_read` does more than observe Raft: after selecting a committed root it invokes `recover_native_v6_committed_closure`, which may pull missing ciphertext from pinned peers and install immutable local ciphertext. It is an appropriate production recovery path, but calling it as a supposedly nonmaterializing preparation gate could pre-repair the condition that the following cold unseal should exercise.

The new fixture-only method directly calls `ProcessRaftNode::native_v6_committed_root_read` and `verify_native_v6_committed_root_read`, validates the committed enrollment against the configured cluster/pins, checks the original absolute deadline, and returns only `(epoch, cloned PublishedRoot data)`. It never accesses the native ciphertext storage, invokes closure recovery, or constructs the Service's `CommittedNativeV6Read` handle. It returns no Actor, install plan, publication receipt or completed-response authority.

The exact lower-level source, `crates/heptabao-raft-runtime/src/process/v6_committed_root_read.rs`, blob `1d2db03a43c20cf9cb6ef5e29afc21874ed6d04f`, binds the selected root and enrollment to one actual quorum read and local applied store generation. Its verifier retains the same store, generation, leader, term and original capped ReadIndex deadline. Ciphertext availability and Service authorization remain separate obligations. That source is unchanged.

## New sequence under the existing budget

After the original process stop returns, the test captures the existing eight-second failover endpoint. The survivor `ready_leader` observation, cold process restart, and new target ReadIndex readiness all consume this same endpoint. A late survivor result, late target read, or late final sealed-Service observation is rejected. There is no second eight-second readiness window. The interval between unsuccessful read-only observations is at most 20 ms and is bounded by the remaining setup time.

The newly reopened process must provide a freshly verified root with the original epoch, original migration-source digest, publication generation, root digest and publication log index. The test also proves that this preparation has left the newly opened Service sealed, without State, native root or HA activation. Then the preparation scope ends and the test sends exactly one real unseal with its original 15-second request deadline. All original post-unseal selection and versioned-history assertions remain.

No unseal, archive repair, CAS, native activation or other mutation is retried by the new loop. No repaired file is copied into place by the test. A rejected application witness cannot authorize the subsequent unseal.

## Meaningful additional assertion within the same case

The existing all-donors-missing case also invokes the new Raft-only observer before the warm archive repair, while every selected shared ciphertext is actually absent on all three voters. It does so inside the already existing anonymous-admission 15-second scope. It checks the exact epoch/source/publication tuple and then executes the original `assert_missing` across all voters.

This makes the new observer's lack of materialization observable in a real Raft test. Accidentally replacing it with the normal native read would try to fetch or fail to recover absent ciphertext. The test still requires the later actual authorized archive repair to restore the exact shared bytes, while preserving the original committed selection and local durable generation/epoch/root/cursor anchor. Its final cold unseal still must reopen and authenticate the graph under the original local barrier.

## Source checks and execution handoff

All six cached source files were recomputed as Git blobs and matched the exact 9770 manifest. Removing only the new `#[cfg(test)]` method from the changed runtime file reproduces its original bytes. Every original assertion line and all four original test names remain in the repair file. The target case still has exactly one process stop, one restart and one unseal. The original pipeline helper and production sources are unchanged.

These are static checks, not Rust compilation or execution. Run the original snapshot selector `native_ha_snapshot_` with expected count seven inside the unchanged 55-case runner. A focused first run may use the exact failed function above with `--exact`, expected count one, and the same feature set `experimental-native-v6-ha,private-ha-forward-diagnostic`. Preserve the resulting source identity, full stdout/stderr and terminal result. The original failure files must remain unchanged after any successful rerun.

The earlier historical-restore readiness helper still uses the materializing native read; this patch does not alter that separate file or relabel its evidence. This repair does not by itself prove physical power-loss tolerance, LAN failover, full OpenBao compatibility, per-host cutover or eligibility to delete old OpenBao assets.
