# HeptaBao continuation checkpoint — 2026-10-18

## Current decision

Full replacement of OpenBao 2.7.1 remains **unproven**. Production traffic has not been switched and old OpenBao services, binaries, data, backups and original failure receipts have not been deleted in this continuation.

The authorized host control tunnel became unavailable. Its authoritative read-only errors are `tunnel_client_not_connected` and later `tunnel_client_not_seen` (the client had not been seen for 300 seconds). This is an access/transport blocker, not a product test result. Do not replay the last Mac operation before reading its actual directory and process state.

## Exact source and changes saved

| Checkpoint | Commit | Meaning |
| --- | --- | --- |
| Original integrated candidate | `40b183000db486a677fadf9bd2fd34873a28c78e` | Complete Mac reconstruction verified every one of 2,762 Git blobs, modes and the full tree `50c821b2487000cf1d536cbd8d84dce0feedb544`. |
| Typed restoration and recovery reference + existing diagnostics | `a84c31b3bae4335958048b2e7f8a7db35fffe13d` | Correct the eight compile errors found on the exact original candidate; preserve the real operation after a committed CAS and a failed response audit. Integrate the existing `71063ee` private forwarding diagnostics without changing wire I/O order or budgets. |
| AuthBus R5 | `09a2e8c38d1565cc8f6a3f1ef48f3b050d6a204e` | Persist UNKNOWN before provider dispatch; prevent lease-expiry retry after a lost result or owner death. Actual-SDK registry remains a candidate. |
| Explicit pending restoration reconciliation | `3ab3ec01787791b80063586c01ea2897a6bde24e` | Cancel only one precisely identified pending operation under a newly authorized request; never automatically replay restoration. |

The new Rust changes are candidates pending real compilation and execution. A successful Git tree, patch application or source review is not a passing Rust test.

## Results actually obtained in this continuation

### Mac original candidate: compile failed

The native Mac run used Rust/Cargo 1.98.0, the existing offline dependency cache and the native HA feature. All 2,762 source blobs/modes were checked immediately before the run.

Compilation failed after 53.884 seconds with eight errors in `service_snapshot_v6_ha_restore.rs`:

- Two `RefMut<DurableService>` values needed explicit dereferencing at the existing borrowed-service boundary.
- The actual immutable authentication owner is `CowOwner<AuthState>`, not an owned `AuthState`.
- The publication frontier is `plugin::PublicationGeneration`, not a plain integer. It must retain its full type through the checkpoint, terminal proof and equality checks; only the public JSON field uses the actual Durable generation integer.

No historical Service tests executed in that failed run. Original log SHA256: `d72c776d098ad297e7182d50087d92b570c72d2490ea1cce20ad1bd429bbb5a7`.

The r2 patch addresses these exact diagnostics. Its successful compilation has not yet been observed.

### Mac direct-LAN TLS: transport observed, HTTP health not qualified

A fresh, uninitialized fixture ran the exact previous diagnostic binary, SHA256 `1546755960a23eb5e27cf5be474e63d63466a79ecb1f69e425cad95f78c9dcb4`, from the already permitted Mac application path. Global firewall settings and application rules were not changed.

- Main → Mac: verified TLS 1.3, exact API leaf pin, 0.062 seconds.
- Mac → its direct LAN listener: verified TLS 1.2, exact leaf digest, 0.057 seconds.
- The owned process was stopped and its exit was observed.

The small diagnostic client read only the first response fragment (`HTTP/1.1 `) and closed. Its raw `passed` flag cannot establish a valid HTTP status/body. The server's subsequent write diagnostic is also not sufficient to diagnose a product failure after that early client close. Preserve the raw receipt; the next probe must read a complete bounded HTTP response before declaring health readiness.

The earlier physical attempts remain separate: attempt 02 reached native activation and failed on a follower's exact forwarded read; attempt 03 failed earlier during Mac listener readiness. Neither establishes leader-kill, election, ReadIndex or full 34 MiB multi-host qualification.

### AuthBus R5: real local processes, fixture backend and owner

[AuthBus R5 evidence and scope](authbus-refresh-r5-20261018.md) records 13 scenarios / 52 assertions and 11 prior trusted-bootstrap regression checks.

The tests use actual HTTPS, actual provider HTTP requests, durable filesystem writes, independent Node processes and a real SIGKILL. They establish that:

- Unacknowledged intent CAS causes zero provider requests.
- Once the provider may have consumed the request, UNKNOWN survives owner death and lease expiry.
- Failed or falsely successful owner writes cannot clear the fence.
- Completion CAS response loss does not authorize another provider refresh.
- A newly verified credential publication can receive a higher epoch; the old digest remains fenced.

A separate [SDK storage extension](authbus-refresh-r5-sdk-20261018.md) replaces implicit owner upserts with a bootstrap-bound locked compare-and-write and explicit `syncExternalCli:false`. It includes a static source inspector and a real-SDK SQLite runner, but that runner has not executed on the disconnected host.

The control server and credential owner in these new tests are fixtures. These receipts do not prove the actual SDK OAuth hook, native HeptaBao-backed R5, production gateway bootstrap or every caller.

## Confirmed KV2 migration implementation gaps

The original lossless protobuf decoder was executed against a synthetic 2 MiB raw record and rejected it with `DecodeError('record bound')`. The current raw-record bound is 1 MiB, the export bundle bound is 16 MiB, and the HTTP helper has separate 2 MiB response / 16 MiB request-body bounds. More fundamentally, `EngineState::stage_openbao_kv2_import` returns 501 on an already activated `Kv2Native` backend and explicitly requires a dedicated graph import writer. Its older owner-based route also serializes the aggregate under `MAX_APPLICATION_STATE_BYTES`.

Thus the successful 34 MiB native-storage/component tests do not establish lossless OpenBao migration. Increasing Python caps alone would leave the native import implementation absent. The existing large-KV2 live test writes and restarts each server separately; it does not migrate that history between them.

## Pending-restore interface and tests

The explicit new operation is an empty-body POST or PUT on:

```text
/v1/sys/storage/raft/snapshot?cancel_pending_restore=native-v6-restore-<64 lowercase hex digits>
```

It requires the current root Actor, native HA activation, current Seal/source custody, actual ReadIndex and the original request deadline. It returns one of `cancelled`, `not_pending`, `committed` or `different_pending`; every result states `restore_performed:false` and `retry_allowed:false`. A separate new request is required for a new restoration.

This first cancellation API requires the client to retain the exact operation reference. A process or HTTP failure before that reference is returned can leave an undiscoverable pending operation; a narrowly authorized read-only discovery extension is being prepared and is not claimed as completed here.

The new Service regression uses a real staging I/O failure after Begin, then cold owner reconstruction and a new leader. The HTTP regression exercises actual parsing/body framing. These tests have been written and source-reviewed; their Rust execution is pending.

## First actions when the host connection is restored

1. Read the Mac r2 materialization receipt, test summary and owned process file listed in the [machine-readable checkpoint](../qa/openbao-acceptance/evidence/continuation-20261018/checkpoint.json). Inspect existing cargo/rustc processes before reusing the shared target cache. The last launch result is unknown.
2. If the r2 operation completed, retain its exact success or failure logs. Do not label it with a later commit. Materialize the latest saved tree separately and bind all source blobs/modes and the toolchain before the next run.
3. Execute the historical Service suite (including post-CAS audit failure and pending cancellation), archive regression, real HTTP query/framing tests and native diagnostic tests. Compile both Mac and Linux feature branches. Keep original HTTP 15-second and native 8-second budgets.
4. Build and freeze matching Mac/Linux server binaries, then use the existing direct-LAN 98-check harness on Mac–ROG–Pocket4 and Mac–ROG–X230. Verify complete TLS/HTTP readiness first. Preserve every once-only mutation intent and ambiguous result; do not relax deadlines or retry a write to make a check pass.
5. Inspect the actual SDK root, wire the R5 shared OAuth path to the real locked SQLite owner with external CLI synchronization disabled for fixtures, and validate a fresh native R5 control document. Old R4 receipts/documents are not new R5 qualification.
6. Prove the remaining lossless OpenBao 2.7.1 KV2 migration, Control Groups and HA quota behavior. Complete per-host real-credential read/write, restart and rollback before traffic cutover.
7. Reconcile every client and backup path before old-service/binary/intermediate cleanup. Preserve unrelated workloads, including heptatrader on Pocket4.

## Limits of the supplemental CI lane

A targeted GitHub Actions lane can provide an independent explicit-feature build/test result on its own runner. Existing default qualification CI does not compile this experimental native HA code. Neither a hosted runner's success nor local loopback component tests replace the requested external-disk Mac, X230 and physical LAN evidence.
