# Forward delivery custody review for recovery r1

Reviewed source baseline: 5ea86e1e0499a4b21e3216a350c12e81f848f86e, with the three-file r1 overlay whose SHA-256 is db4ef001db69a421464eea74bc80239acb3dcb6a2a381e99278c3ee45a5b4f08. This review does not claim a compiled or passing candidate.

## Why the original follower owner cannot change during the remote exchange

`http.rs::execute_service_request` obtains the actual `Mutex<Service>` writer and calls `begin_request_before` inside that guard. `Service::handle_inner_control_group` synchronously calls `HaProcess::forward_request_completed`, then `stage_forward_delivery`. The outer request path subsequently performs its mandatory audit and `complete_forward_delivery`, then returns `RequestExecution::Complete`.

The follower's forwarded request does not return an external plan or release this writer during the network exchange. A separate seal/unseal request cannot acquire the same Service writer during that call. Direct Service entry points retain an exclusive `&mut Service` for the same synchronous call chain. The test pipeline likewise holds its real Service mutex throughout `handle`.

The receipt's authenticated network completion nonce is a different binding from the follower's `unseal_nonce`; it is not being treated as an original local Seal owner. A future change that releases the follower writer during forwarding must capture and retain an explicit original local owner before that release. The current synchronous implementation does not need such a new API.

## What permits the one nonce transition

Before and throughout native local installation, `LocalHaEnvironment::capture/check` binds the same HA Arc, data directory, SealMetadata, original local nonce and barrier digest, and rejects recovery/audit fences. `sync_native_v6_from_ha_checked` uses that guard through the actual selected graph, local conditional publication, final witness checks and physical root readback. Only after successful installation does `install_epoch_activation` publish the newly allocated activation nonce.

The r1 stage first completes that existing synchronization and obtains the actual current application witness. It then captures the delivery owner. It does not mutate a previously captured delivery owner, renew a deadline, forward a second request, admit another Actor, or consume another token use.

If the authenticated completed response belongs to an older graph, its full owner projection and completed-prefix checks still reject the newly installed graph. A higher local epoch alone never legitimizes that earlier response.

## What remains immutable after stage

Pre-audit and post-audit checks use the same captured delivery capsule. They synchronize under the same receipt deadline but never replace its nonce, barrier, HA owner, namespace binding or original Actor/clock. A later epoch installation or seal/unseal invalidates that capsule. `begin_at_mode` also rejects dispatch while `pending_forward_delivery` remains present, preventing an old pending capsule from being reused by a new request.

The existing `completed_forward_original_unseal_owner_vetoes_after_local_audit` test obtains a real completed receipt, captures the delivery owner, performs the real audit, rotates the local nonce, and requires HTTP 503 with no data and no second token use. `completed_forward_precise_follower_audits_without_second_floor_or_use` covers normal delivery without second admission or floor publication. The historical two-epoch test now directly observes the live stale follower's old epoch/nonce before its first real read and its new epoch/nonce afterward.

No additional product delta was justified by this review. Actual execution of the historical and two existing forwarding regressions remains required.
