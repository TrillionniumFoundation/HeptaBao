# NEW R10 snapshot streaming relay — minimal API and custody addendum

Source-only proposal; no product edits, host I/O, requests, tests or runtime qualification. This is a new design identity, not recovered A7/347db/16f9. Canonical source is [49503322c7f446e5eb41e7744f1fdbd7f1192ecc](https://github.com/TrillionniumFoundation/HeptaBao/tree/49503322c7f446e5eb41e7744f1fdbd7f1192ecc), tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. Paths and line numbers below refer to that exact tree. The earlier NEW R10 pending analysis remains unchanged in tree 578b3a99f0ca3649d0f44a4ace22bfaef225945d.

## Decision

Add a dedicated typed stream callback to the existing authenticated peer listener. Keep one actual TLS connection, original bounded capacity and deadline; leader Service performs the real application admission and native restore. Ready is admission evidence only; Final requires actual owner completion and audit. For upload, the same HaProcess allocates an affine operation identifier after real admission, leader records its negative custody before Ready, origin durably records that exact identifier before Proceed, and the original restore coordinator consumes it once. No Final means no deadline renewal, new upload, Begin/CAS replay or automatic cancellation.

Use the existing barrier-authenticated DurableService journal/ledger for the small negative-custody records, with a new typed internal resource and wrappers. Do not invent a parallel sidecar recovery engine. Existing Raft pending/restore lineage remains the sole truth about Begin/Stage/root publication. Existing recovery records cannot directly represent the pre-Ready stage; that gap and the required narrow projection change are explicit below.

## 1. Concrete seams: five implementation units

The following names are proposed, not existing compiled APIs.

| Unit | Exact current seam | Minimum addition |
|---|---|---|
| Peer stream | heptabao-ha-service/src/authenticated_peer_frame.rs:55–150; src/lib.rs:829–915 | A transport-owned NativeSnapshotPeerSession, private constructor, no Clone/Serde or raw-socket escape. Reuse actual pinned handshake, strict ALPN and ForwardDeadlineStream. First envelope/control frames stay bounded; stream uses at most 64 KiB chunks and the existing native archive cumulative limit. |
| Handler registration | server/src/http.rs:642–676; ha.rs:106, 1362–1375, 959–1137 | A separate register_native_snapshot_handler, one-time registry with Weak<Service>. Dispatch before into_legacy_parts loses actual leaf/ALPN context. Clone callback out of registry lock; hold one existing forward-class permit throughout; preserve consensus/ReadIndex/native-repair reservations. |
| Prepared peer | ha_native_v6_runtime.rs:449–570, 954–958, 1215–1248 | PreparedNativeSnapshotPeer minted only by the owning HaProcess from an actual verified committed selection. It binds process instance, selected leader, committed enrollment/current leaf, configured transport and original deadline. Clone transport machinery and release HA mutex before Service/network I/O. It grants no Actor/restore authority. |
| Service split | service_snapshot_transfer.rs:374–457, 715–719, 749–843; http_snapshot.rs:338–397 | Native relay admission, typed Pending and finish. Leader retains the complete original PendingExternalRequest; body/network outside writer; original native finalization/audit before Final. Origin uses separate routing/negative custody, not a second application-token admission. |
| Operation/custody | ha_native_v6_epoch_restore.rs:371–443; durable-service conditional journal pattern below | PreparedNativeRestoreAttempt plus typed begin/settle/status custody wrappers using the existing journal. Local restore wrapper retains its current operation allocation and behavior; relay-only entry consumes the prepared identifier into the same existing Begin/Stage/CAS implementation. |

The current ForwardHandler is Fn(ForwardRequest)->Response, and AuthenticatedPeerFrame's callback returns a whole Vec without a TLS handle. Neither can become a stream by placing archive bytes in JSON or reusing its return body. The session constructor must remain at actual mTLS ingress; arbitrary frame fields cannot reconstruct it.

## 2. Actual destination and current/next leaf pins

Actual destination is ParsedPeer.endpoint, created from HaPeerConfig.address and server_name (ha.rs:2754–2797). api_address is the public redirect origin. cluster_address is explicitly diagnostic only (2815–2819), not dial/pin/routing authority.

Native eligibility currently rejects every certificate_sha256_next overlap: ha.rs:173–183 and ha_native_v6_runtime.rs:489–496. validate_enrollment_binding:559–570 also requires committed enrollment.pins == configured_pins. Therefore this R10-derived lane uses the committed current leaf in one handshake. It must keep rejecting overlapping current/next configurations. Ordinary listener overlap support does not qualify native rotation; do not try a current certificate then reconnect with next, or retry a body after pin failure.

Outbound exchange_before_pinned_server already completes handshake before frame bytes, requires heptabao-raft/1, bounds the chain and compares the actual leaf to independently supplied membership custody. Reuse that handshake in a single-session callback; ordinary exchange_before lacks that exact leaf check and is not equivalent. Server ingress must likewise verify actual client leaf/node against actual committed enrollment, following native authenticated ingress:573–627, before Service application admission. Validate cluster/source/target/route/direction/session nonce; a peer's claimed certificate digest is data only.

The selected leader can be obtained inside the owner from NativeV6CommittedRootRead::leader_id. A changed leader or failed selection is refusal of this one exchange, not a routing retry. A first correct implementation may use the existing committed-read path; if it does not fit the original budget, preserve the observed failure rather than replacing it with unproven leader_status equivalence.

Each process retains its original local monotonic bound. Origin caps exchange by its original HTTP/forward deadline; receiver caps all phases from accepted_at. Remaining-duration metadata may shorten a receiver cap, never reset it. A Rust Instant is not portable between machines, and an origin timeout is not proof that a remote effect did not occur.

## 3. Exact operation ownership and Ready/Proceed

Current owner behavior: ha_native_v6_epoch_restore.rs:419–422 generates 32 random bytes after the validated candidate exists, then 435–443 invokes the actual Begin. An error after Begin can already have effects while root_attempted=false; after root CAS invocation, 651–667 retains root_attempted=true. NativeHaEpochRestoreError's reference is not a retry grant.

Proposed API boundaries:

- HaProcess::prepare_native_snapshot_restore_attempt takes the real admission's owned source/deadline/custody, verifies this same live process/leader/enrollment, and generates the private affine PreparedNativeRestoreAttempt. No public constructor, Clone, Serde, wire-to-attempt conversion or caller-supplied nonce. The serialized operation ID remains identification data only.
- The relay's SnapshotTransferPlan owns that attempt. Service stages a negative-custody record through the existing Durable owner, then captures the actual post-journal source using the original Actor and clock. A local journal generation change must be recaptured as an actual new source; never relabel the old generation.
- A private publish_native_v6_historical_restore_with_attempt consumes that exact type only after original archive validation. The existing public-to-Service local wrapper still allocates at its current late point and delegates to the common original body. Do not move Begin, fabricate a candidate or alter nonrelay semantics.
- The prepared identifier cannot authorize publication. The existing original_gate, actual committed source, archive/seal/typed graph validation, real Begin and target enrollment, fsync quorum, one root CAS and actual reread all remain required.

One upload exchange:

1. Origin creates one owned routing request and connects once; upload body is not yet read/spooled.
2. Leader performs real Service authentication once, including any finite-use debit and request audit, then allocates attempt and durably records negative custody. Only after the exact record is committed/current and the real source is captured may Ready be sent.
3. Ready binds original request/session, actual post-auth source and the actual prepared operation reference. It is neither restore completion nor next-epoch authority.
4. Origin verifies Ready and actual local source/materialization, records the exact operation/session in its existing durable journal and fsync-backed committed state, then captures retained original Auth/Actor custody under real gates. Only after this committed record may it send Proceed.
5. Leader consumes one bounded stream through the existing parser/spool outside the writer. Under the writer, the original restore path consumes the attempt and performs the actual Begin/Stage/root CAS.
6. Leader finishes original Pending: terminal clock, mandatory audit, original Auth checks and actual historical completion. Final binds the true result, stream length/digest, session/request, committed prefix/epoch and operation.
7. Origin verifies Final and actual required materialization under the original bound, checks the retained original Auth (not newly restored Auth), performs its terminal audit and settles its custody record. Only then can public success escape.

service_snapshot_v6_ha_restore.rs:317 retains current Auth; NativeHaHistoricalReceipt:45–55 and final checks:772–902 keep it separate from restored Auth. Ordinary forward delivery's current-Auth checks cannot be silently treated as this historical-original-Auth contract.

## 4. What the existing ledger covers, and what it cannot

| Existing component, exact source | Reusable evidence/mechanism | Not a substitute |
|---|---|---|
| raft-runtime/src/v6_epoch_restore.rs:117–201, 429–473, 537–605 | Real Begin command, target enrollment, pending intent and committed lineage; exact-operation recovery after Begin. | Command validation requires a nonzero different proposed_root_digest and next_epoch; Pending requires real begin_log. Before upload/candidate, there is no valid Begin to create. Do not use placeholder roots or reserve the next epoch early. |
| server/src/ha_native_v6_epoch_restore.rs:217–344 | Separately admitted exact-operation discovery/reconciliation; no Begin/Stage/root CAS replay. | It does not carry a pre-Ready request's audit/finite-use obligation or its peer session. |
| durable-service/src/native_ha_retirement_ledger.rs:303–398, 624–763 | Same barrier/journal, bounded typed record, original owner checks, conditional pending/complete publications, actual generation, authenticated read-only status, capacity reservation and unresolved handling. apply_batch_conditionally_with_io_gate is a concrete existing mechanism. | Retirement's physical owner, file-count capsule, conditions and restore veto are specialized. Do not call retire_native_ha_shared for a snapshot or reuse its resource/schema/permission. |
| durable-service/src/prepared_restore_projection.rs:57–69, 97–123 | Verified incoming state projection and a new derivation ledger. | It starts with incoming snapshot and replaces the replay ledger with only the new derivation. An arbitrary current local custody record is not automatically preserved. |
| durable-service/src/negative_current_publication.rs:14–42 | Actual no-write current-backend authentication under the held owner. | It writes no admission record, creates no quorum/Actor and cannot persist or settle Ready. |
| durable-service/src/restore_transaction.rs:142–201 | Authenticated physical old/new bundle recovery. | Its file-intent marker is authority for a fully prepared local replacement, not a pre-upload request log. |

Chosen reuse: add a dedicated typed internal snapshot-relay-custody resource and begin/terminal/status wrappers in DurableService, implemented with the existing conditional journal, request-binding ledger, barrier and capacity-reservation primitives. No separate sidecar/WAL or second restore coordinator.

The resource holds bounded negative data: schema/role, exact operation and session/request digests, admitted source/epoch, actual committed generation, predecessor/terminal digest and disposition. No token, credential, archive bytes or serialized Actor/Auth. Deserialization produces status data only. A fresh read/status cannot reconstruct PreparedNativeRestoreAttempt or renew its clock.

Leader pending must commit before Ready; origin pending before Proceed. Reserve pending and terminal capacity first, as the current two-publication ledger pattern does. Pending/partial journal failure means no next protocol stage. Unresolved capacity yields backpressure, not eviction or automatic replay.

There is one necessary storage addition beyond journal reuse: a narrowly typed current-custody preservation projection at the existing prepared-restore boundary. It must accept only the exact live current resource under its original owner and expected digest, exclude archived values, bind the actual replacement target, and keep every unresolved identifier as negative data across both leader replacement and origin historical catch-up. It must not reintroduce retired request ledger acknowledgements. Do not pass arbitrary resources through a widened public projection API.

This preservation is not already implemented or proved. First tests must show real generation/epoch changes and reopen keep the exact record, and that unrelated/malformed/archived records cannot be substituted. Until that passes, upload relay is disabled. From actual Begin onward, the existing Raft pending/lineage is the only truth about restore effect; the local resource just correlates this request and its negative delivery obligation. Settlement reads that exact truth and cannot issue another restore.

## 5. Pending drop, failure audit and Final

Current snapshot plan takes native_request_binding out of Service (transfer:715–719); it returns that exact binding only in finalization (828–843). It carries a negative outcome, not Actor/payload/publication authority. Keep that ownership. Do not leave it in idle Service, rebuild it from peer JSON or mark an unrelated request failed.

Add a bounded Service registry of exact pending settlement cells, with an affine guard owned by this Pending. Drop only marks its own cell cancelled/unsettled; no I/O, new lock/deadline or synthetic audit. Writer-owned settlement examines the exact cell and durable record. Known cancellation before possible restore is distinct from a possible remote commit. Token admission/use debit may still have happened even when no historical Begin was allowed.

If final writer lock or audit is unavailable after transfer, retain the exact negative obligation and withhold public payload/success. If the original deadline has expired, later recovery may produce a separately labeled observation, not an invented within-deadline response. A recovery fence is set by the actual writer from that precise unsettled owner; Drop alone must not poison unrelated Service admission.

Downloaded bytes also remain behind the existing leader native audit/file gate and the origin's final gate. A new domain-separated CompletedNativeSnapshotReceipt binds session/request/cluster/source/target/current membership, exact byte count/digest, real terminal status/audit/prefix and optional operation. Ready, a generic response body or successful TLS EOF does not construct it. No Final or malformed/partial Final means unknown when effects may have occurred; no retry or cold-restart success regression is inferred.

## 6. Native NoForward must be bound at actual ingress

http.rs:2055–2071 marks native downloads/uploads deferred; 2228–2235 only creates ordinary no_forward_target when !deferred_body. The raw header may be in logical_data, but current native standby admission:405–437 unconditionally selects its pre-auth 307. Thus ordinary NoForward tests do not qualify the new stream.

Add an HTTP-created native DefaultRelay/LocalRedirectOnly preference bound to the same checked NativeTarget and request attempt. Nonempty NoForward on a standby selects the existing audited trusted-origin 307 without Actor admission, use debit, peer contact, spool or body read. Direct leader handling stays the real local path. Empty/missing header uses the default. Do not let a forwarded JSON field mint this capsule or bypass leader authentication. Exact official native-header negative parity remains a test requirement, not a source-review pass.

## 7. Minimum implementation and validation order

1. **Custody first:** implement the private attempt owner and typed existing-journal wrappers/projection; leave network dispatch disabled. Test actual commit/unknown journal branches, exact source recapture, capacity, own-record cancellation, replacement/reopen and no capability reconstruction. Ordinary local restore still uses its original RNG/Begin path.
2. **One connection:** add pinned session/registry with actual mTLS tests for wrong current leaf/CA/SNI/ALPN/node/cluster/target, overlap refusal, strict bounds and same original deadlines. Keep ordinary peer/consensus callbacks unchanged. No application admission on failed transport custody.
3. **Leader then origin split:** bind actual Service Pending, Ready/Proceed and genuine completion gates. Test real finite-use debit exactly once; original Auth across restore; failure before Ready, partial body, after Begin/CAS, missing Final, final-lock/audit loss; all unknown paths preserve exact reference and never replay.
4. **Current product integration:** run current normal-profile direct snapshot and HA suites, then actual valid archive save/restore using official 2.7.1 CLI and independent API/all-node/cold readback only after a complete known business result. Native NoForward and invalid-token cases need their own exact differential. Do not expand any original 15 s/8 s or caller budget.

This is a bounded implementation plan, not an instruction to edit or run the active R10 candidate. Phase B NEW R3 is an unchanged observer of that candidate, queued after HA/strictwire. full_replacement remains false.
