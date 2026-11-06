# Native snapshot standby forwarding: implementation contract

Status: SOURCE-only proposal against 4e808d0ecb1bcded22870a7ec960dfb2491cf6ec / eba5e650bd080b8ad41ea52a2bc68867f541d255. No product source has been edited in this packet, no Rust test or build has run, and no Runtime request is included. CONTRACT.public.json is the normative proposed boundary; SOURCE-ANCHORS.public.json and references/ contain exact existing sources.

## Why the native standby path needs a change

The one original official OpenBao 2.7.1 CLI run is preserved in tree 871aa23bfee256e91247fbb7e6d42c4cb82d181d. Its complete report is 0b2edd60185b80817c3c7f1378b914ae914ab21e, 848,065 bytes, SHA256 d5c691d23b513a2a63916792bbe21178e2b34799e6adbd20ddf88cdf6147bc48. The actual case facts below do not grant a successor any qualification.

| Case | Original result | Server evidence | Required interpretation |
| --- | --- | --- | --- |
| B01 leader save A | CLI 0, valid 39,348-byte archive | Leader 200 | Actual leader save evidence |
| B02 leader restore A | CLI 0, exact baseline on all three nodes and after cold restart | Leader 200 | Actual leader restore evidence |
| B03 leader save B | CLI 0, valid 41,744-byte archive | Leader 200 | Independent valid input for B05 |
| B04 default standby save | CLI 2 / incomplete_snapshot, no archive | Standby 307 and leader 200 in the sole CLI window | Save failed despite the leader's audit result |
| B05 default standby restore B | CLI 0, baseline not restored; exact mutated state retained on all three nodes and after cold restart | Standby 307 and leader 400 | False CLI success; known rejection, no restore qualification |

No raw second upload, negotiated CLI ALPN, raw client Location/header, private CLI stderr body, or internal cause of the 400 was observed. Audit association is the recorded single owned CLI window, not a fabricated request ID or independently verified audit MAC.

The frozen official v2.7.1 API source provides a precise compatible mechanism: httpRequestWithContext issues the second redirect request but continues returning the first response; the restore path supplies a raw body and ResetJSONBody does not rewind that body when BodyBytes is absent. This is source evidence. It does not measure the second request's actual bytes or uniquely identify the internal 400 branch. References: official/api/client.go 1707–1765, api/request.go 59–89, api/sys_raft.go 169–265.

The product's native snapshot admission deliberately emits its configured-origin 307 before authentication, finite-use persistence or body staging. Merely changing the CLI flags or pointing the controller at the leader would avoid the required default standby behavior. The proposed product change instead serves that original request through a single authenticated peer transfer.

## Concrete integration shape

Add a typed affine Forward variant beside the existing Execute and Redirect variants. It is selected only for the existing empty-query snapshot save/restore forms on an actual native HA standby. Direct leader execution continues through the current native snapshot plan. The original-ingress-bound no-forward preference continues to select trusted 307, including nonempty values "false" and "0". The repair, pending-restore inspection/cancellation, lossless-export and native-large paths retain their current explicit handling.

The forwarding plan captures the original local owner, configured HA instance, chosen enrolled leader, original request/deadline and its private transfer custody. It cannot be reconstructed from an archive, response JSON, advertised API URL, client Host or SDK Location. A new receiver provenance type makes a forwarded request one hop only: the peer target must itself be leader, otherwise it returns a terminal result without routing again.

Use the existing cluster peer endpoint, CA, server name and mTLS identity, with explicit selected-server leaf verification before forwarding token/certificate metadata or data. The receiving end identifies the actual TLS client leaf through the enrolled-peer map and compares it with the prelude's source, target and cluster. Strict Raft ALPN is mandatory for the new profile. Preserve the existing accepted pin-rotation policy; do not infer identity from the API origin. An unsupported profile or leader change cannot trigger a legacy fallback, second connection or second upload.

The existing authenticated frame API accepts a complete Vec and returns another Vec. Therefore the first implementation boundary must be a separate authenticated stream branch, while retaining the old frame branch's exact limits and behavior. A bounded stream decoder alone is data integrity machinery; it cannot mint an authenticated peer, Actor, storage or completion capability.

### One upload

1. Send bounded canonical metadata over the verified connection. The leader admits the original end-user token, namespace and policy exactly once using its existing native snapshot path. A valid peer does not become the end-user Actor.
2. Before body streaming, return an explicit admission result. Rejection does not cause a retry or an unbounded body drain.
3. Transfer the original HTTP body through fixed chunks, with checked sequence, cumulative length and an explicit final count/digest. No archive-sized Vec, base64 or ordinary JSON forwarding.
4. The peer reader exposes EOF to the native importer only after complete protocol termination and exact count/hash verification. A bare socket EOF, timeout, missing END or trailing frame cannot certify a complete upload.
5. Run the existing native restore finalization once, including historical Begin/Stage/quorum/CAS, original-Actor and terminal audit rules. Only its actual completed result may mint the dedicated completion variant.

The final request binding contains the canonical prelude and the verified upload's final length/digest. Because the digest is not known before a one-pass upload, the initial nonce is only admission context; it is insufficient to mint completion. The final proof binds the exact END result.

### One download

The leader's existing native plan creates the held archive and completes its source/clock/Actor/audit gates. The response descriptor binds that exact archive, including its length and digest. The standby receives it into a private immediately unlinked SnapshotFile and verifies full termination before releasing a successful HTTP head or body. It then performs authenticated publication/catch-up and local final delivery checks under the original deadline. The existing HTTP writer receives the held file only after those gates.

HEAD binds representation metadata without transmitting the body. Failure after a successful first response byte cannot retract already emitted bytes; it also cannot grant retry permission or prove that a remote effect did not happen.

## Completion is a separate security boundary

Ordinary response_digest covers status, JSON and headers. It does not bind an external archive. A valid ordinary completion plus an unrelated file is not valid snapshot completion.

The dedicated descriptor must bind a domain/profile, original nonce, final request digest, cluster/direction, route/method/namespace, response status and semantic headers, body kind, representation/transferred lengths and SHA256. Its publication retains authenticated StateIdentity, clock floor, audit sequence/MAC, committed prefix/applied index, owner projection and a domain-separated publication MAC. Private constructors must consume the actual native terminal capability. An archive digest is never authority by itself.

Two success variants are necessary:

- DownloadCompleted preserves the exported root/generation and distinguishes any authorized observation-only terminal successor from the immutable archived source.
- HistoricalRestoreCompleted preserves the original admitted Actor and original-auth provenance, original identity/activation, operation digest, and the actually committed new root/epoch/terminal successor.

The distinction is required by current code. Historical restore deliberately changes activation and replay epoch and checks the retained original Auth. It cannot be routed through an ordinary "Actor is present in the restored current Auth" shortcut. Conversely, the old Actor cannot authorize a new read or another restore. This variant authorizes only delivery of the single completed response.

At the standby, authenticated committed-prefix catch-up remains under the actual local Service/Seal/barrier owner. Capture the final delivery capsule after a legitimate verified installation, as current forward delivery already does. Tie an allowed historical owner transition to that exact publication, and veto unrelated replacement. Preserve pre-audit and post-audit checks and existing recovery fences. Restore success whose audit/final owner delivery fails remains reconciliation-required with retry_allowed=false; never rewrite it as a harmless rejected attempt.

The exact binary publication encoding and the original-auth historical variant are mandatory implementation review points. This packet does not claim the old JSON constructor already supplies either.

## Bounds and resource ownership

| Boundary | Required value or rule |
| --- | --- |
| Metadata | Existing 1 MiB bounded metadata ceiling and existing individual field checks |
| Data frame | At most 65,536 bytes; all nonfinal chunks full; explicit sequence and END |
| Native archive | Original feature-dependent MAX_NATIVE_ARCHIVE; current native-HA value 2,488,803,400 bytes |
| Maximum frames at that bound | 37,977; no empty data frames or count overflow |
| H2 public upload | Existing 32 MiB collected-body limit remains; this proposal does not claim larger streaming ingress |
| Time | Original request deadline clipped by existing forward_timeout; receiver retains actual TCP-accept origin; no per-chunk refresh |
| Memory | A fixed chunk, bounded metadata and bounded TLS state; no whole archive Vec |
| Standby disk | At most one additional archive-sized held spool for download |
| Snapshot concurrency | Existing single busy SnapshotSpool lease per Service, not a global "16/32" assertion |
| Worker capacity | Existing forwarding permits and actual worker ownership retained until termination; reserved ReadIndex/native/root-pull capacity untouched |

An Instant must not be serialized as a cross-host clock. The sender retains its original local absolute deadline throughout; the receiver clamps its own accept-origin bound by a smaller transmitted remaining allowance. No later message restarts TLS, admission, transfer, hash, catch-up or audit time.

Do not retain the Service writer or HA control mutex across stream I/O. H2 keeps its existing outer spawn_blocking and scoped plain worker; joining on the reactor or detaching the transfer would reintroduce the earlier custody failure. Drop/cancel/panic must close the unique stream/file and release its lease/permit only when the actual owned worker ends. After metadata/admission, a transport failure can include token-use persistence or restore effects; no completed proof means no retry authorization.

## Minimal source seams

CONTRACT.public.json enumerates seven source seams: native admission/HTTP body dispatch, configured peer transport and receiver branch, bounded stream data module, separate snapshot completion/delivery modules, and weak Service handler registration. The direct native snapshot pipeline, original public HTTP framing, normal forward codec and existing response_digest remain the reference behaviors.

The first concrete code slice should implement the bounded body contract and exact terminal witness as an isolated compile unit with narrow real decoder tests. It must explicitly remain data-only and cannot be called a product fix until the authenticated receiver, native plan, binary publication and local delivery path are connected. The next slice must supply that integration and the original-auth historical variant without weakening gates. No formatting/build/runtime qualification is implied by source construction.

## Validation and the fixture

Necessary tests exercise wrong enrolled peer/ALPN/direction before protected bytes, once Actor use, legal and malformed stream termination, actual archive sizes beyond the old ordinary frame limit, original deadline/cancel cleanup, final owner/audit veto, and a historical restore that legitimately changes epoch/Auth. These are source requirements; no new test has been executed in this packet.

The existing controller accepts either one direct pair or one standby307/leader-terminal pair. Transparent forwarding will produce an ingress and leader terminal pair, so a narrowly versioned audit-topology classifier is needed for a fresh fixture. It must require the exact owned ingress plus selected leader, one complete pair each, and preserve the original single CLI window and any newly authenticated correlation. It must not fabricate request identity from adjacency.

Keep B04's CLI exit0, valid archive and known200 requirement. Keep B05's CLI exit0, known200/204, exact real baseline on all three nodes, unchanged input and original cold-restart evidence. Keep all existing invocations, flags, budgets and no-replay rules. The old B04/B05 failures remain immutable. A new reviewed product candidate, normal binaries and fresh authorized PhaseB are still required; previous Mac/X230 full34, H2 and LAN evidence is not relabeled.

## Provenance and limitations

SOURCE-ANCHORS.public.json contains full-identity references and exact line excerpts; references/ carries their whole sources. CANONICAL-MEMBERS.public.json traces the product leaves through the exact four root directories and the HA-service subtree. ACTUAL-FAILURES.public.json is a selected lossless projection of the original complete report, not a replacement raw report.

The independently unobserved second upload bytes, CLI ALPN, internal400 cause and client wire framing remain unobserved. The implementation is driven by the failed default standby behavior and verified source mechanisms, not by invented diagnostic facts.
