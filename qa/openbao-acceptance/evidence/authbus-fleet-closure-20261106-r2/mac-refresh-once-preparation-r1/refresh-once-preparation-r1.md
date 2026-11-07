# Current Mac main3 refresh once controller — prepared core

This is preparation, not a provider refresh receipt. The controller has no module-level side effects and is not a production launcher. No production ledger, provider request or production CAS was executed by its local qualification.

## Already observed separately

- Actual Mac SDK cooperative refresh mutex: 23 isolated cases and both independent-process lock directions passed, job `1a1b1e250b5-fc05-7b51`.
- Actual Mac lower SDK raw-CAS adapter: 29 isolated cases passed, job `1a1b21a8741-fc05-7c60`; 133 returned SQLite handles closed once. It preserves complete owner order, usage, other profiles and raw state rows, and prevents a second original COMMIT dispatch.
- Current selected main3 flags/state: readonly job `1a1b222dff5-fc05-7c90` succeeded with four unchanged full9 observations. Configuration has `leader=false` and `enforceRefreshLeases=false`; selected quarantine/backoff entries are absent. All three access credentials are expired and have refresh fields. These facts do not prove the running gateway's loaded flags or provider validity.

## Prepared controller behavior

The fixed ledger root is `/Users/qianqi/heptabao-authbus-refresh-once-ledger-20261106`. It is distinct from disposable run roots. Its private scope binds exactly the previously selected main3 IDs and main owner directory. The original launcher must create that root once and preserve it. Each owner has one fixed ordinal directory; an existing directory is always refused, including a preceding failure before dispatch or an UNKNOWN outcome. A new launcher, local attempt or new temporary directory cannot reuse that slot through this controller.

The controller performs one selected owner at a time under the original outer deadline. It acquires the qualified actual SDK mutex, rereads the complete current owner and checks it against current source authority. It persists a private intent, then an UNKNOWN dispatch record, with file and containing-directory fsync. At the provider hook's final send point, it synchronously rechecks source, running-writer and original mutex authority plus the ledger namespace. No await occurs between that last check and the supplied native send.

The provider hook must persist the complete bounded response bytes and metadata before the actual SDK JSON parser receives them. The controller then saves the normalized new credential privately before invoking the separately qualified lower raw-CAS adapter. The adapter checks the private durable response witness before writing and again in the actual transaction. A provider exchange, a local owner commit, a complete mutex closure and later application liveness are separate facts.

Any failed response, parsing, persistence, source check, CAS, COMMIT acknowledgement or cleanup is unreplayed. A successful provider exchange followed by an incomplete local write is retained for explicit recovery from its private response record; the controller does not call the provider again. A callback arriving after the original deadline sees a closed context and cannot send or write.

The private ledger retains its own directory descriptors and exact file-generation witnesses. Checks are cooperative namespace checks, not an atomic openat/compare-unlink protocol against arbitrary same-UID namespace attackers. It does not remove a foreign replacement. The existing qualified mutex has the same explicit cooperative-lock scope; it does not cover plugin helpers that bypass that mutex.

## Local qualification boundary

`mac_refresh_once_controller_local_test_r1.mjs` uses real local filesystem operations, O_EXCL, retained descriptors and fsync. It substitutes provider, source authority, running-writer authority, SDK mutex and raw-CAS capabilities. Its final result is 31/31. The initial 30/31 result and exact source preimage remain separate: a directory replacement during the final source check showed the need for another ledger verification after source/writer checks. The final implementation makes that additional check; it does not reclassify the original failure.

Cases cover unknown native-send outcome, duplicate dispatch and response, response capture before send, raw-response/intent/normalized-record fsync failures, full-owner CAS rejection after provider success, lost COMMIT acknowledgement, failed mutex release after known commit, last-moment source or ledger replacement, async/false authority callbacks, expired and late contexts, oversized responses, changed provider identity, forged durable witnesses, response inode replacement, scope/slot symlinks, unknown descriptor close, configured-only leader facts, a provider result without a real send, and terminal-write failure without a second attempt.

## Bindings still required before real execution

1. Read and bind current public provider flow, fetch guard, runtime fetch, response-body, expiry and auth-identity source. Apply only reviewed in-memory source overlays. Keep original SSRF/TLS/proxy checks, prevent redirects/retries, clamp the original 30-second provider budget to the existing outer deadline, capture complete bounded bytes before parse, and place the once latch after final asynchronous DNS/dispatcher preparation.
2. Independently observe exact registered `gui/501/ai.openclaw.gateway` process birth, executable, loaded arguments and current configuration generation. Configured `leader=false` is not accepted as running-writer authority. If the observed process cannot be bound to that configuration, present an exact owner-bound, reversible quiescence/restore procedure before a production action.
3. Bind the qualified real mutex and lower SDK CAS through a fresh owned launcher with current source scope, kernel read/write/network limits, explicit original child custody, response closure and private durable ledger admission. The generic dependency-injected core alone cannot claim those properties.
4. Qualify actual source overlays and their transport failures in an isolated fixture. Real provider dispatch remains withheld until the ongoing actual API/SDK migration checks and the explicit concurrent-writer admission are closed and the complete execution plan has been reviewed.
5. After a known source commit, create a new current generation/capsule and update target HeptaBao KV with CAS. The prior expired capsule remains historical. Provider application liveness, actual gateway consumption, client restart/rollback, fleet cutover and deletion of old OpenBao remain separate evidence gates.

No credential value, profile ID, credential digest, original configuration digest or raw production argument/environment is part of the public receipts.
