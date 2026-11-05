# H2 synchronous native-ingress boundary — new source candidate

Status: **source only; no Rust formatting, compilation, tests, server or CLI execution is claimed by this packet**. The candidate is based on canonical commit `3cb873919170cc77101b27f6a3ab9e98f41f8d93`, tree `7f4d48a647a81ca96e8a24a0a057c2c829459060`. It changes one existing production file, `crates/heptabao-server/src/http_h2.rs`, and adds one test file. The separate cold-read timing proposal is owned by the HA reviewer and is not silently included here.

## Why this boundary changes

The actual stopped node1 observation recorded `fresh_ingress_same_root_closure` failing with reason SHA-256 `392f52cb2031a180c22d20184a7237a9def3cf925148ba9f0eebf68f1bb25aed`. The exact public `HaError::InvalidCluster` Display string hashes to that value. Within the complete canonical source path for that scope, the only source of that variant is `require_blocking_worker`: it refuses whenever `tokio::runtime::Handle::try_current()` succeeds. The root independently reviewed that finite error chain in blob `2256dc9f3932002fad81d898dba825e4d42e0ae8`.

The normal H2 implementation runs synchronous Service work inside Tokio `spawn_blocking`. The primary Tokio 1.53.1 source reference enters the runtime on those workers before executing jobs. A blocking pool thread therefore does not satisfy the stricter native guard's requirement of having no entered Tokio runtime. The exact locked dependency version and upstream source reference are recorded in `source-chain.public.json`; this is not a new verification of deployment registry bytes.

The old observation has no request ID or recorded negotiated ALPN. It does not by itself prove that the old B01 CLI used H2. Both historical B01 UNKNOWN outcomes stay UNKNOWN, with no replay or relabelling.

## Exact production change

Keep the original `tokio::task::spawn_blocking` call. Inside that already-owned blocking job, call a private `run_unentered_service_worker` helper with the same original `Instant`. The helper starts one scoped standard-library thread and joins it before returning. That new OS thread does not inherit the parent's Tokio enter guard.

The 825-byte original parsing and `process_parsed_request` body is unchanged except for four additional leading spaces. Its wire value, request reader, context, certificates, peer, attempt ID, consistency settings and absolute deadline remain the same. No wrapper converts the native guard to a permit, removes it, sets a thread-local bypass, or authorizes a nested async context.

The outer await now has two fallible layers. Its first `?` unwraps the original Tokio JoinError mapping. Its second unwraps the new helper's `Result<T, ()>`. The callback result (the original reply tuple) is moved once without cloning or reinterpreting it. A deliberately nested callback `Result` remains an inner value; the component tests explicitly check `Ok(Err(...))`.

The existing `negotiate`, `serve`, `request_wire`, `send_reply` and `response_frames` implementations remain unchanged. The only existing function body changed is the normal Service dispatch in `exchange`. The unchanged request-wire function is immediately followed by the new helper and test-module declaration. The review proof reverses the entire replacement dispatch, including its trailing newline and extra question mark, and removes the one helper block to recover every byte of the original 13,613-byte file.

## Ownership and terminal behavior

| Event | Owner and result |
| --- | --- |
| Already expired before helper entry | Return helper Err without calling the Service callback; drop its captured inputs normally. |
| OS thread creation fails | Return helper Err before the callback starts; no retry and no new Service admission. Earlier HTTP parsing/rate-limit observations are not refunded. |
| Deadline expires while the thread is being scheduled | The child checks the same original deadline before invoking the callback and refuses without entering Service. |
| Callback returns normally | Join the actual child, move its original result to the blocking parent, then let the original reply path use the same deadline. |
| Callback unwinds | Join reports the panic and the helper returns Err. Rust unwinding drops the callback captures; existing poisoned locks and durable recovery state are not cleared. |
| Async waiter or H2 stream is cancelled | A started Tokio blocking job continues owning the scoped child. Its pool slot is not released until join completes. The child is not detached or classified as completed by cancellation. |
| Connection is torn down | The existing runtime drop still waits for owned blocking jobs; the original connection guard remains alive in the outer standard-library request thread until that return. |
| Work runs past the response deadline | No new deadline or retry is granted. Existing synchronous effects remain owned until their actual completion; the original reply path can refuse publication. This patch does not claim that Rust can forcibly kill a thread at the deadline. |

The join is executed in the existing blocking job, never directly on the async reactor. Scoped-thread lifetime enforcement also prevents borrowed worker state from escaping if an intermediate operation unwinds.

This helper supplies an execution context, not an authorization capability. The original native permission, ReadIndex, enrollment, exact root, actor, audit and unknown-outcome checks remain responsible for authority and effects. A nested Tokio runtime entered inside the child recreates the original refusal predicate.

## Absolute deadline and cost

No duration is added to a production request. The same original `Instant` is checked before spawn, immediately inside the child, by the unchanged callback and by `send_reply`. Thread scheduling consumes that original budget. The helper adds no retries, polling loop, fallback executor or timed-join budget.

There is one additional OS thread for each concurrently executing normal H2 Service callback. This is a real thread/stack and scheduling cost. It is not a global pool of 32 threads.

The existing H2 runtime is per accepted connection, with `max_blocking_threads(MAX_STREAMS as usize)` and `MAX_STREAMS = 32`. Each child retains one running blocking parent until join, so at most 32 such additional children are active per connection runtime. The original global connection guard further bounds live connections by `config.max_connections`, whose accepted range is 1 through 128. Thus the loose upper bound on additional children is 32 times the configured live-connection bound, not 32 globally. Other existing runtime, connection and audit threads are outside that count. No new stack-size promise or negligible-cost claim is made.

An H2 reset can leave an already-started callback running. That callback continues charging its parent's blocking capacity and the connection's lifetime; reset is not completion. Queued callbacks do not gain a fresh deadline when eventually scheduled.

## The three unchanged rejection workers

The rate-limit rejection, unsupported native-large H2 transport rejection and oversized payload rejection keep their existing `spawn_blocking` calls. Their source chain is:

`audited_wire_rejection` -> original `lock_until` -> `Service::handle_wire_rejection` -> fixed wire fingerprint and `wire-rejection` / `wire-response` audit events.

That Service method does not call logical `begin_request`, native ingress permission, ReadIndex or the fresh-ingress closure. The full audit sink implementation was read: it appends/syncs the existing audit file, uses the existing configured audit outputs and preserves failure fences. These three branches therefore do not reach the specific native guard diagnosed here. They are left unchanged. This is a source-reachability result, not new runtime qualification of every audit sink.

## Six new component sources

The new module is `http::h2_transport::sync_worker_tests`. Exact names and scope are in `components-plan.public.json`.

1. An actual Tokio blocking parent has an entered Handle, while the joined standard-library child has a distinct thread ID and no Handle; the parent still has its Handle afterward.
2. An expired original deadline calls no work and drops the captured owner once.
3. An inner callback Err value is preserved rather than flattened.
4. A fixed synthetic unwind is joined and the capture is dropped once.
5. Entering a nested Tokio runtime recreates the unchanged guard's refusal predicate.
6. Cancelling the async waiter cannot free a single occupied blocking slot; a queued probe runs only after the real child finishes.

The nested-context component checks the guard predicate. It does not fabricate a native admission or call the private HA-service guard directly. The existing guard's source remains byte-identical, and real native dispatch is a later gate.

The original unexecuted 5,740-byte test draft is retained in `history`. The 6,126-byte successor removes `expect`, `expect_err` and `panic!` in response to the repository's actual strict Clippy rules. Fallible operations use explicit Result propagation, and the intentional unwind uses `std::panic::resume_unwind` with a fixed static payload. Six names and all behavioral assertions remain. The expired-deadline and inner-result test functions are byte-identical. There are no new lint allowances.

A static source check is not a Rust compiler or runtime result. These component sources await the reviewed pinned formatter and normal build.

## Integration and runtime gates

The HA owner prepares the one combined normal-build controller. The original 44 names and original extra seven remain separate and unchanged. A distinct new group proposes this six-test set, the two cold-timing helper tests and one existing real cold-repair regression. That new nine-test group has its own shared 600-second cap; it is not counted in the old 51-test denominator. Actual libtest listing must match the exact expected names before dispatch.

The previous release 1800-second, libtest compilation 3600-second, listing 30-second, six original runtime group 600-second, extra-seven shared 600-second and TERM5/KILL5 contracts remain. New source, artifact, roots, controls and actual authority receipts must be frozen. No result from the old 3cb build qualifies the combined candidate automatically.

After normal build qualification, a separate fresh isolated fixture must exercise actual strict-TLS H1 and actual negotiated H2 native requests including the snapshot path. It must directly record ALPN without private CLI stderr or debug dumps. The existing ALPN test in `http_api_alpn_tests.rs` proves real Rustls TLS1.2/1.3 negotiation and application-record delivery only; it explicitly does not exercise H2 Service dispatch, native profile or an official CLI. It cannot satisfy that integration gate by itself.

A subsequent independently fresh Phase B uses the exact official OpenBao 2.7.1 CLI and legitimate native archives A/B. It retains the original five-window state, all-node audit, API readback and cold-restart criteria, with CLI/HTTP15, action300, ready45, election60, peer1.5, forward8 and TERM5/KILL5. CLI exit zero alone is not restore success. Any unknown/partial result stops subsequent mutation, CLI and cold restart, allowing only read-only reconciliation and owned cleanup. Neither historical UNKNOWN is reused.

Concrete actual-H2 fixture binding and passive ALPN observation are still to be reviewed. No GODEBUG/http2debug or private CLI stderr access is proposed.

## Evidence and verification limits

`source-chain.public.json` binds the canonical source leaves, exact excerpts, observed-reason evidence and upstream version reference. `canonical-membership.public.json` independently matches all fourteen referenced leaves through the six full directly fetched Git trees whose Merkle hashes equal canonical 3cb.

Production and new-file diffs are complete unified patches. Source-only strict application and inverse byte checks are recorded separately. Three early inverse-verifier attempts failed because the verifier used the inner-body fragment in place of the full dispatch, then omitted the trailing newline. The candidate was never changed to obtain a pass; the failed verifier outputs and the corrected explicit boundary are retained.

This packet creates unreferenced Git objects only. It does not move a source branch or PR, overwrite any prior fixture, start a product, call a provider, change a stored credential, or grant deployment qualification.
