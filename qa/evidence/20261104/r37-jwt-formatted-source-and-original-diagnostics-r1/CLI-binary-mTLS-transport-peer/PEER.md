# Independent narrow review: snapshot peer transport SOURCE

Verdict: no new blocking finding in the reviewed transport slice. This is a source-only conclusion, not Rust compilation, component execution, Service integration, delivery, publication or product qualification.

## Exact scope

Reviewed the 17-file packet cd697d0d4315132fdcb8f2bca8eae6f22e349918 (476,384 bytes), including the complete 20,662-byte peer source, 20,411-byte test source, two small integration deltas, before/after sources, and the three exact rustls files. Also read the separate 15,545-byte body source bbf14e2500ffbfe36a0ef24ca0e19240e88d319e. All 18 whole inputs are enumerated in INPUTS.public.json.

Production: a5cbd1487eab920ccf00376197e63e6e0ca69e21 / SHA256 4ead5f27c8d14e0113ebcae7188aa1c4448cdc2e3d5827d02a7aa0c1b242ecff.
Body: bbf14e2500ffbfe36a0ef24ca0e19240e88d319e / SHA256 c5371d4d81da56be70655bd618d7fbe321ca52df531cd30f33b92dd014a903a5.
rustls 0.23.44 is bound by the supplied lock and official annotated tag to commit 64ad386785c718c74262b79e6893813db381adfe. This review reads that exact source; it does not assert a deployed binary dependency.

## Closure and partial I/O

At peer source lines 264–272, the client finishes the framed upload, sends close_notify and explicitly flushes before reading the reverse response. Receiving close_notify sets rustls' received-side flag (common_state.rs 522–526), while sending it sets the distinct local sent-side flag (581–588); wants_read depends on the received-side flag (674–683). The reviewed implementation therefore preserves reverse-direction reads/writes at the source level.

Body source lines 367–391 requires exact END count/length/SHA and a nonempty one-byte underlying read returning zero before constructing VerifiedSnapshotBody. rustls conn.rs 180–194 and 233–240 distinguish received close_notify from bare TCP EOF, which returns UnexpectedEof after buffered plaintext. The body probe uses a one-byte buffer, avoiding the empty-buffer zero shortcut. finish (402–411) refuses a consumer that left payload unread and does not drain it silently.

The receiver sets FailedIo before sending READY (peer 383–389), and sets BodyComplete only after body.finish and a deadline check (390–403). complete requires BodyComplete, then writes terminal metadata/body/close_notify and flushes before setting terminal_written (440–455). The listener requires both callback success and that terminal flag (525–539). Explicit I/O failures or unfinished body reads do not create the decoded-body witness. rustls Stream::write may defer a transport error after consuming plaintext (stream.rs 117–127); subsequent exact writes and explicit flush are therefore material parts of this protocol. A server-side encoded witness/terminal_written remains a local send fact, not proof of remote application receipt. The client additionally requires response body.finish and its original deadline before returning a successful transport result.

## Identity, time and application boundaries

Client source 201–237 uses one selected configured endpoint, one connect, CA/name/strict ALPN, certificate-chain bounds and exact enrolled server leaf before sending metadata at 243. The server identifies the actual mTLS client and retains actual leaf/acceptance time in a privately constructed owner; the snapshot branch rejects missing Raft ALPN. The ordinary branch feeds the already read four bytes back into the existing bounded decoder. The old authenticated module is an exact prefix of its successor; the lib change is only gated exports. No Service route is wired by this slice.

Client deadline is min(original request deadline, transport timeout); receiver clamps received remaining time from the actual TCP acceptance origin and its configured timeout. ForwardDeadlineStream refreshes each actual socket timeout using the same deadline. This is conservative rather than a new budget. Generic caller-supplied Read/Write operations are not forcibly interrupted by these Rust checks; late return is rejected, and actual integration must retain its own bounded held-source/sink contract.

The method accept_body<T> returns data verification, not Actor or parser authority. In particular, T can be Result<...>; an inner Err must still be rejected by the Service before complete. Its parsing callback may write only private staging and must not finalize a restore. Similarly, exchange_snapshot_before writes response_sink before final END/EOF verification, so that sink must be staging/held storage and cannot publish an HTTP success early. READY must follow the real native Actor/source/target/cluster/nonce/hop admission, and complete must follow the actual owner/audit/publication gates. These boundaries remain deliberately unimplemented by this transport slice; the peer does not qualify the planned successor integration.

## Validation actually performed

One pure V8 run of the supplied independent verifier completed 50 source/whole checks: all 18 input pins, strict one-hunk reconstruction of both integration changes, exact four-file combined patch/new-file reconstruction, bounded source-order assertions and presence of six intended test sources. No author checker, Rust formatter/compiler/test, network service or Runtime operation ran for this review.

There are six test sources: five socket/mTLS scenarios and one constructor-only expired-deadline refusal. All are uncompiled and unexecuted. The tests cover source-level plans for opposite-direction download after close_notify, bare TCP EOF rejection, selected-leaf denial before upload, terminal rejection without upload consumption, original callback isolation, and expired construction. They do not currently provide an executed partial-write/cancellation fault proof or full Service/HTTP publication proof. The eight-second value bounds the TLS test exchange; disposable OpenSSL setup uses status() and is not individually hard-timed by that value.

Original B04/B05 or prior compatibility results are unchanged. No production source was edited by this review, and no Runtime, credential, provider, SDK or host action was authorized or performed.
