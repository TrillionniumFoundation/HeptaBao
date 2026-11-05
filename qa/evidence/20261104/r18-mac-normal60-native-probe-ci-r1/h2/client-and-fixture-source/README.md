# Independent normal native HTTP/2 gate — source proposal

This is a new QA project and a new fixture. No QA Cargo command, Rust component, product process, network request, prepare, or live run has been dispatched from this package. The product identity is df026fe323dd7cf0f0ec57d7d2d9c5a79897053c / 424463ccd2310ddc1e7b2bbcd7b7af29ae58c825. Original Phase B UNKNOWN results remain unchanged and are not retried.

## Review order

1. PLAN.public.json and the three UNRESOLVED templates state all proposed steps and caps.
2. candidate/native_h2_client.rs defines the single TLS connection and single HTTP/2 request.
3. candidate/native_h2_client_tests.rs contains six separate QA components using real h2 streams over in-memory duplex I/O.
4. candidate/native_h2_gate_r1.py adds the H01–H03 operations to the recovered normal fixture/lifecycle.
5. candidate/native_h2_binding_r1.py requires actual normal 44, existing 7, new 9 and an independently completed QA build/components receipt.
6. candidate/build_native_h2_client_r1.py creates only the new owned QA project, validates the generated lock, builds offline and retains the exact compiler outputs.
7. Review diffs, canonical member hashes, original references, selected pure component receipt, and the independent h2 EOS review explain what is retained and what is new.

All ready flags are false in templates. The placeholders cannot authorize execution. ROG's first df026 normal attempt stopped at an absent old target before Cargo, so this package neither invents a successful normal receipt nor silently creates a replacement target. The parent must bind a separately verified existing target and actual normal receipt after that job's terminal review. Only then can the new QA build be separately authorized.

## What the live gate would establish

| Case | Actual operation | Required evidence |
| --- | --- | --- |
| H01 | Original strict HTTP/1 helper GETs the current leader's native snapshot route | Complete 200, bounded real native archive, one actual request/response audit pair on that node |
| H02 | One strict TLS HTTP/2 GET of wire/data/seed?version=2 | Actual ALPN h2, CA/localhost/leaf verification, stream 1, complete 200 JSON, exact baseline value and version |
| H03 | One strict TLS HTTP/2 GET of the actual leader's native snapshot | Same TLS and stream evidence, complete 200 application/gzip, canonical archive validation, all observed KV2 versions and metadata unchanged across the three nodes |

The retained normal setup creates a synthetic two-version KV2 dataset and three loopback native nodes using the ordinary default-feature binary. The synthetic marker text normal33-wire-seed-2 is a historical test label, not a statement that the product is revision 33. The actual candidate is enforced by source, binary, and build receipts.

The three operations have separate explicit roles. H01 is a positive control. H02 and H03 each make one connection and one request, without redirects, reconnects, or request retries. There is no official CLI invocation, restore upload, service cold restart, production cutover, provider request, or J3160 access in this gate.

The later official OpenBao 2.7.1 CLI B01–B05 exercise remains a separate fresh fixture. Passing this H2 gate would not supply CLI or restore/cold interoperability results. It also cannot retroactively establish the old B01 connection's ALPN or request identity.

## Message completeness

The client offers only h2 and requires rustls to report selected ALPN h2. It builds a root store from the one bound CA, verifies localhost, compares the actual peer certificate SHA256, and connects only to one of the three fixed loopback ports. Resumption and early data are disabled. No DNS, proxy, system CA fallback, trace, or dynamic URL is used.

It requires a single canonical decimal Content-Length, bounds headers and body, observes every DATA result, waits for trailers, rejects nonempty trailers, requires RecvStream::is_end_stream(), and checks the exact byte count. A DATA loop returning None is insufficient by itself.

The exact h2 0.4.19 source at d57d1b852fec9dda6d42d3454502006d52104da8 was inspected and independently reviewed. A reset before receive EOS enters Cause::Error even for NO_ERROR; the remaining receive/trailer polling returns an error. If EOS was already received, ErrorAfterEndStream can preserve message completeness for any later reset reason. The gate therefore proves the received message was complete; it makes no claim that no late reset occurred or that the whole bidirectional connection closed gracefully.

The parent additionally requires status 200, the operation's exact Content-Type, actual JSON value/version or archive shape, and actual audit pairing. A complete error response can make the client itself exit zero and is rejected by the parent. The body cap is 8 MiB and qualifies only this small fixture. It does not supply the separate 34 MiB transport result.

The archive observer checks the complete single gzip member, canonical tar layout, four regular members, exact termination, native header shape and clear checksums. Sealed payload shape is checked; this observer does not independently authenticate the encryption tag. Actual restore plus API readback and cold restart are still separate required evidence.

## Six independent QA components

The components use real h2 client/server connections over a single owned in-memory duplex. They do not call product code, bind a socket, create files, or use credentials.

- Complete DATA with END_STREAM is accepted.
- Complete DATA followed by empty terminating trailers is accepted.
- RST_STREAM(NO_ERROR) after all declared body bytes but before EOS is rejected.
- EOF after all declared body bytes but before EOS is rejected.
- Short EOS and duplicate Content-Length are rejected.
- Expired or extended original request deadlines are refused.

For reset/EOF cases, an acknowledgment forces the server to wait until the client has already observed exactly the declared body bytes without EOS. The component then calls the production QA receive function. Deliberate negative streams may also end their connection driver with its fixed h2 error; this is recorded as joined, not converted into message success. Normal paths still require clean/cancelled driver completion. Six names and execution results are checked from the retained libtest output. These components have not yet been compiled or run.

## Standalone offline build

The QA Cargo project is outside every frozen product worktree. It uses exact direct versions and normal compatible dependency features. The proposed build seeds the owned Cargo.lock from the canonical copy, runs generate-lockfile offline once, and then verifies the result before any build:

- Exactly one owned QA package has no registry source/checksum.
- Every other package must have the exact name, version, registry source and checksum present in the canonical df026 lock.
- Foreign registries, path packages, missing checksums, duplicate packages, unexpected fields and wrong versions are rejected.
- Subsequent binary and component compilation use --locked --offline.
- Both compiler JSON streams, source inputs, actual binary identities, component listing/run, and owned cleanup are retained.

No target fallback is implemented. The bound existing target is required to remain the same directory. Source HEAD/tree/status and the canonical lock are checked before and after; Cargo's working directory is only the new QA project. The original normal 44/7/9 receipts are required but are not re-executed by this controller.

The builder reuses only the exact reviewed Phase B Owner class factory and the exact CLI reference lifecycle definitions. It does not invoke their main, native fixture setup, or Phase A owner constructor. Original Popen registration, process identity, deferred signal handling and one explicit stop budget are retained.

The new QA build cap is 600 seconds with proposed outer supervision of 660 seconds. Its internal caps are Git/tool 15 seconds, offline lock generation 20, release compile 180, component compile 180, list 15 and six-component execution 30. Every operation is clamped to the same absolute build deadline. Cleanup retains TERM 5 / KILL 5 without business or build command replay. A missing result for a published command intent is unknown. A descriptor-close failure remains failed and cannot be cleared by later descriptor reuse.

## Fixture deadlines and ownership

The original normal action cap remains 300 seconds. HTTP and the H2 client's entire connect/handshake/request/receive/driver closure use the original 15-second absolute Linux monotonic deadline. Time spent preparing the private stdin file consumes that same interval. The client does not start a fresh timer after TCP, TLS, headers, or DATA.

Readiness remains 45 seconds; election 60; stable leader 2.2; peer 1500 ms; forwarding 8000 ms. The original reference deadline kill/wait 5 seconds is separate from the single explicit stop/finish TERM 5 + KILL 5 ledger. No whole-path claim of one budget after every possible signal is made.

The new live supervisor proposal is 2400 seconds for this distinct gate; it is not a historical Phase B outer limit. Readonly prepare is 300/330. The controller explicitly fails if final observation or publication overruns its original final/prepare interval.

The recovered setup, HTTP request path, server start, exact process ownership, action/deadline helpers, state observations, and stop ledger retain their original definition bytes. Thirty-four definition segments are byte-identical. New methods are the two H2 operations, private input framing, H1 positive control, and exact audit-pair requirement. Official CLI/restore/cold methods are not invoked and were removed from this independent controller.

Any unknown, partial body, timeout, missing client terminal, failed business check, or unconfirmed stop prevents subsequent cases. Only bounded read-only evidence and owned cleanup remain. The old UNKNOWN fixture is never used for a new request or grant.

## Privacy and audit boundaries

The root token is read only from this new fixture's private bootstrap file. It enters the client through a bounded private stdin file; argv contains only a SHA256. Bodies remain private. The public report contains fixed classifications, counts and digests, without raw headers, errors, token or certificate text. Actual fixture literals and encoding variants are scanned; that is not a universal secret detector.

Audit observations use the retained real schema, stable file/prefix/sequence checks and complete request/response pairs. The controller requires exactly one pair on the actual target during each isolated request window. Audit MACs are not independently authenticated, route digests are not reversed, and audit events do not prove HTTP framing. The H2 client supplies its own receive-message evidence.

## Remaining gates

The product's actual normal build and 44/7/9 completion, the QA client's actual build and six components, future source/artifact transport, concrete binding, readonly prepare, and an exclusive new live window all remain separate gates. No runtime pass is claimed by this source package. No result here makes the OpenBao 2.7.1 whole-replacement denominator complete.
