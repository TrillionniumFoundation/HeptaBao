# HeptaBao P0 Development Memory Execution Contract V1

## Profile

`HB-P0-DEV-MEMORY` is a disposable, loopback-only engineering profile. It is not compatible, durable, available, replicated or production supported.

## Start contract

The binary requires:

- `HEPTABAO_P0_BIND`, defaulting to `127.0.0.1:18200`, and rejects a non-loopback IP;
- `HEPTABAO_P0_DEV_TOKEN`;
- `HEPTABAO_P0_DEV_UNSEAL_KEY`;
- `HEPTABAO_P0_AUDIT_PATH`, an absolute new file path.

The token and unseal key must be distinct and at least 24 bytes. Rejected weak/equal credential inputs are overwritten before returning an error. The audit file is created with create-new semantics. Existing files, symlink components and non-directory parent components are rejected. Pure-std path inspection cannot eliminate every platform TOCTOU; production audit devices require descriptor-relative, no-follow platform adapters and independent review.

## State machine

Initial state is uninitialized and sealed. Init marks initialized but stays sealed. Unseal requires the injected development key. Seal requires authentication while unsealed. KV v1 requires initialization, unsealed state and the development token.

P0 request bodies intentionally accept only a bounded single-field JSON subset:

```text
{"key":"<ASCII development value>"}
{"value":"<ASCII development value>"}
```

General JSON whitespace, arbitrary object fields, arrays, Unicode escapes and the full OpenBao request schema are not implemented and must not be inferred from P0 success. Raw unescaped quotes, unsupported escapes, non-ASCII bytes and trailing syntax fail closed.

The body contract is exact per operation:

- init accepts exactly `{}`;
- unseal accepts only a non-empty registered `key` object;
- KV write accepts only a non-empty registered `value` object;
- health, seal status, seal, KV read, KV list and KV delete accept no body.

Unexpected or otherwise ignored bodies are rejected with `operation-body-forbidden`, audited as `RequestRejected / NotAttempted`, and never reach authentication, state transition or storage mutation.

## Connection and deadline contract

- each accepted TCP connection carries exactly one HTTP/1.1 request and receives `Connection: close`;
- no more than 32 request readers are active at once;
- admission beyond that bound returns 429 after a transport-rejection audit, or 503 when the audit cannot be persisted;
- the complete request must arrive within one five-second absolute read lifetime;
- every read uses the remaining lifetime, so byte trickling cannot reset or extend the deadline;
- every normal or rejection response has one five-second absolute write lifetime;
- before each partial response write and the final flush, the implementation recalculates the remaining lifetime and configures the socket with that remainder, so successful short writes cannot restart the deadline;
- capacity rejection in the listener thread and parser rejection in a worker use the same absolute-deadline writer;
- no error path may perform an unbounded blocking write on the listener or worker;
- each admitted connection uses a fallibly created bounded worker; a worker-allocation failure releases the active count, audits `connection-worker-spawn-failed`, closes the accepted socket and does not panic the listener process;
- the validated envelope then carries a dispatch deadline expressed as nanoseconds from the same process-local monotonic clock epoch;
- `deadline <= received_at` is an invalid envelope and never reaches operation classification;
- Host exactly equals the listener's actual local address, including an assigned ephemeral port.

## Request identity

The ingress allocates a request-attempt ID immediately after `accept` and before reading request bytes. Parser, framing, Host, timeout and socket errors therefore have an auditable identity without retaining raw request bytes.

A syntactically valid `X-HeptaBao-Request-Id` may replace the attempt ID after parsing and exact Host verification. The P0 registry permits at most 4096 live identifiers for 60 seconds and rejects duplicate use with 409 or saturation with 503. It is process-local development machinery, not the Authbus HA replay authority, and it is intentionally lost on restart. Registry `Debug` redacts the entire active-ID map and reports only capacity and TTL configuration.

## Owned secret-material lifetime

- canonical request targets own path/query strings, redact `Debug` and overwrite those owned strings on drop;
- canonical target equality can be checked without constructing a duplicate target string, and Authbus request binding uses that path;
- parsed header values use owned byte vectors and are overwritten by their controlled destructor;
- parsed request types do not implement implicit `Clone` and their `Debug` output excludes target text, header values and body bytes;
- parsed request bodies are overwritten when the request is dropped;
- the raw socket accumulation vector and fixed read buffer are overwritten on every controlled success or error return;
- `SecretBytes` rejects implicit cloning, redacts `Debug`, overwrites rejected constructor input and overwrites owned bytes on drop;
- in-memory KV paths use an owned redacted wrapper and overwrite their owned string buffer on entry removal or server-state drop;
- in-memory server-state `Debug` reports only initialized/sealed flags, KV entry count and generation; it never renders KV paths or values;
- P0 response bodies do not implement implicit `Clone`, are redacted in `Debug`, and are overwritten on drop;
- an old response body is overwritten before replacement after a response-audit failure;
- the rendered HTTP wire vector is overwritten after the write/flush attempt, whether delivery succeeds or fails;
- KV read JSON is assembled directly into the owned response vector rather than through a secret-bearing temporary `String`;
- Authbus request-binding `Debug` is length-only; assertion and verified-identity `Debug` redact subjects and cryptographic fields;
- Authbus assertion and verified identity do not provide implicit `Clone`;
- temporary canonical digest and unsigned signature payload vectors are overwritten immediately after their provider returns, before provider errors are propagated.

These are best-effort controlled-path guarantees. They do not prove compiler-resistant zeroization, allocator reuse safety, page scrubbing, locked memory, swap exclusion, kernel-buffer clearing, crash-dump exclusion or the behavior of an external crypto provider.

## Audit ordering

- malformed framing, parser failures, Host mismatch, request-read timeout and admission saturation are audited before their error response;
- worker-allocation failure is audited against the pre-parse attempt ID before the connection is closed;
- operation/body mismatches are audited and rejected before dispatch;
- rejected valid envelopes are audited; if rejection audit is unavailable, the response is 503;
- accepted requests are audited before dispatch;
- request-audit failure prevents mutation;
- response audit records committed or not-committed outcome with distinct stable detail codes;
- post-commit response-audit failure returns 503 with `committed=true` and a recovery reference;
- response-delivery failure does not alter a known committed outcome and is audited separately;
- no transport or application audit record contains raw tokens, unseal keys, request bodies or secret values.

The P0 recovery reference is not durable across process restart. A production implementation requires a durable idempotency/outcome ledger and a read-only reconciliation API before ambiguous retries can be safe.

## Response framing

Every response carries an exact `Content-Length`. HTTP 204 is represented as body-free at the P0 library boundary and rendered with `Content-Length: 0` and no content type. KV write/delete and seal may not place metadata in a 204 body.

## Test matrix

- fresh health = 501 and sealed;
- init = committed, credentials not returned, and requires exactly `{}`;
- unseal wrong/correct key;
- authenticated and unauthenticated KV operations;
- empty-body enforcement for health, seal status, seal, KV read/list/delete;
- sealed rejection;
- exact Host, duplicate Host and request-smuggling negatives;
- invalid equal/earlier deadline and expired dispatch request non-dispatch;
- total socket-read deadline under partial and byte-trickled input;
- total response-write deadline under partial progress and a non-reading peer;
- bounded concurrent connection admission;
- bounded rejection-response writes;
- fallible worker creation with fail-closed capacity release and no panic;
- client request-ID replay, registry saturation and registry diagnostic redaction;
- request, rejection, response-audit and response-delivery ordering;
- zero-byte HTTP 204 wire and library response;
- new absolute audit file and symlink rejection;
- request/response/server-state/Authbus diagnostic redaction;
- raw unescaped quote rejection in the P0 JSON subset;
- explicit controlled-path overwrite markers for target, KV path, request, response, wire, digest-preimage and signature-payload buffers;
- process startup rejects missing/equal/weak credentials and non-loopback bind.

Machine-readable transport cases are maintained in `planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml`.

## Exit boundary

A successful P0 test means only that the bounded development contract executed on the exact source. It does not close H01 compatibility, H02 production dependency selection, durable storage, Authbus HA replay, security review, memory side-channel qualification or any authority gate.
