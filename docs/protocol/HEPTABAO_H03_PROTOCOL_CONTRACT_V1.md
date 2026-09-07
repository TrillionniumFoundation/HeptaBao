# HeptaBao H03 Protocol Contract V1

## Scope

This contract defines the P0 request envelope and the minimum H03 semantics needed before framework or TLS selection. It is deliberately narrower than full OpenBao compatibility.

## Bounds

| Surface | Bound |
|---|---:|
| HTTP head | 16 KiB |
| body | 1 MiB |
| request target | 2 KiB |
| header count | 64 |
| one header value | 8 KiB |
| request dispatch budget | 60 seconds expressed as process-local monotonic nanoseconds |
| P0 total socket-read lifetime | 5 seconds absolute; byte trickling cannot extend it |
| P0 total response-write lifetime | 5 seconds absolute; partial progress cannot reset it |
| P0 concurrent request readers | 32 |

## Parsing invariants

- HTTP/1.1 only.
- CRLF only; bare CR/LF and NUL are rejected.
- Request head and target are ASCII.
- Exactly one non-empty Host header is required.
- Duplicate headers and `Transfer-Encoding` are rejected.
- `Content-Length` is decimal canonical form and exactly matches the body.
- Header names use the HTTP token character set; values do not contain controls, tabs, leading/trailing OWS or multiple leading spaces.
- Paths begin with `/v1/`; duplicate slash, dot segment, backslash, NUL, fragment and encoded slash/backslash are rejected.
- Percent escapes use uppercase hex and may not encode an unreserved character.
- Query keys are unique and canonicalized into lexical order; operations not defining query semantics reject all query parameters.
- P0 request bodies are a bounded, single-field JSON subset, not a general JSON or OpenBao compatibility claim.
- The P0 JSON subset accepts only a quoted `key` or `value` field with the registered escapes; a raw unescaped quote, unsupported escape, non-ASCII byte, extra field or trailing syntax fails closed.
- Body semantics are operation-specific: init requires exactly `{}`; unseal and KV write require a non-empty registered body; health, seal status, seal, KV read, KV list and KV delete require an empty body. A body that would otherwise be ignored is rejected and audited before dispatch.

## Operation registry

P0 registers only health, init, seal status, seal, unseal and KV v1 read/write/list/delete. Unknown method/path combinations fail closed. Classification happens after target canonicalization and before authentication or mutation.

## Deadline and clock domain

`MonotonicTick` means nanoseconds from one process-local monotonic clock epoch. The value is never a wall-clock timestamp and must not be serialized, compared across processes or used as Authbus wire validity evidence.

The caller supplies `received_at`, `deadline` and the actual dispatch-time `now` from the same monotonic clock domain. `deadline <= received_at` is always `InvalidDeadline`. A valid deadline is no more than 60 seconds after receipt and later than actual dispatch time. Clock regression, conversion overflow and expiration cannot dispatch.

The ingress socket additionally enforces a five-second absolute read deadline. Per-read activity does not reset this deadline, so a peer cannot keep the sole request alive indefinitely by sending one byte at a time.

Every response uses a separate five-second absolute write deadline. Before each partial write and the final flush, the implementation recalculates the remaining lifetime and configures the socket with only that remainder. Successful partial writes therefore cannot restart the response lifetime.

## Request identity

A P0 ingress allocates an attempt identity before parsing so malformed framing, Host mismatch and read failures remain auditable. An optional `X-HeptaBao-Request-Id` is syntax-checked and guarded against in-process duplicate use after successful parse and Host binding. This bounded development guard is not the Authbus HA replay authority; the production lifecycle is specified separately in `HEPTABAO_AUTHBUS_REQUEST_ID_LIFECYCLE_V1.md`.

## Secret-bearing request types

Header values are stored as owned byte vectors so their controlled destructor can overwrite the bytes. Header `Debug` renders names and counts only. `ParsedHttpRequest` and `RequestEnvelope` do not implement implicit cloning; their safe `Debug` output contains method, byte counts and timing metadata but never target text, header values or body bytes. Parsed request bodies are overwritten when the owned request is dropped.

Canonical targets own their path and query strings, redact `Debug`, overwrite those owned strings on drop and can compare an input against the canonical representation without constructing an additional secret-bearing target string. Authbus request binding uses that allocation-free canonical comparison.

The socket ingress also overwrites its raw accumulation vector and fixed read buffer on every controlled success and failure return. This prevents ordinary code paths from retaining duplicate token/body bytes after the owned parsed request has been constructed.

`SecretBytes` owns secret bytes, cannot be implicitly cloned, uses length-aware comparison, redacts `Debug`, overwrites rejected constructor input, and overwrites its owned byte storage on drop. P0 in-memory KV paths use a redacted owned wrapper and overwrite the owned path string when the entry is removed or the server state is dropped. Callers may borrow secret bytes only through the explicit exposure method.

These controls are best-effort process-memory hygiene, not a claim that compilers, allocators, prior temporary values, OS socket buffers, swap, crash dumps or optimized-away writes cannot retain data. Production work still requires independently reviewed zeroization primitives, memory locking, dump policy and platform evidence.

## Response framing

Every response carries an exact `Content-Length` and closes the connection. HTTP 204 responses have `Content-Length: 0`, no content type and no body at both the library and wire layers. A caller may not encode metadata in a 204 body.

## Audit semantics

A request-attempt identity exists before parsing. Parser, framing, Host and socket-read failures are audited with `operation=None`, `RequestRejected`, `NotAttempted` and a stable detail code before the error response is written.

For a valid envelope, operation-specific body validation and request audit both precede dispatch. A mutating response is acknowledged only after response audit. Committed and merely prepared responses use distinct detail codes. If the operation committed but response audit or response delivery failed, the outcome remains committed and the caller must not blindly retry.

## Exclusions

Chunked transfer, HTTP/2/3, proxy forwarding, namespaces, wrapping, leases, plugins, Agent/Proxy behavior, TLS, durable reconciliation, production replay storage, allocator/page scrubbing and full OpenBao error/normalization compatibility are outside P0.
