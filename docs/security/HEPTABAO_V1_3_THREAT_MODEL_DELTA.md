# HeptaBao V1.3 Threat Model Delta

## Scope

This delta covers the strict H03 protocol crate, the Authbus assertion contract and the `HB-P0-DEV-MEMORY` server. It supplements the system threat model and grants no qualification or authority.

## Assets

- development root token and unseal key;
- in-memory KV paths and values;
- request target, headers, body, identity, canonical operation and deadline;
- response body and rendered HTTP wire bytes;
- audit happens-before and commit outcome;
- Authbus subject, signing-key identity, nonce, request binding, canonical digest preimage and unsigned signature payload;
- exact source, lock graph and test evidence.

## Trust boundaries

1. untrusted TCP client → strict HTTP parser;
2. parsed request → operation registry, operation-body policy and state guard;
3. process environment → development credential loader;
4. process → audit filesystem path;
5. Authbus process/domain → assertion verifier;
6. verified external identity → HeptaBao identity/policy evaluation;
7. repository source → CI runner and evidence artifacts.

## Threats and controls

| Threat | Control | Residual risk / required later evidence |
|---|---|---|
| HTTP request smuggling | CRLF-only, exact Content-Length, duplicate-header and Transfer-Encoding rejection | HTTP/2/3, proxies and framework adapters remain unqualified |
| Malformed P0 JSON accepted as a secret value | bounded single-field ASCII subset; raw quote, unsupported escape, extra/trailing syntax and non-ASCII fail closed | full JSON and OpenBao request compatibility remain absent |
| Operation/body confusion or ignored payload | exact per-operation body policy; init requires `{}`, unseal/KV write require a registered body, read/list/delete/seal/health surfaces require empty body; mismatch is audited before dispatch | full OpenBao endpoint-specific schemas remain H01-blocked |
| Path and normalization confusion | `/v1/` canonical target, no duplicate slash/dot/backslash/encoded slash, uppercase canonical escapes; Authbus compares against the canonical representation without allocating a second target string | Full upstream normalization corpus and cross-language vectors remain H01-blocked |
| Host/routing confusion | exactly one Host header; P0 requires exact bound loopback address | trusted proxy and cluster forwarding are out of scope |
| Slowloris or byte-trickle connection pinning | one absolute five-second request-read lifetime; every read receives only the remaining duration | production adaptive limits and distributed ingress enforcement remain absent |
| Non-reading peer extends response lifetime | one absolute five-second response-write deadline; every partial write and final flush receives only the remaining duration | production backpressure, cancellation and async runtime integration remain unqualified |
| Per-connection thread resource exhaustion | 32-connection admission bound; fallible `thread::Builder` creation; spawn failure releases capacity, audits and closes | P0 still uses one native thread per admitted connection and is not a production scheduler |
| Deadline bypass or stale request dispatch | deadline must be strictly after receipt; receipt/deadline/actual-dispatch monotonic checks | distributed deadline propagation remains future work |
| Secret leakage through derived Debug or Clone | request/response/assertion/identity types remove implicit secret copies; request registry, server state, canonical target, KV path, replay state and Authbus identities use redacted diagnostic views | public accessors and explicit application copies remain possible and require review |
| Secret residue in owned user-space buffers | canonical target/query strings, KV path strings, header values, request body, raw ingress buffers, rejected credentials, response body, rendered wire, Authbus digest preimage and unsigned signature payload execute explicit overwrite paths | compiler elimination, allocator copies, kernel buffers, swap, dumps and page reuse remain unproven |
| Audit bypass before mutation | body-policy and request audit are mandatory before dispatch; request-audit failure blocks mutation | production multi-device audit quorum is not implemented |
| Ambiguous retry after commit | post-commit audit failure returns committed=true plus recovery reference | durable idempotency ledger is not implemented in P0 |
| Audit path symlink attack | absolute create-new path and symlink/non-directory component rejection | pure-std path inspection has TOCTOU; descriptor-relative no-follow adapter required |
| Authbus assertion replay | bounded nonce cache check-and-record after signature verification | HA-consistent replay store and epoch fencing remain H21-WP12 |
| Authbus method/path/body confusion | length-prefixed digest binds request ID, method, canonical target, Host and body; local digest/signature preimages are cleared after provider return | provider retention and cross-language canonical-byte conformance still require independent evidence |
| Cross-process monotonic-time misuse | assertion validity uses Unix seconds with bounded skew | trusted time source and rollback monitoring remain deployment controls |
| Authentication confused with authorization | verified result can only carry `AuthorizationEffect::None` | policy/identity integration and red-team review remain required |
| Test provider promoted to production | production digest/signature provider is absent; test provider exists only under cfg(test) | candidate bakeoff, key custody and algorithm policy remain blocked |
| Automatic snapshot purges replay source | in-memory replay topology uses `SnapshotPolicy::Never`; manual snapshot cases remain | exact-head OpenRaft matrix must execute |
| Fixed leader assumed after process pause | bounded consensus-leader discovery after resume | true per-node process suspension remains external-lab work |

## Abuse cases

The following must fail closed: duplicate Host, body without canonical length, conflicting framing, malformed single-field JSON, raw unescaped quote, body on an empty-body operation, non-exact init body, encoded slash, unknown operation, equal/earlier deadline, expired request, byte-trickled request, non-reading response peer, connection-worker allocation failure, sealed secret access, missing/weak/equal development credentials, rejection-audit outage, request-audit outage, forged Authbus signature, key/issuer/audience mismatch, future/expired assertion, replayed nonce and any attempt to represent Authbus verification as authorization.

Diagnostic tests must prove that request targets, tokens, request bodies, KV paths/values, live request IDs, Authbus subjects, replay entries and canonical binding bytes are absent from safe `Debug` output. Source and exact-head tests must bind the controlled overwrite paths without representing them as compiler- or hardware-level zeroization proof.

## Residual boundary

P0 deliberately lacks durable storage, HA, TLS, namespace isolation, production authentication, lease/external-effect machinery and OpenBao compatibility. Successful local or CI execution cannot be used to protect real secrets. Independent security review, fuzzing, memory/side-channel testing, external storage laboratory evidence and authority remain mandatory.
