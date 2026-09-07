# heptabao-proxy

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded local proxy planning for request credential replacement, response filtering and HTTP header-smuggling defense. It does not open sockets, terminate TLS, pool upstream connections, parse request bodies or claim production proxy compatibility.

## Public API and ownership

`ProxyPolicy` owns request/response header allowlists, body-size limits and one upstream timeout. `plan_request` consumes caller headers and a server-side `SecretValue`, removes untrusted credentials and produces a `ForwardPlan`; `plan_response` applies the corresponding response boundary.

## State and data model

Header names are normalized to validated lowercase tokens. Header values are bounded byte vectors with CR, LF and NUL rejection and are zeroed on drop. Forward plans contain only retained allowlisted headers, body length and the configured timeout, not an open connection or reusable credential object.

## Invariants and authorization

Duplicate headers fail closed before forwarding. Standard hop-by-hop headers, every header nominated by `Connection`, and known credential headers are stripped. Exactly one server-generated `Authorization: Bearer` value is appended to an accepted request; client credentials never win precedence.

## Failure, retry and reconciliation

Policy, header and size errors occur before upstream entry. A transport failure after forwarding requires the client/operator unknown-outcome taxonomy and must not be retried merely because the local proxy lost the response. The generated timeout is a dispatch bound, not proof of non-entry.

## Concurrency and ordering

`ProxyPolicy` is immutable after construction and may be shared by an outer synchronization layer. Request headers are validated, de-duplicated, stripped and allowlisted before server credential injection; response credentials and hop-by-hop fields are removed before any downstream serialization.

## Security and privacy

Header-value diagnostics are always redacted and buffers are zeroed on drop. The proxy must run on a constrained local interface, obtain its server token outside process arguments, enforce TLS upstream, reject absolute-form or authority confusion in the transport layer and avoid forwarding tracing headers not explicitly allowed.

## Persistence and compatibility

No cache, cookie jar or durable format is defined. Header policy and transport behavior require explicit versioning if exposed as a stable product surface. Compatibility evidence must include duplicate headers, `Connection` nominations, credential aliases, size limits and ambiguous upstream outcomes.

## Observability

Recommended counters cover rejected duplicate headers, invalid header bytes, stripped credential fields, body-limit rejection, upstream timeout and outcome class. Header names may be reported only from a bounded approved vocabulary; values, tokens, paths and arbitrary connection nominations are never telemetry labels.

## Operations

Runbooks must address local listener ownership, upstream certificate rotation, token replacement, header policy rollout, timeout saturation and ambiguous request reconciliation. A configuration error should stop the proxy rather than start with an empty or permissive policy.

## Tests and executable evidence

`cargo test -p heptabao-proxy` proves attacker credentials are replaced, `Connection`-nominated headers cannot be smuggled, duplicate and oversized requests fail closed and debug output contains no header value. Strict workspace Clippy and rustdoc are additional current-head gates.

## Evolution and open boundaries

A real listener, TLS, HTTP/2 and HTTP/3 normalization, streaming limits, cancellation, upstream health, response body filtering and OpenBao proxy behavior remain open. Those implementations must preserve the credential and ambiguity boundaries defined here.
