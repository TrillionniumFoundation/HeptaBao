# Ownership and bounds

The Agent owns authentication; `ManagedSecrets` owns admitted subscriptions and
ambiguous-outcome fences; `Templates` owns the immutable executable, subprocess,
RPC pipes and private output directories. The Rust helper owns only the in-memory
template evaluation. It depends on the existing `heptabao-workflow-template`
evaluator and `serde_json` with arbitrary precision. It is outside the server's
runtime dependency closure.

Credentials arrive only as explicitly requested secret values over private pipes.
The helper cannot fetch arbitrary network resources or choose a destination.
Its result is data, not an authorization receipt. Immediately before and after
publishing a sink, the Python owner checks original token generation, lease
authority and deadlines. A background expiry check removes published sinks when
known authority ends. Ambiguous issuance is fenced rather than retried.

Frame, source, output, step, range and secret-call bounds reject malformed or
oversized work. Exact JSON numeric strings survive the evaluator value boundary.
The original process owner provides cancellation for blocked I/O and kills/reaps
the helper if its deadline expires. Secret-bearing strings are not guaranteed to
be immediately erased by Rust/Python allocators; no stronger erasure claim is made.
