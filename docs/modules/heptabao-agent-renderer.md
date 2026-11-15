# heptabao-agent-renderer

Status: `IMPLEMENTED_REVIEW_REQUIRED` / V3. Shared rules are in
`docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`; see the
[module closure dossier](../module-closure/heptabao-agent-renderer.md).

## Purpose and non-goals

Evaluate one bounded Go template for the Python managed-secret Agent. This
helper is neither a secrets server nor a network client, persistent lease owner,
general process executor or independently authorized credential provider.

## Public API and ownership

`crates/heptabao-agent-renderer/Cargo.toml` declares a library and executable.
`run_stdio()` in `src/lib.rs` returns an exit code for one framed session. Its
direct internal dependency is `heptabao-workflow-template`; the Python Agent,
ManagedSecrets and Templates retain authentication, lease, process and sink owners.

## State and data model

An initial newline-delimited JSON frame contains template source and a timeout.
During evaluation a private `secret` request receives owner-supplied JSON data.
A final result contains output and counters. No state survives process exit.
Frames are at most 1 MiB; source and output are at most 64 KiB each.

## Invariants and authorization

No token, network address or destination path is accepted by the helper. Secret
lookups require the external owner's exact configured route and original token
authority. A successful rendered result does not authorize sink publication.
Numeric JSON values are kept lossless across the evaluator boundary.

## Failure, retry and reconciliation

Parse, budget or owner refusal produces the fixed `template_render_blocked`
category and an unsuccessful exit. The Python owner withdraws the affected sink.
An ambiguous secret issuance remains fenced in ManagedSecrets; rendering cannot
convert an uncertain provider outcome into permission to replay it.

## Concurrency and ordering

One process evaluates one template and exchanges ordered frames over its original
pipes. Execution steps, range iterations and secret calls are bounded separately.
The outer Python owner bounds blocked pipe I/O, then terminates and reaps the same
process on timeout. The Rust clock hook alone does not cancel a blocked pipe read.

## Security and privacy

The Linux owner verifies and seals a memfd image before execution, preventing a
path replacement from changing the admitted executable. Diagnostics contain only
fixed failure categories. Plaintext values remain in ordinary process memory;
the implementation does not claim guaranteed immediate string erasure.

## Persistence and compatibility

The helper owns no persisted format. Its JSON lines form a private, unversioned
protocol paired with `clients/python/heptabao/templates.py`; unknown public-client
compatibility is not implied. Linux sealed-memfd support is required by the owner;
macOS template execution fails closed as unsupported.

## Observability

Success reports bounded `secret_calls` and `steps` counters. The owner maintains
rendered, changed and blocked counts without publishing secret payloads. Failure
does not print template input, response bodies or credentials to diagnostics.

## Operations

Build with `cargo build --locked -p heptabao-agent-renderer`. Configure the Python
Agent with the resulting absolute binary path, digest, explicit managed routes,
private template sources and private destination directories. Use the Agent owner
for execution; direct invocation lacks its timeout and sink lifecycle guarantees.

## Tests and executable evidence

Run `cargo test --locked -p heptabao-agent-renderer`. The
`oversized_or_unterminated_rpc_cannot_become_a_request` unit scenario checks hostile
framing; process tests cover literal output, private secret RPC and redacted refusal.
Run Python client discovery for cancellation, substitution and sink-expiry tests.
Environment-denied AF_UNIX tests remain distinct from passes.

## Evolution and open boundaries

This integration restores a detached client feature without changing server cert,
quota or HA ownership. Actual managed provider deployment, macOS template support,
and full production qualification remain separate work. The package has no
compatibility or release authority merely because the source is merged.
