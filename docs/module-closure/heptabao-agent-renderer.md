# heptabao-agent-renderer module closure dossier

## Design and state ownership

The package evaluates one in-memory template. The Python Agent owns the original
token, ManagedSecrets owns lease/outcome state, and Templates owns process and
sink custody. The helper retains no database, credentials file or durable receipt.

## Module boundaries and trust assumptions

The `heptabao-workflow-template` dependency supplies evaluation. Private JSON RPC
supplies explicitly requested values, never a bearer token or network endpoint.
The Python owner must admit the executable image, retain original pipes, enforce
deadlines and recheck authorization before publishing output.

## Failure semantics and ordering

Malformed, oversized, refused or over-budget evaluation fails with a fixed error
category. A result is data rather than an authority grant. Blocked I/O is cancelled
by the owner, which terminates and reaps the helper. No provider effect is retried
because a renderer failed or returned late.

## Acceptance evidence

**Named executable anchor:** `oversized_or_unterminated_rpc_cannot_become_a_request` in `crates/heptabao-agent-renderer/src/lib.rs`.

`cargo test --locked -p heptabao-agent-renderer` also exercises real child-process
literal rendering, private secret RPC, refused secret redaction and lossless
numbers. The source and result must be bound to the actual tested commit.

## Known gaps and evolution

Current Linux execution depends on sealed memfd support. The Rust hook alone does
not enforce a blocked-read deadline. Production compatibility, live secret
provider operation and cross-platform deployment are not qualified by these tests.
