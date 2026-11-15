# HeptaBao Agent renderer

This private helper evaluates bounded Go templates for the Python Agent's
managed-secret owner. Build with `cargo build --locked -p heptabao-agent-renderer`.
It accepts no command-line arguments, bearer tokens, network endpoint or output
path. The Agent supplies a template over stdin, handles explicit `secret` RPC
requests, and publishes the final output only after checking its original token
and lease authority again.

The Python owner in `clients/python/heptabao/templates.py` admits the configured
binary by SHA-256, copies it into a sealed Linux memfd, and executes that retained
image. The owner enforces pipe and process deadlines, private destination custody,
and expiry cleanup. The Rust evaluator's execution hook does not itself time out
a blocked stdin pipe; calling the binary without that owner does not provide the
full lifecycle contract. macOS template execution is currently unsupported.

See [API.md](API.md), [DESIGN.md](DESIGN.md), and the
[module guide](../../docs/modules/heptabao-agent-renderer.md).
Run `cargo test --locked -p heptabao-agent-renderer` for bounded parser, lossless
number, and real process RPC regressions. This helper grants no production or
OpenBao replacement qualification.
