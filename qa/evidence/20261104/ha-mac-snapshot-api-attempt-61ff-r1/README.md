# New isolated snapshot API integration attempt

This is a new 2400-second attempt after the prior job reached its original deadline and all owned children stopped. The old failed result, strict green and zero executed tests remain immutable. It does not extend that attempt.

Source a20dbd15e3b2fd7e828949b937d1d5da75588620, tree 6046535302a94418d8bc67b65887f68d2d690062, builds on the physically frozen c6a0 / same-tree review a40 candidate. Twenty-one exact source pins include eleven changed paths: actual API TLS fixture and wiring, the independently reviewed unsupported-owner fixtures, two migration-process cleanup repairs, and one exact invalid-gzip literal expectation.

All three API addresses are actual bound, separate loopback TLS sockets before HA startup; configured certificates match the original cohort pins. Requests use the production HTTP parser, Service admission/finalization and writer. Cold restart rebinds the same address. The original missing-API fixture remains a refusal test. This is a component fixture, not production serve or physical LAN qualification.

The controller checks the previous terminal result and cleanup, current source and toolchain pins, a fresh output directory and target release lock. Preparation, strict Clippy, normal libtest compilation, fourteen named tests and normal server/seed linking share one fixed 2400-second deadline. Only each exact Cargo test artifact is used. Known negative cases are retained while the remaining named cases run once; unknown, timeout or failed cleanup stops. All fourteen must pass before production build qualification.

The six observed ordinary KV / consistency 307 differences remain unimplemented here. The fixed official archive oracle also accepted footer truncation and concatenated archives with a real restore, so the old archive rejection test is not silently changed to green. Full workspace, all 34 normal-wire comparisons, physical failover/restart, full migration/recovery and cutover remain separate gates.

No production service or production state is modified. This package has not executed; the compile-only request must first produce a successful pinned syntax receipt, then the execute request is reviewed against that exact input.
