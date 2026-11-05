# Normal cold-native timing: single-file source candidate

Exact base:49503322c7f446e5eb41e7744f1fdbd7f1192ecc, read.rs a1de3065d7883b4b1943d794756e182f1a2ce708. Only this source file changes. The normal fixed ColdNativeHaPhase enum feeds the existing bounded timing observer. Every original operation is evaluated once and its original Result returned; gates, original deadlines, error responses, owner/witness/cursor checks and recovery branches remain.

The whole cold load gets a typed timing scope. Source acquisition and inner install/repair results are distinct, and the first recoverable materialization result is separate from the final rematerialization. There are20 fixed labels, no dynamic label/data output, no new source reads or product operations. The warm proof tail is byte-identical. Original private diagnostics remain unchanged.

The observed stopped-log line178 completed a committed-read context with remaining time, but has no request ID. This candidate addresses the unobserved cold path after that kind of read result; it does not prove a cause for the original node2 unseal503. The failed business run stays91/98 with postcold0/12 and is not replayed.

Eight actual source-text checks passed. They do not compile Rust or prove lifetimes/runtime behavior. The first harness's mistaken whole-file single-occurrence expectation and a later output-truncation event are retained. The candidate is unformatted, not built, not tested as product, not pushed to a branch and not dispatched. The proposed validation plan requires independent normal-source qualification; it inherits no prior CI or runtime results.
