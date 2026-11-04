# Native fresh-ingress observer: explicit Result error type

This is a new source-only proposal based on diagnostic commit bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24 (tree ac4027db88fec69381ea0c6bba953d9a99c4e82a). The main PR commit 6d3040a2dbd06661a67f5c62df259ff446eb8515 is not changed by this packet.

## Actual failure

The one authorized normal build, job 1a1a87f578a-fc05-2ee0, terminated with Cargo exit 101 in 62.09384498698637 seconds under the original 1800-second release-build cap. Its controller terminated exit 1. All owned processes were reaped with no remaining process-group members. No tests ran and no new binary is qualified.

The complete stderr contains 27 E0277 errors and one E0308 error. The latter explicitly reports that the new closure result was inferred as Result<Option<NativeV6IngressRead>, str> at the borrowed Err match, while the function's unchanged signature requires Result<Option<NativeV6IngressRead>, String>. This is a compilation failure in the newly added observer wrapper. It does not explain the earlier Phase B HTTP 503 and does not turn that earlier unknown operation into a known outcome.

## Exact change

Only the local binding's type is added:

```rust
let result: Result<Option<NativeV6IngressRead>, String> = (|| {
```

The explicit type is identical to the containing function's existing return type. It gives each original question-mark expression the existing String error target, rather than allowing the observation match's borrowed reason to drive an unsized str inference. Every function call, permission check, argument, question-mark operator, observer step, refusal, completion branch, returned value, deadline and cleanup action remains byte-for-byte unchanged.

This packet has not been formatted or compiled on a host. A source-only peer review is not a compiler result. The failed bf0 build and its directory must remain intact; any successor requires a new source identity, a fresh build root and a new key after parent review. The already reviewed runner and its original 44 tests plus seven separately recorded existing ingress/timing tests should be retained with their original caps. The seven tests were not run in the failed build and are not newly invented substitutes for the 44.

## Evidence and limits

Complete Cargo stderr: 27914 bytes, SHA256 d47156c8828983229eccec58c9a4cd5f1535b653c7d59fab9ddf4db72839ee3e. Complete Cargo stdout: 384196 bytes, SHA256 324a6b59e740e1ed2dc0c447ce638557d5cbd53cdec2c5b3afaa0a701cee3c92; its final build-finished record has success=false. Both were read from fixed version-pinned files after the job terminated. No compiler or product was restarted during evidence collection.

The actual source stage and admission fences qualify their recorded observation intervals. This packet does not invent a final post-failure source/old-artifact rehash absent from the failed controller's receipt. Later successor preparation must explicitly bind the retained failed source, logs and receipts as fences.
