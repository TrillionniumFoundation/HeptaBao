# r1 additive evidence — numeric source lexemes and canonical witness

This addendum supersedes only the earlier report's statement that the seven-boundary raw follow-up remained incomplete. The frozen product/test overlays and patches are unchanged. It does not add a HeptaBao compile or runtime success claim.

## New actual source evidence

The independently executed Mac OpenBao 2.7.1 read-only follow-up completed successfully. I locally read and verified the exact receipt hashes:

- Summary: `/workspace/scratch/915e5e680008/continuation-20261019/numeric-raw-actual-r1/summary.json`, 62684 bytes, SHA-256 `4102fe44bfefb5901f0ae3221955ef50630a39bd9680f4f23b9730988640e36b`.
- Controller: `/workspace/scratch/915e5e680008/continuation-20261019/numeric-raw-actual-r1/controller-receipt.json`, 1039 bytes, SHA-256 `a5be87a9305ce05f5b62017dd8560512734950d4af3bf0c412914c73474c17cc`.

There were 85 GET/LIST requests, each with a definite response, no retries and a completed owned process wait. The decoder acquired 21 raw records twice with identical results. It selected the actual config root one relative level below the former assumed mount root and found the salt there. The controller records zero source writes, clone stopped, and all 19 original fixture files unchanged. The observed version is 2.7.1 and the cluster matches the preceding numeric diagnostic. `migration_qualified` remains false: this source-only diagnostic does not qualify a target migration.

| Input numeric token | Earlier write status | Re-read API token | Exact source protobuf token |
| --- | ---: | --- | --- |
| `1.0` | 200 | `1` | `1.0` |
| `-0` | 200 | `-0` | `-0` |
| `1e-6` | 200 | `0.000001` | `1e-6` |
| `1e-7` | 200 | `1e-7` | `1e-7` |
| `1e20` | 200 | `100000000000000000000` | `1e20` |
| `1e21` | 200 | `1e+21` | `1e21` |
| `1e400` | 400 | 404; absent | No payload or metadata record |

The six accepted numbers each have `raw_number_same_lexeme=true`. The overflow case has no raw payload and no metadata record. It is an intentional rejected-write case; its generic `api_case_matches=false` field is not a value mismatch because no API data object exists, while `api_matches_prior=true` and `rejected_write_has_no_raw_state=true` bind its expected absence.

## Three distinct contracts

1. **Public API projection.** OpenBao GET may round a stored precise number and change its spelling. The candidate reproduces the empirically observed binary64 projection at KV2 response construction. Exact storage is not replaced by that projection.
2. **Exact canonical target value.** `heptabao-lossless-json-v1` hashes compact UTF-8 JSON with sorted keys and each number's current exact stored token. It preserves numeric precision, signed zero and the actual retained payload representation across target cold/snapshot recovery. The supplied wide-integer/long-decimal fixtures and independent 134-byte Python vector are bound exactly. The controller must not silently switch this hash to a rounded API value.
3. **Source text token.** The official raw protobuf preserves the six source spellings above. That is stronger than mathematical decimal equivalence or matching public API output. The unchanged HeptaBao domain decoder already represents raw `-0` through a signed floating Number and normalizes positive exponent signs. Consequently source `1e20` versus stored `1e+20`, or source `-0` versus the existing signed floating token, can have distinct hashes despite preserving the number/sign. The candidate does not alter this global decoder and cannot establish byte-for-byte source-token preservation for every possible JSON number. Original source raw receipts/backup bytes must remain separate evidence.

The current witness profile is deliberately not a general mathematical JSON canonicalizer: it preserves the stored decimal token, including the long decimal's trailing zero in the supplied vector. A future source containing exponent-case/spelling variations requires an explicit, independently verified mapping to this profile or a separate token-preserving storage design. Neither the completed source-only raw diagnostic nor a successful target wide/decimal witness may be described as closing that broader lexical round-trip claim.

## Pinned Number constructor review

Exact primary source https://docs.rs/serde_json/1.0.151/src/serde_json/number.rs.html shows `Number::from_string_unchecked(String)` is callable with `arbitrary_precision`; it stores the string directly. Its documentation explicitly excludes it from the stable public API. Both existing ee5 CI logs record compiling serde_json 1.0.151. This is source/dependency evidence, not execution of the new caller.

The candidate passes only the constant syntactically valid token `-0`. It introduces no unsafe block and does not bypass validation of user number strings. Number-to-Value reserialization can normalize that token again, so the code moves the projected Value directly into the response and the existing new tests assert final serialization through ordinary KV2 and actual Service import/cold/snapshot flows. Runtime transport still needs its own check. The constructor could disappear or change on a dependency upgrade; the pinned source and real build/tests must remain bound to the result. Static inspection cannot substitute for those build and semantic tests.
