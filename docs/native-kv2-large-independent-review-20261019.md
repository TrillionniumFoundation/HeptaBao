# Full34 native-large HTTP and parser independent review

This is a source review, not a compile or runtime pass. No remote machine, credential, listener, cargo cache, repository branch, or production source was changed during this review. The frozen full34 r1 files were read locally; AuthBus owns the subsequent product deltas. Root owns integration and actual validation.

## Source identities

Reviewed base: `/workspace/scratch/915e5e680008/kv2-full34-r1-20261019/work/`, derived from the full34 r1 overlay on the parent-provided 741 source baseline.

| Relative server source path | Reviewed r1 Git blob |
| --- | --- |
| `http.rs` | `d739c31c9c37b4423f3137a12bdda0da9cdbd60d` |
| `http_snapshot.rs` | `b801da57ad951b2242e212297074847f7a51e107` |
| `http_h2.rs` | `6ec729b935e75c16cb01f3e5fdec2c549faa7a2e` |
| `http_native_kv2_large.rs` | `7f0934e2ad340135667802d6878f35a160c30d2c` |
| `engines/kv_lossless_native_large.rs` | `3837db004a47cf868527994ae06bfa1ce98d168e` |
| `engines/kv_lossless.rs` | `d7182ed6f2dc39d5bd730de5b307125dfad0bb81` |
| `service_native_kv2_large.rs` | `a1dbc13bb27ad6eec4113978a91f9401547da6df` |

Reviewed subsequent HTTP-only delta:

- File: `/workspace/scratch/915e5e680008/kv2-full34-r3-20261019/native-kv2-large-r3-overlay.json`
- SHA256: `313a23a9a0496d3f9e33e6d4fb02cda0017dc36fb857acf05acb9839edb6f7bd`
- `http.rs` resulting Git blob: `6d6a52bc87f4a8c954e71391b9638ce73e390d8e`
- `http_native_kv2_large_tests.rs` resulting Git blob: `278f6c9efc0af116fca59cef5dd10fc794c9c651`

Both r3 files were recomputed from their supplied UTF-8 content. Their byte counts, Git blob identities, and declared SHA256 values match. Their expected base SHA256 values match the frozen r1 files. The complete diff contains only the scoped query branch and extensions to two existing HTTP tests; the number of tests is unchanged.

## Definite defect found and addressed in r3

The original `merge_query_fields` whitelist had no `mount` field or native-large exception. Every documented positive request of the form `POST /v1/sys/migration/openbao/kv2/native-large?mount=secret` therefore failed with HTTP 400 before reaching Service admission. The positive header test and the Service tests that use `upload_http` would encounter that same route failure. This was reported to root and the owning AuthBus agent before the next real compile.

The independent review of r3 confirms that its exception is scoped to the native fixture feature, POST, and this exact logical path. It accepts exactly one nonempty `mount` string of at most 1024 bytes. Numeric-looking and boolean-looking mount names remain strings. Unknown fields, duplicate fields (including percent-decoded duplicates), and an existing body object are rejected. The global whitelist was not expanded.

The larger wire budget remains selected separately by the original exact raw path, POST, native wire mode, feature, and dedicated media type. The query fix does not grant encoded route aliases, ordinary JSON requests, or unrelated paths a 64-MiB body budget.

## HTTP framing and prebody observations

- The ordinary HTTP JSON limit remains 2 MiB. Its existing scoped canonical KV2 write exception remains separate. The domain JSON decoder's ordinary 16-MiB limit was not changed.
- The new wire lane uses a positive Content-Length at most 64 MiB. It rejects missing or invalid lengths, duplicate headers, Transfer-Encoding (also when combined with Content-Length), and Expect. The early framing rejection path does not drain a large rejected upload.
- The header loop can retain a bounded body prefix from the same 4096-byte read as the header delimiter. It does not read the remaining large body before Service admission. This is a bounded prefix, not evidence of zero bytes ever being received from the socket.
- Unknown consistency metadata and excessive Content-Length preserve the deferred lane's early refusal. A wrong media type, method, trailing slash, or route suffix does not obtain the large lane.
- `BodyReader` preserves the original deadline before and after reads, limits each read to the remaining declared length, and rejects premature EOF. Its constructor rejects a buffered prefix longer than the declared body and rejects chunked/zero/excessive lengths. This constructor is called after admission, but no graph publication follows invalid framing.
- The deferred executor acquires the Service writer for admission, returns an immediate refusal without reading/draining the large body, and performs the upload only for a real External plan. It reacquires the writer under the same deadline and finalizes the same pending request once.
- The HTTP/2 implementation rejects this dedicated unsupported route before its body-data loop. It does not obtain the native-large budget by falling back to normal H2 JSON parsing.

## Strict parser observations

- `NativeLargeBundle` is a private proof type; arbitrary request bytes cannot select a decoder budget by adding a JSON field.
- Its validation-only token visitor checks decoded duplicate object keys at every nesting level. The explicit bounds are 64 MiB for the whole bundle, 4 MiB per record, 1,048,576 structural nodes, and depth 128, in addition to the existing entry/version/retention limits.
- The decoder consumes a single JSON value and then checks end-of-input. The closed outer import schema still rejects unsupported fields. Existing lossless validation retains version numbering, history completeness, timestamp, metadata, and destroyed/deleted value rules.
- Each actual KV payload goes through the existing domain decoder during projection. The large profile does not substitute a generic serde Value conversion for the token-preserving path. The tests explicitly exercise a wide integer and an object whose key is `$serde_json::private::Number`.
- The original deadline check is carried into validation and native graph construction. Byte and structure bounds also cover a single large scalar that cannot yield at every byte. I found no source path from a malformed or deadline-expired bundle to an accepted publication in this scoped review.

## Additional concrete authorization ordering observation

AuthBus independently pointed out, and I confirmed in the r1 source, that `stage_native_kv2_large` checks native/pristine destination state before `TransferPlan::authorize` performs its sudo check. Ordinary Actor and parameter ACL checks already occurred in `handle_inner`. The upload lease and large body allocation still occur only after sudo succeeds.

The remaining difference is that an Actor granted update on this migration path but lacking sudo can distinguish destination or native-state errors before receiving a sudo refusal. This is not a demonstrated body-read or publication bypass. A narrow correction is to perform the same observed-time sudo check immediately after validating the mount query, retaining all existing plan and terminal authorization checks. A meaningful regression can extend the existing refusal case: a real update-only Actor aimed at a nonpristine mount must get 403 and leave body-read count zero. AuthBus and root own the decision and implementation; no extra product file was edited here.

## Required runtime evidence and current limits

The local review environment has no Rust compiler. No test count or runtime result is inferred from the source review. Root must retain the actual combined source identity and run the existing three HTTP tests, three codec tests, the full34 Service cases, and any terminal Actor additions under the real feature set. Full34 remains a single-node native import profile; this review establishes no HA large-upload contract and no multi-host migration result.

The separate recovery r1 three-file overlay remains frozen and unchanged. Its new cold-unseal diagnostics have not yet established the Linux failure cause; that repair remains pending the real diagnostic output.
