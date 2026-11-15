# KV2 API number projection and exact native storage witness — r1

## Status and source identity

This is a locally reviewed, uncompiled candidate. No Rust compiler is available in this scratch environment. The parent owns GitHub persistence and all Mac, X230 Linux, CI and LAN execution. This report records source work and the observed OpenBao oracle; it does not record any new passing Rust test or complete replacement result.

The product overlay is based on commit `ee53a4039c5b60a06e26b4505f29d17bd3d66050`, tree `10584bab7747671aed8346127e5baa3519c6d95a`. Every existing input Git blob was also compared successfully with the independent exact manifest for `22cdbc19679cceffe082c6ced8b8e8bb7567058e`, tree `c4b3c4e6d81ba80c889433bd8baaf722faa838b1`; all new paths were absent there. `source-manifest.json` contains the before and after SHA-256 and Git blob for every file.

- Product overlay: `numeric-witness-r1-overlay.json`, 801697 bytes, SHA-256 `3b23947373f85b07d6dffe31bad0805cefe8ff10e532fa2a787a817685d2b94e`.
- Product patch: `numeric-witness-r1.patch`, 58805 bytes, SHA-256 `ccea92bdf4c8acafab461c9be7b1e6cf8f4460c1d90a508b9f69b5898d3ac9e8`.
- Separate existing-test adaptation: `../numeric-tests-r1/numeric-tests-r1-overlay.json`, 58655 bytes, SHA-256 `7b1415c4f067243129a20dd8a362e5256a3923498f9b55976cec8dd68b94332a`.
- Separate existing-test patch: 8010 bytes, SHA-256 `292afd26ec7a0540db1fb877a7cd16158853e6e088883b575fa06c42e143c177`.

The test adaptation has an explicit dependency on the product overlay. It retains the same 17 test function names in its three files, with no new cases or changed deadline values. Other existing large-HTTP cases are untouched. The parent’s prior 43-case suite gains eight new cases, for a planned total of 51; an actual executed denominator must be read from the subsequent runner logs.

## Observed OpenBao 2.7.1 oracle

The independent Mac diagnostic observed the following separation:

| Input/raw value | Public KV2 GET value |
| --- | --- |
| `9007199254740993` | `9007199254740992` |
| `0.123456789012345678901234567890` | `0.12345678901234568` |
| `1.0` | `1` |
| `-0` | `-0` |
| `1e-6` | `0.000001` |
| `1e-7` | `1e-7` |
| `1e20` | `100000000000000000000` |
| `1e21` | `1e+21` |
| `1e400` | POST returned 400; subsequent GET returned 404 |

The wide-integer/long-decimal diagnostic also read the original protobuf payload and confirmed the exact original values. Its projection file is `../actual-mac-numeric-projection/projection.json`, 12685 bytes, SHA-256 `9d46e5113eff82506ab1bc410ca86290410317b9786cdf76c5aec5a5c3e4d825`; its controller receipt is 854 bytes, SHA-256 `94f6ac138d9b55b228d917df35afaed988785032010a5587643f31ffd5fd138e`.

The seven-boundary diagnostic is `/workspace/scratch/915e5e680008/continuation-20261019/numeric-boundaries-actual-r1/summary.json`, 14333 bytes, SHA-256 `1281990796a3be2fc0064f0ffcb7fd2696b6bb7bf800e886e2534120e087481d`. Its controller receipt is 963 bytes, SHA-256 `6247db22303e34d8c21ec7022ad7d57c47269561e04c06d442b9f3c14fa016aa`. All 17 requests have definite responses, with no mutation replay. Its tail raw-record extraction failed with KeyError and `diagnostic_complete=false`; therefore those seven observations establish API behavior only. The parent/host agent’s independent read-only raw follow-up remains separate evidence.

The observed response behavior matches binary64 conversion and Go encoding/json formatting. The local implementation uses that inference and the primary Go formatter contract; no unseen OpenBao Go implementation is presented as directly inspected.

## Product changes

### API response projection

`engines/kv.rs` invokes the new `engines/kv_api_numbers.rs` only when rendering a readable KV2 data payload. Both ordinary and native point reads reach this constructor. Metadata integers, configuration, timestamps, subkey structure, KV1, global JSON decoding, owner storage, lossless import and snapshot serialization do not pass through it.

The projector creates a separate secret-owned response copy, recursively converts numeric values to finite binary64 and emits the shortest Go-style token: fixed decimal in `[1e-6, 1e21)`, scientific notation outside that interval, a signed positive exponent, and no padded exponent. Private serde-looking user object keys remain ordinary keys. The exact stored value is never overwritten by projected values.

For the single constant valid token `-0`, the implementation uses the pinned arbitrary-precision `serde_json::Number::from_string_unchecked` constructor. Parsing that string through serde’s generic Value serializer would otherwise turn it into integer zero. The completed projected Value is moved directly into the EngineResponse. A real Service regression checks its final response serialization before and after cold/snapshot recovery. This constructor is public but documentation-hidden in serde_json 1.0.151: the pinned dependency and actual build remain a material verification requirement. No user-controlled string reaches this constructor.

The current repository’s existing lossless decoder already canonicalizes some lexical forms, including raw `-0` into a stored signed floating token and positive exponents with an explicit `+`. This change preserves those existing stored number tokens; it does not promise byte-for-byte retention of the original JSON document’s whitespace, exponent spelling or key order. The exact wide integer and long decimal numeric tokens remain unchanged. The witness hashes the current lossless canonical value, not the original external document text.

Ordinary KV2 POST/PUT/PATCH validates newly supplied numbers after CAS validation and before a version/metadata entry can be created. Binary64 overflow returns 400 without a mutation; finite tokens are not normalized on storage. Lossless import remains able to retain exact out-of-range values. Public rendering of such an imported out-of-range value fails closed with 500; there is no direct source-oracle claim for this artificial imported-overflow GET case. Product tests separately cover the official ordinary POST 400/GET 404 behavior and storage atomicity.

### Single-version native witness

The feature-scoped route is `POST /v1/sys/internal/storage/kv2-version-witness`. It accepts only `{"mount":"secret","path":"history","version":3}`: an explicit positive integer version, bounded canonical mount/path, no force or extra body fields, root namespace and no response wrapping. HA is explicitly refused before forwarding. The implementation is an internal migration/recovery evidence profile, not an OpenBao compatibility endpoint.

The normal parameter ACL runs before dispatch. The same admitted Actor must then pass sudo before any selected mount or payload is inspected. The affine delivery capsule retains the original Actor, RequestClock, deadline, admitted Auth bytes, source root and typed publication generation, physical data directory, on-disk seal, unseal activation nonce and barrier digest.

The point read uses the actual scoped NativeSource and existing authenticated payload descriptor reader. It validates the native root, installed owners, encrypted payload address/AEAD closure, and original gate. Soft deletion does not erase the retained payload: the witness reads it directly from its authenticated descriptor without undeleting or manipulating time. Destroyed history must have neither a descriptor nor hydrated data. Only metadata, a SHA-256 and byte count are returned; plaintext is erased after hashing.

Canonical profile `heptabao-lossless-json-v1` uses compact UTF-8 JSON, recursively sorted object keys, original array order, standard JSON string encoding and the existing exact stored number token. The independent Python vector in the tests is 134 bytes with SHA-256 `8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395`.

The capsule is consumed by the usual mandatory terminal audit. A legitimate terminal clock-floor change is recognized only by its affine receipt whose exact before checkpoint matches this read. The response’s `source_root_sha256` and `source_publication_generation` continue to name the actual read source; they are never relabeled as the later terminal root. Delivery rechecks the original Actor/time and current root/owner/ciphertext custody. Any owner/nonce, policy, token expiry, deadline, seal or unrelated publication change withholds the hash and returns 503. A delivery veto records a negative audit; audit failure fences the service. No fresh authentication, request budget, automatic retry, restore, cancel or business publication is introduced.

## Test scope and remaining execution

New exact function names:

- `kv2_api_271_overflow_write_is_atomic_while_imported_storage_stays_exact`
- `kv2_api_271_rounds_response_numbers_without_changing_stored_tokens`
- `kv2_api_271_uses_go_float_notation_and_keeps_metadata_integers_exact`
- `native_kv2_storage_witness_canonical_profile_matches_independent_python_vector`
- `native_kv2_storage_witness_reads_retained_soft_delete_and_rejects_torn_payload`
- `native_kv2_storage_witness_service_import_cold_and_snapshot_keep_exact_payloads`
- `native_kv2_storage_witness_service_original_actor_expiry_after_audit_withholds_hash`
- `native_kv2_storage_witness_service_rejects_scope_parameters_and_terminal_owner_change`

Use explicit native/private feature settings from the parent’s current scoped runner. Filters `kv2_api_271_` and `native_kv2_storage_witness_` must execute exactly three and five cases respectively. Do not infer success from successful compilation or a zero-match filter.

The five witness cases include the independent canonical vector; real paged descriptor/objects with soft-delete, destroyed absence and a removed required block; actual FileBackend Service import/cold/snapshot/cold recovery; parameter/sudo rejection before payload AEAD reads; and a Service owner nonce change or real issued-token expiry after a successful terminal audit that must withhold the hash. Test-only hooks are single-thread-local and one-shot; RAII clears them on unwind. The issued-token case waits within its original 15-second test request scope, without changing any production deadline.

The separate three-file adaptation changes public API expectations to explicit independent constants. It also calls the actual root-authorized witness for each full34 version, after undelete, and for imported small history; expected hashes bind the unchanged exact source fixture. Deleted values must cause a real encrypted payload read, destroyed values must not. Metadata, private-name objects, graph identity/capacity and all existing veto assertions are retained.

Still required: actual Mac/X230 builds and execution of the complete combined candidate; transport-level oracle checks; the controller’s import/cold/snapshot witness comparisons; and all still-open HA, AuthBus and cutover gates. HA witness refusal is a source contract here, not a newly executed multi-machine proof. Nothing in this candidate permits claiming full OpenBao replacement or deleting old services.

## Primary technical sources

- Go encoding/json encoder source: https://go.dev/src/encoding/json/encode.go
- Exact serde_json 1.0.151 Number implementation, including the documentation-hidden arbitrary-precision constructor: https://docs.rs/serde_json/1.0.151/src/serde_json/number.rs.html

Runtime OpenBao statements above are bound to the local observed receipts, rather than inferred from a documentation version label.
