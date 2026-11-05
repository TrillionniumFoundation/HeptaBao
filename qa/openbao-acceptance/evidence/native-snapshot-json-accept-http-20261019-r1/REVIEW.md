# Native snapshot HTTP Accept compatibility — R1

## Status and exact base

This is a local source repair and a frozen regression candidate. Rust compilation, the two actual HTTPS tests, the revised framing test, and the official full34 rerun are **pending**. Static source checks below do not count as those executions.

Base: `9770bdd4ca77aa832ec8083a054760637e92cfa1`, tree `f32f1acf9a794844719b6df225df3d23f2389e02`, 2,979 files. Manifest SHA-256: `9e167d20256e2d59c9ce57c73b90a0976403cf7a20db3e1d6b5de011c9d3cb0c`. Every locally cached base file was recomputed as a Git blob and matched this manifest.

Parent-reported results for the unmodified base remain distinct: physical Mac and main Linux each passed the original 55 cases and binary build; CI Linux passed 55; CI Mac passed 54 and failed one separate cold ReadIndex / peer-connectivity case. This patch does not resolve or relabel that separate CI failure.

## The actual full34 failure

The exact, unchanged Mac full34 summary is 69,757 bytes, SHA-256 `102ccd9df282c81fda246d42234eff2d9f1379630e3a627087d7afb5ee77e413`. Target binary SHA-256: `5d10aec72d0dcce2a7a78ba0a209d264fb173b739531d76231e3011b7d0f33aa`.

The original 31-check driver observed 21 checks: 20 passed and `snapshot_download` failed. The first 17 primary checks included the actual official raw export, import into active native storage, full historical API and precise storage-witness comparisons, and both comparisons after SIGKILL/cold reopening. Three cleanup checks also passed. Ten required later checks were never reached. The failed download returned the native ordinary-route rejection, with error `native candidate supports root ordinary KV and local seal observations`.

The summary's full34 and storage-precision qualification fields remain false because the required restored stages were not completed. The original driver remains byte-identical, SHA-256 `83d9436f321b380f44504829c426ccf5d3e52830b223f584a84d5237b9c2323d`. No flag is changed to enable HA, no failing check is removed, and no request is replayed by this patch.

## Exact cause and the official contract

The driver's normal HTTP client sends `Accept: application/json` on its GET snapshot request. The HTTP parser explicitly excluded that one Accept value when selecting the typed snapshot download. Consequently `begin_native_snapshot_before` was never entered, `native_snapshot_transport` was not set for admission, and native Service rejected the ordinary JSON route. This is a representation-selection error, not the observed capacity or request-deadline failure.

OpenBao v2.7.1 tag commit `a5db72cef75c24b920ade02065b18dd8eb666bac` provides the primary contract:

- [The exact API documentation](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/website/content/docs/api/system/storage/raft.mdx) describes GET `/sys/storage/raft/snapshot` as returning binary snapshot data and POST as consuming a binary archive. Git blob `99bf5294b90b4f044e3244b7b19263e093c3fb43`.
- [The exact logical handler](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system_raft.go) maps that ReadOperation to `handleStorageRaftSnapshotRead`. The handler calls `SnapshotHTTP` with the response writer and seal access; it contains no Accept-based JSON branch. Git blob `d18d66bc0ec259093e4b757f8d23e81be109d26b`.

These official files were retrieved by the parent and their raw byte hashes are recorded in `source-and-failure-evidence.json`. The old `vault/` and `http/` paths returned 404; this version uses `internal/`. `internal/http/sys_raft.go` is also recorded for retrieval provenance but contains bootstrap/join handlers and is not used as snapshot-contract evidence.

## Product change and preserved boundaries

Only one executable predicate changes, in `http.rs`: a native-wire GET/HEAD snapshot download no longer falls back to the bounded JSON lane based on Accept. The existing `download` route/method predicate, native-wire opt-in, help handling and body-framing checks remain. Binary uploads still follow Content-Type independently. The HTTP/2 adapter uses this shared parser. The explicit internal non-wire JSON parser retains its previous lane.

No Service, archive, durable, HA or driver code changes. The download now reaches the existing typed admission which still enforces the request's real Actor, root namespace, root-only snapshot authority, trusted clock, seal and current owner identity, original deadline, request and terminal audit, exclusive staging lease, actual archive validation, and terminal response ownership. Namespace/seal/permission errors are not changed to success. Snapshot-force semantics and pending-restore selectors are unchanged.

The three existing files change as follows:

| File | Change |
| --- | --- |
| `http.rs` | Remove the GET/HEAD Accept=JSON opt-out; register a fixture-feature/test-only HTTPS module. |
| `http_snapshot.rs` | Replace the prior framing test's incompatible JSON-Accept expectation with binary GET/HEAD selection; preserve ambiguous/chunked negatives and explicitly cover help, JSON upload, and the internal non-wire lane. Rename that test to describe its corrected assertion. |
| `http_api_alpn_tests.rs` | Make the existing synthetic TLS certificate fixture visible to the sibling test module. No existing ALPN test logic or product TLS configuration changes. |

The new file is `http_snapshot_accept_tests.rs`; it has exactly two new test functions and adds no dependency or Cargo feature.

## Meaningful HTTPS regressions

Each test creates a unique private directory and an actual Service with the production file backend and encrypted paged records. All initialization, unseal, policy/token creation, native activation, small lossless import, ordinary reads/writes, witnesses, seal and snapshot operations use actual loopback TLS requests through the production HTTP parser, parsed-request dispatch, Service and response writer. No Actor, snapshot plan, clock, archive response or API result is fabricated.

Each request has one original 15-second deadline shared by connect, TLS, parse, admission, archive/body I/O and final reply. The fixture's client verifies the synthetic CA and hostname, checks the negotiated ALPN/protocol and exact peer leaf, then parses bounded headers and reads the entire length-framed or chunked body. It does not accept a status prefix as successful delivery. The HTTPS request worker is joined even during assertion unwinding before its Service/directory can be dropped. Successful fixture cleanup is explicitly checked. These are in-process loopback HTTPS tests, not LAN/physical multi-host evidence.

### Success case

`http::snapshot_accept_tests::native_snapshot_https_json_accept_download_restore_and_cold_keep_exact_history`

A three-version imported history has a retained soft-deleted payload, destroyed version without payload, and live version. The exact decimal, wide integer, Unicode and literal backslash-u0000 payload has canonical length 134 and SHA-256 `8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395`. A separate ordinary HTTP write preserves numeric negative zero. A genuine non-root token is issued before native activation, establishing the real Token API precision owner involved in R4 restore.

The test reads ordinary API projections separately from the precise storage witness, downloads a complete binary archive with `Accept: application/json`, performs and observes a real CAS=3 write creating version 4, uploads the old archive as binary, and checks the restored API and precise storage. It closes the actual Service, opens the same data directory into a fresh Service, unseals through HTTPS, and repeats the history/negative-zero checks. A HEAD snapshot with JSON Accept retains binary media/length and an empty body. Snapshot spools are empty at completion.

### Refusal case

`http::snapshot_accept_tests::native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals`

Actual GET and binary POST requests with an absent token or a non-root policy token (including read/update/sudo) remain 403. A nonexistent namespace remains 404. These denials precede snapshot-spool allocation. A root upload of invalid gzip remains 400, staging is cleared, and the exact stored history is unchanged. A sealed Service rejects GET snapshot with 503; ordinary HTTPS unseal restores normal precise reads. Each snapshot call checks the actual audit file gained its request and terminal response entries before the complete client reply.

### Revised existing framing case

`http::snapshot::tests::binary_route_only_supports_chunking_and_snapshot_accept_remains_binary`

This replaces the old name `binary_route_only_supports_chunking_and_explicit_json_accept_preserves_old_download`. Its former JSON-Accept assertion encoded the incompatible behavior that caused the physical failure. Its rejection assertions remain and its parser budget remains one second.

## Execution handoff and denominator

The original 55 selectors and required counts are unchanged. None of the three selectors above is selected by those original groups. Run each as an additional exact single case against the newly identified candidate source; do not treat a zero-test filter or compilation success as a test pass. For the same feature set as the original physical runner, each command has this form:

```text
cargo +1.98.0 test --locked --offline -p heptabao-server --lib --features experimental-native-v6-ha,private-ha-forward-diagnostic <EXACT_FUNCTION> -- --exact --nocapture --test-threads=1
```

The feature-free single-node runtime is deliberate: `HttpsFixture` uses `Service::new` and `configure_native_v6_candidate`, never HA construction. The test module is also gated by `fixture-native-v6-service`, so it is available to the separately identified native-Service-only build.

Parent-owned formatting, build, actual test logs, and then the unchanged 31-check official full34 rerun must carry their own source identities. If the new HTTPS or restored full34 stage fails, preserve its actual body/log and investigate that specific failure. This candidate alone does not establish full replacement, HA qualification, per-host cutover or eligibility to remove OpenBao.
