# H2 source successor: current product 4e808, qualified instrument df026

This packet changes the Python fixture's source identity checks. It does not run the fixture, move a ref, rebuild the Rust client, copy artifacts, or qualify the current product. The full QA instrument build is separately completed and accepted; the current Linux product, desktop source, transports and fixture still require their own actual admissions.

## Why the split is required

The original binder used one COMMIT/TREE pair for the server, the client build receipt and the client JSON report. The Rust executable actually contains df026/424463 constants. Changing that shared pair to 4e808/eba5 would reject the already built instrument. Keeping it at df026 would carry the old product requirement into a current-product fixture. The old binder also compared its historical QA-build normal-result SHA with the fixture's current combined product result. That comparison has the same coupling problem.

The new code has exact, separate PRODUCT_COMMIT/TREE and H2_INSTRUMENT_BUILD_COMMIT/TREE constants. It never accepts either identity interchangeably. The binding, input proof, prepare and controller schemas are v2; the independent Rust request/report protocol remains v1 and its source is unchanged.

| Field or check | Exact meaning in this packet |
| --- | --- |
| Binding candidate_commit / candidate_tree | Current server product: 4e808d0ecb1bcded22870a7ec960dfb2491cf6ec / eba5e650bd080b8ad41ea52a2bc68867f541d255 |
| Binding instrument_build_commit / instrument_build_tree | Previously built QA instrument: df026fe323dd7cf0f0ec57d7d2d9c5a79897053c / 424463ccd2310ddc1e7b2bbcd7b7af29ae58c825 |
| Native/release/combined product receipts, clean Git source | Must match current PRODUCT constants; combined schema is linux-normal-same-root-publication-exact-tests.v1 |
| QA build candidate_commit / candidate_tree, source_before / source_after and original build binding | Must match H2_INSTRUMENT_BUILD constants |
| QA build normal_product_result_sha256 | Historical tool-build prerequisite only: exact 48,188 B normal60 result 84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b, runner 1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40 |
| Rust response report candidate_commit / candidate_tree | Compile-time instrument identity, checked at the actual driver response predicate against H2_INSTRUMENT_BUILD constants |
| Final controller candidate_commit / candidate_tree | Current product; instrument_build_commit / instrument_build_tree are separately reported |
| Verified inputs independent_h2_qa | Instrument build/lock/source/six-component proof only; explicitly no HTTP or product qualification |
| Verified inputs product_test_qualification | Current product receipt/runner and separate 44, 7, 9, 1 groups; total 61 |

## Current product admission

The original 44 test groups, seven ingress tests and nine cold/H2 tests retain their exact lists, receipt checks and group caps. The aggregate now requires 61, original_60_test_total 60 and original_60_status passed. A separate same_root_publication_regression object must pass its exact schema, sole testcase, independent 600-second group clipped to the original outer deadline, recorded exit/timeout/reap/remaining checks and exact current runner SHA 93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be.

The additional exact name is:

`service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors`

The eight existing product-file pins are unchanged blobs in the exact 4e808 tree. The packet includes the commit, four parent tree responses and an independently recomputed membership proof. This is exact membership for these eight pins, not a new full-tree source-import qualification. The future standalone source import remains responsible for the full canonical source closure.

The four current product slots (server, native receipt, release receipt, combined61 receipt) remain null. The original groups file has its unchanged known content pin. No df026 server or normal60 receipt is substituted into those current-product slots. The current desktop source path is planned and not asserted to exist.

## Actual instrument provenance retained

The one R3 QA build job 1a1ab68bbb6-fc05-4d8a completed successfully. Full actual tree f45a36bc253f88c3eebc58baf4720a875ca217d7 was accepted by the root's 384-check result 81a7931599ec85df94d8eb9afe42879d20a0367b. It contains 12 actual commands, 75 + 75 complete Cargo events, 76 exact registry members of the canonical lock, six executed Rust components under one shared original 30-second component command, and all owned children/FDs closed.

The current binder still checks the original builder, original build-binding SHA, three Rust/Cargo source pins, exact lock subset, retained executable, actual component listing/output/record and command cleanup. Its historical normal60 prerequisite is fixed independently of the current normal61 product. The template fills the twelve instrument content pins from those actual public records. Destination custody is not yet established.

The original provenance table b9951d3f7ac4ce16c151c6c1b4c3bc43ee4ebc64 distinguishes nine independent file_info observations from three component files initially supported only by whole read_multiple_files content/hash/version. The HA agent subsequently obtained exactly three separately authorized file_info observations in tree f656ac312b0bde7e1372e4b1732605a1f066c5c1. Their whole hashes and versions match the original reads; all three are mode 0600, UID/GID 1000, nlink 1. The v2 table preserves the old table and read provenance while adding those exact observations. All twelve metadata rows remain historical actual observations, not an assertion about the host at a later dispatch. The transport must recheck custody.

No Rust source or component source changed. This packet contains no new QA-build dispatch.

## Scope and unchanged behavior

The fresh planned control/work roots use suffix r2. The source namespace is normal-same-root-publication-validation-source-r1. The same three normal native processes, fixed ports, setup, custody and cleanup code remain. Every source definition outside the declared identity/qualification/report changes is byte-identical: 17 binding definitions and 42 driver definitions, including generic file reading, ownership helpers, setup, request dispatch, single-request H2 invocation, mutation/unknown fencing and cleanup.

The three fixture cases are unchanged: H01 is the strict H1 native snapshot control; H02 is a single explicit TLS/H2 KV2 version-2 GET; H03 is a separate single explicit TLS/H2 native snapshot GET. CA, hostname and exact server leaf checks, selected ALPN h2, single connection/request, complete data/trailers/receive EOS, exact Content-Length, status 200, expected body semantics, archive checks and all-node state/audit observations remain unchanged. A client exit 0 cannot by itself prove product success.

The original 15-second client/HTTP limits, 300-second action/final windows, 45-second readiness, 60-second election, 1.5-second peer timeout, 8-second forward timeout and 5+5 explicit cleanup limits are unchanged. Read-only prepare outer 330 and H2 fixture outer 2400 retain the reviewed original H2 proposal. The original reference timeout SIGKILL/wait5 remains a separate existing stage from one final explicit TERM5/KILL5 budget.

The 8 MiB body bound proves only this small fixture path. There is no 34 MiB qualification, no restore, no cold restore, no standby relay, no official CLI operation, no provider request, no production cutover and no full OpenBao2.7.1 replacement claim. The old B01 unknown records and unobserved old ALPN remain unchanged. Official OpenBao2.7.1 CLI functional windows are a later independent fixture.

## Offline verification and peer scope

The stored offline script parsed/compiled the four complete Python sources without executing those modules. It strictly applied and reversed both full diffs, checked unchanged constants and definitions, and executed selected pure predicates with exact public QA inputs or explicitly synthetic publication objects. Fifty-one checks passed.

The old coupled predicate rejects the actual df026 instrument when the current-product receipt slot differs. The new selected method accepts the real tool proof independently, rejects product identity masquerading as the instrument, rejects a replacement normal60 ancestry SHA, and rejects a mismatched original build binding. The actual driver predicate accepts the instrument's compiled identity and rejects current-product identity in that role. New publication predicates reject old total60, missing/failed/wrong-name ABA, a surviving child and the old runner. Synthetic publication success is a shape test only; it is not evidence that the Linux product passed.

The independent HA peer review covers the new normal61 fields against the exact runner and strict whole diff. It does not grant runtime. No target host was called during this source preparation.

## Remaining gates

The unresolved dispatch file has ready=false and requests_authorized=false. It is not a runnable request. Product normal61, source import, artifact transports, exact host inputs and create-only local staging must close before a concrete private binding is produced. Read-only prepare and live each require a separate exact authorization. The QA12 transport source is owned by the HA validation agent; this packet does not duplicate or execute it.
