# Next same-corpus OpenBao 2.7.1 comparison — plan only

No oracle, service or HA cohort was started for this document. The preceding normal HeptaBao protocol remains the active implementation step. Historical synthetic comparison69/full34/DR25 and diagnostic Rust cases do not satisfy this new comparison.

## Retained official input and reusable code

The existing Mac ARM64 official 2.7.1 input is:

| Input | Retained path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| bao | `/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016/bao` | 177888914 | `50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c` |
| official archive | same directory, `oracle-official.tar.gz` | 73965161 | `15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91` |

These are retained previously measured pins, not a new current file read. Execution must rehash the actual archive and executable and check the unique archive member before starting. `qa/openbao-acceptance/official_openbao_launcher.py` at source 4bde/9c68 supplies `verify_inputs(version="2.7.1")`, immutable `PINNED_RELEASES`, sanitized environment, certificate setup and `storage_configuration`. The actual entry is `bao server -config=<new private server.json>`, never dev mode.

The existing `start_oracle()` receipt declares `synthetic_only=true` and initializes 1/1 shares. It cannot be reused unchanged for the actual private current projection. A small private-corpus lifecycle adapter may reuse the verified artifact/environment/TLS/storage helpers, but must issue its own honest `private_current_projection` scope, complete private root/share custody and original process receipts. This is a new isolated oracle, not a change to any existing OpenBao service.

For 2.7.1 the non-HA backend is explicitly PebbleDB. The existing runner selects `raft_storage=True` only when requested. PebbleDB must not be relabelled as Raft to make snapshot or HA claims.

## Minimal reusable driver boundary

The shared input is the exact `ProjectionSource` and `projection_rows()` output used by formal HeptaBao, plus the fixed standard KV2 canary requests. A private `ComparisonCorpus` envelope should bind the projection pin, mount/key mapping, exact ordered request method/path/body/expected-status list, and each backend's original observations. It contains all real payloads privately; public output contains only counts, status and clearly separated capabilities.

A small driver needs only these adapters:

| Adapter | Responsibility |
| --- | --- |
| `CorpusReader` | Reuse actual restored-generation/allrows verification; emit the same payload and order for both products |
| `BoundedKvClient` | Reuse the single-request strict TLS/15-second owned-wire pattern; no redirects or mutation retries |
| `PrivateOpenBao271Lifecycle` | New normal TLS root, actual 2.7.1 identity and private custody, cold stop/reopen, original child cleanup |
| `SemanticComparator` | Compare complete KV data, version numbers, CAS and deletion state; retain both products' original metadata/time values |
| `ResourceObserver` | Observe the exact original server process during an identical separately declared operation window; retain raw numeric observations privately |

Do not route the current managed source through an isolated fixture launcher or repeat CAS0 on it. Its already observed phase-one trace can establish the first correctness side. If the resource workload must be repeated, use an independently recovered HeptaBao target and a fresh OpenBao target with the same complete corpus, and declare their exact initial state and cache condition. This is actual restored business data with private credentials; it is not a replay against active dependency clients.

### Exact common KV2 operation classes

Both products receive every business row as one CAS0 version-1 write, complete reads of every current key, complete metadata, the same multi-version canary, soft delete, destroy, data CAS rejection, metadata CAS rejection/success, cold reopen and undelete/destroyed-absence observations. The comparator must preserve every original response and compare the whole expected key/version denominator; it may not replace these with aggregate success counts.

Server-generated creation/update/deletion timestamps naturally differ across the two independent executions. Compare their required ordering, unchanged-versus-mutated behavior and consistency across each backend's own API/restart/export witnesses, while retaining exact originals. Do not normalize away substantive metadata, missing history, default-policy behavior or CAS counters. Hepta-specific activation, raw witness and lossless-export endpoints remain additional Hepta evidence, not invented OpenBao protocol support. OpenBao raw history export can reuse the reviewed `tools/migration/openbao270_kv2_migrate.py` read-only export path after exact mount discovery; it must retain deleted payloads and destroyed tombstones and must not rewrite the accepted source.

### Backup and HA comparison boundaries

The normal PebbleDB oracle does not make `/sys/storage/raft/snapshot` a generic file-backend operation. For a same-HTTP snapshot comparison, explicitly create a separate **single-node Raft** OpenBao oracle with the same corpus and run actual save/restore/fresh-target/cold checks. Keep that topology and denominator separate from the non-HA resource result. A one-node Raft result grants no leader-loss or quorum qualification.

After formal KV2 closes, the physical Mac/ROG/Pocket4 phase needs actual matched multi-node cohorts and the user's required leader crash, election, ReadIndex, acknowledged durable commits, cold restart and recovery tests for both products. The current module supplies a current complete logical history and a frozen export boundary for a pristine HeptaBao Raft cohort; it does not execute or replace those HA tests.

### Resource scope

Use the same machine, client/TLS/body sizes, exact request count/order/concurrency and declared steady-state window. Preserve per-request wall observations separately from the server's CPU/RSS/disk measurements; the owned Python request-process overhead is not server CPU. The current module records request elapsed time but did not instrument a matched resource benchmark, so no complete resource result can be recovered retroactively from its future protocol result alone. Define numeric OS sampling and original PID identity before the comparison, record background activity and cache state, and avoid comparing cold build time or summing different Hepta-specific endpoint work as a product ranking.

No current or future comparison result by itself grants dependency-client migration, per-machine rollback, real-traffic cutover, old-service deletion or full replacement. Those remain the later ordered gates.
