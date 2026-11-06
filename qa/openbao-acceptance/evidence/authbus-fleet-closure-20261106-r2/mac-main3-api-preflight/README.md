# Main3 current AuthBus preflight — preserved attempts

This package is a source and failed-preflight checkpoint. It does not qualify the actual main3 API canary, the actual plugin/SDK migration, provider availability, production cutover, or removal of OpenBao.

## Authoritative outcomes

| Operation | Durable job | Outcome |
|---|---|---|
| Exactly eight installed public AuthBus source files | 1a1b1bb80dc-fc05-7a81 | Succeeded, exit 0; 82,927 whole source bytes copied into a new private directory and independently read back. No credential/configuration input was read by this operation. |
| API r1 create-only preparation | 1a1b1cc2471-fc05-7adb | Succeeded, exit 0. Review caught a fixture-only activation route before qualification or any server/API dispatch. Preserved; never executed. |
| API r2 create-only preparation | 1a1b1d7bcd1-fc05-7b1c | Succeeded, exit 0. Uses the canonical normal storage route and explicitly configured native_v6_file storage. |
| API r2 guards and current-source preflight | 1a1b1dc7351-fc05-7b2e | Failed, exit 1. All 108 QA guard tests passed with zero skips; current source-generation admission refused before any service or HTTP operation. |
| Independent read-only namespace diagnosis | 1a1b1de3b3b-fc05-7b39 | Succeeded, exit 0; complete 5,237-byte stdout and no stderr. Only safe category/field-name predicates were emitted. |

The 108 denominator is 30 inherited launchd custody gates, 33 fixed-system-ps/TLS gates, and 45 main3 scope/HTTP/authority gates. It is separate from the product's canonical 107 selected tests.

## Why r2 remains failed

The exact refusal is `current_source_full_generation_exact`. The preflight completed in 0.28967370791360736 seconds, with zero service mutations, zero HTTP requests, no manager service entries, no unknown helper outcome, and known closure of all returned helper/volume/home resources. The capsule fence opened and closed four descriptors. Its create-only private qualification binding already exists and must not be overwritten or replayed as if the failed preflight had succeeded.

The independent later diagnosis found every captured identity and explicit absence for all five agent authentication databases still exact. The three registry files — database, WAL, and SHM — differed only in ctime_ns. Their other eight identity fields, including inode, size, mode, and mtime, remained equal. The registry rollback-journal absence remained exact. This does **not** establish a change in credential bytes or registry contents, and does not establish when or why ctime changed. The full-nine-field admission rule remains enforced. A fresh actual registry/SDK/selected-owner capture and a distinct succeeding attempt are required.

## Scope and source binding

The canonical server is commit 4bde9aee03fcd27c59e13607e529b1cee594b249, binary SHA-256 5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c. New retained mode-0500 binary copies were prepared; the canonical artifact was not modified. The actual r2 server configuration was read back and checked against the exact normal native_v6_file profile. The permitted activation route is `sys/storage/native-v6/activate`; fixture options are rejected.

The capsule's public source-selection authority is the original actual SDK order job 1a1b197fa0e-fc05-79c0 and exact original public stdout SHA-256 fb65fe07d9afc97aa102d7f00561537b315cf0b349b339f6ca8f3285bd5a10c4. The capsule producer was known-succeeded job 1a1b1a4c29c-fc05-7a0c, worker source SHA-256 dbbac9f6ee12704b1e6e73ca2587d6f4e6489b58ec36122c49d24a9605274628. Eighteen public SDK source pins are checked as provenance from that capture; Layer A does not execute the SDK.

The selected private scope is three actual main-owner OAuth objects and fifteen consumer references over five agents. All three access-token states were observed expired by the source producer. Provider calls, refresh, and production changes remain zero in this package. Credential bytes, profile IDs, current configuration hashes, capsule hashes, private generation values, private bindings, and TLS private keys are absent from the archive. Public script/source hashes, synthetic server configuration, public certificate, fixed case labels, and safe counters are included.

The complete qualified fresh-r2 launchd custody logic and fixed-system-ps exception were retained, with new roots and labels. Budgets remain 600 seconds for the controller, 120 per business phase, at most 45 per explicit source observation clamped by its phase, wrapper readiness 30, executable observation 10, TLS health 15, and failure cleanup 60. Source observations are explicit before/after checks, not a continuous lock.

## Raw evidence layout

- `current-plugin-binding/`: original request, launch, terminal, complete stdout, independent whole-file readback, and all eight public installed code files.
- `api-r1-unexecuted/`: the original submitted source set, preparer, manifest, complete create-only preparation receipts, and actual critical readbacks. Remaining r1 submitted sources are not represented as independent remote readbacks.
- `api-r2-preflight-failed/`: all fifteen submitted sources, actual complete source readbacks, normal server configuration/public certificate, preparation receipts, the exact qualification loader and never-used run loader, both lossless stdout pages, complete stderr with 108 named guard outcomes, and the independent namespace diagnostic.

No old attempt, source, result, private binding, or data directory was replaced or deleted.
