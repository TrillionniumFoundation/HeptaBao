# Native numeric integration and source-witness follow-up — 2026-10-19

## Change boundaries

This delta targets the exact historical test, host runner and CI workflow from commit `22cdbc19679cceffe082c6ced8b8e8bb7567058e`, tree `c4b3c4e6d81ba80c889433bd8baaf722faa838b1`. The migration controller starts from the independently frozen source `376fa19f6aeac5f9f10bcaaafaf3bb8fa06f801973097f79230ab3dcee6ecb57`. Product Rust implementation belongs to the separate numeric/witness overlay. These changes preserve all earlier candidate sources and failed run receipts.

## Historical source-root assertion

The actual Mac 22cd run passed five of six historical cases and failed the clock/Actor restoration case at its source-root assertion. The log SHA-256 is `a001f2a2ff45d92ff0b0efd130cd692df4cfd1fa40251a8733f01a1b2dc8d0d3`. The old comparison took its expected root before ordinary request admission. The production historical restore captures its actual source after the original Actor's real admission, including any required precise Auth clock publication.

The revised case retains the pre-admission observation, then uses the single original 15-second request scope to admit the original Actor and obtain an independent fresh verified ReadIndex before archive transfer. That observation must match the actual Service source. The test compares all encoded native root fields and owner references after replacing only the Auth owner reference in a detached copy. It also compares the complete actual Auth encoding with a detached copy changed only by observation of the independently read actual clock floor. The later transition source must equal that independently witnessed admitted root. No expected value is copied from the restore plan, transition or response. Original Actor removal, live-clock inheritance and restored history checks remain.

The cold rejoin helper checks its same original eight-second setup deadline on the successful ReadIndex branch as well as the unsuccessful branch. Starting the owned process still precedes this setup budget. The one subsequent real unseal retains its separate original 15-second request budget; this does not claim an eight-second process-start-and-unseal limit.

## Planned native run: 55 cases

The existing eleven groups, their 43 cases, selectors, ordering, features and execution budgets remain byte-for-byte unchanged. Six additional groups cover eight new tests and four affected existing tests:

| Group | Required discovery count | Reason |
| --- | ---: | --- |
| `kv2-api-271-numbers` | 3 | New official API number projection and overflow tests |
| `native-kv2-storage-witness` | 5 | New lossless source-bound witness tests |
| `lossless-json-private-tags` | 1 | Existing exact-value and private-tag regression changed by the product overlay |
| `lossless-kv1-conversion` | 1 | Existing conversion regression changed by the product overlay |
| `lossless-token-equivalence` | 1 | Existing token/deserializer regression changed by the product overlay |
| `native-raw-private-tags` | 1 | Existing native raw transport-tag regression changed by the product overlay |

Both physical runner and CI still require actual compiler discovery to match each expected count, a successful command exit, and the exact terminal passed/failed/ignored counts. Static inspection confirms the selectors exist in the supplied product sources; it does not replace actual Rust compilation or execution. The low-memory build option and all source/tree verification, process ownership and timeout controls remain unchanged.

## Migration witness receipt

Each successful `sys/internal/storage/kv2-version-witness` response now must include a positive unsigned 64-bit `mount_incarnation`, a lower-case 64-hex `source_root_sha256` and an unsigned 64-bit `source_publication_generation`. Booleans are rejected as integers. The controller retains all three exact values for every response. It does not equate roots across separate requests: real terminal Auth clock publication can legitimately change the current root and generation. Unexpected plaintext `data` or `payload` fields inside the witness are rejected.

All 31 required controller checks, three actual target storage stages, fixture values and original request/worker budgets are unchanged. Missing or invalid source fields cannot qualify a native storage stage.

## Validation and limits

The final controller and tests ran 13/13 local checks successfully, including real pinned TLS over a synthetic local loopback server. The updated existing witness test exercises missing fields, booleans, invalid bounds and root encodings, plaintext-field rejection, and exact retention of changing valid sources. The first attempt passed twelve checks but could not create the synthetic TLS socket under the execution sandbox; its error receipt is retained. The subsequent authorized local loopback run passed all thirteen, with source hashes unchanged. The first receipt's `started_utc` field was emitted after that short command; use its elapsed duration and retained log rather than that label for precise start ordering.

`evidence/resumed-20261019/numeric-integration-host-r1/` contains both executions and the independent 55-case static selection report. No actual Rust case, official OpenBao process, HeptaBao process, host cutover or production credential was executed by this delta's local validation. Physical 55-case Mac/Linux execution and real two-process migration remain required.
