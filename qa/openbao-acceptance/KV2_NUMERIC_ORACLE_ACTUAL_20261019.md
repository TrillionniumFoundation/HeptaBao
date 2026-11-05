# Official OpenBao 2.7.1 numeric raw follow-up — actual Mac evidence

The previously incomplete numeric diagnostic now has a completed, separate raw readback. This addendum supersedes the earlier limitation that the raw-root lookup had not completed. The original failed diagnostic, its seven original writes and its source fixture remain preserved. The follow-up copied the stopped failed fixture into a new private root, started a distinct owned official OpenBao process and sent only reads. No numeric write was replayed.

## Retained sources

The exact actual receipts are checked in alongside this addendum:

| Artifact | SHA-256 |
| --- | --- |
| [Actual summary](evidence/resumed-20261019/numeric-raw-actual-r1/summary.json) | `4102fe44bfefb5901f0ae3221955ef50630a39bd9680f4f23b9730988640e36b` |
| [Owned clone lifecycle receipt](evidence/resumed-20261019/numeric-raw-actual-r1/controller-receipt.json) | `a5be87a9305ce05f5b62017dd8560512734950d4af3bf0c412914c73474c17cc` |
| Earlier incomplete numeric summary | `1281990796a3be2fc0064f0ffcb7fd2696b6bb7bf800e886e2534120e087481d` |
| Read-only follow-up script | `d8de2d02d902c525b715e8e9491d39df1114b280f738e33b78b9b2840e23a524` |

The [independent review](evidence/resumed-20261019/numeric-raw-actual-r1/independent-review.json) recomputes the receipt hashes, checks the reference to the actual earlier failed summary and evaluates the complete request/case inventory. These are readback and review receipts, not a replacement for the retained private responses on the actual host.

## Observed API and raw numbers

The actual server identifies as OpenBao 2.7.1 and matches the earlier fixture's cluster. The readback reproduces all seven earlier API statuses and numeric lexemes. The original raw payload stores all six accepted input lexemes exactly:

| Original JSON number | Original write status | Actual GET status | Actual API number | Actual raw number |
| --- | ---: | ---: | --- | --- |
| `1.0` | 200 | 200 | `1` | `1.0` |
| `-0` | 200 | 200 | `-0` | `-0` |
| `1e-6` | 200 | 200 | `0.000001` | `1e-6` |
| `1e-7` | 200 | 200 | `1e-7` | `1e-7` |
| `1e20` | 200 | 200 | `100000000000000000000` | `1e20` |
| `1e21` | 200 | 200 | `1e+21` | `1e21` |
| `1e400` | 400 | 404 | No value | Neither raw payload nor metadata exists |

The raw decoder also completed. Its `Decimal` representation may canonicalize exponent spelling: for example, stored `1e-6` becomes the exact decimal text `0.000001`, while `1e21` becomes `1E+21`. That changes textual spelling without losing numeric precision. This evidence establishes the source record lexemes and exact numeric values; it does not claim arbitrary original JSON whitespace, object order or exponent spelling survives every migration serialization stage.

## Raw-root failure resolved by observation

Two independently acquired raw inventories contain the same 21 records. Their actual closed configuration root is one level below the earlier assumed root. The earlier outer root does not contain the salt entry; the actual nested configuration root does, with a 36-byte salt. The successful decoder used that complete observed closed root. The earlier fixed outer-root assumption is therefore concretely false for this real official fixture.

The root projection retains SHA-256 `aed1c61fa8b5c6370236b1d72dfee3697e3e1939e3cf76b5b46980b50991ad08`. The receipt records the source-bound root, decoder and migration module hashes, each response hash and the exact numeric cases. No production credential or raw secret was introduced by this synthetic numeric fixture.

## Ownership, timing and qualification

The follow-up issued 85 requests: 53 GET and 32 LIST. All 85 outcomes are known, all owned HTTP leaves were waited, and no request was retried. The responses are 84 HTTP 200 and the expected HTTP 404 for the rejected overflow key. The diagnostic completed in 3.555358 seconds within its original 120-second budget. It performed zero writes and invoked no migration.

The separate owning controller records the clone stopped and all 19 original fixture files unchanged. The diagnostic deliberately does not grant itself that lifecycle qualification; the lifecycle assertion comes from the controller that created, owned and stopped the clone. `synthetic_only=true` describes the fixture data and its scope: these observations came from an actual official OpenBao process, not a mocked HTTP response.

This closes the official-source numeric raw phase. HeptaBao API projection, exact native storage witnesses after import/cold restart/snapshot restore, the full 34 MiB two-process migration, physical LAN failover and per-client credential cutover still require their own actual receipts. None is marked successful by this addendum.
