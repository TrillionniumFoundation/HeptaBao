# Pocket original first-cycle registry read adaptation, r3

## Observed r2 result

The single r2 preflight ended with exit 1, no timeout and no unknown outcome. Its 18 completed checks passed, then the current registry read failed closed. The actual SQLite error was `SQLITE_CANTOPEN` / 14. The 111,644,672-byte main database existed with the required custody; both `-wal` and `-shm` were absent. The existing fallback required a present WAL and therefore correctly refused this different shape.

The full failed core, outer result, intent and authoritative job terminal remain in `observations/pocket-preflight-*-r2.public.json`. The exact direct-error receipt is `pocket-preflight-registry-direct-failure-r2.public.json`, SHA256 `f2d7821539b47ec31bbd94ae13164570d25819eb6f68680cabe437d04ef04465`.

Both auth tables, configuration, six cache bytes/absences, independent native4 input, hold markers and held service states were unchanged. No HeptaBao server, installed plugin, native factory, provider call or production change occurred.

## Exact code delta

Only `current_registry_matches` changes behavior. In addition to the original unchanged admission expression for a present WAL and absent SHM, it accepts exactly error code 14 with both sidecars absent and a nonempty main file at most 128 MiB. The existing regular-file, UID, mode, link count, path and original descriptor checks still apply.

That new branch copies only the main file, with its original descriptor kept open. The same copy routine checks source identity, byte count and full SHA. Before and after the clone query, all copied originals are rehashed and both source sidecar observations must remain identical. The final source fence repeats the original identities and hashes and checks sidecars both before and after verification. A dangling sidecar symlink is rejected by the unchanged `lstat` custody code; it is not treated as absence.

Only the new owned clone may create missing SQLite sidecars. The query remains `mode=ro`, `query_only`, `BEGIN`, the original exact 13 columns and the original exact row. No `immutable`, source write, checkpoint, permission change or production process stop is added. Other codes, changing sidecars, oversized or changing main files, or a different registry row still refuse.

Seven of the ten QA source files remain byte-identical, including the complete r2 controller, all actual consumer/native/CAS helpers, the trusted source projector and coordinator. The r3 controller continues to be named `pocket_shared_first_cycle_live_r2.py` to make its identical content explicit. Launcher and prepare changes only select the fresh r3 QA, prepare receipt and preflight/live directories. The old original native prepare-r2 and trusted private input generation remain fixed. All budgets and production fences are unchanged.

## Verification and limits

Python syntax checks passed. All helper top-level AST nodes other than `current_registry_matches` are identical. Its four nested custody/copy/query/public-write functions remain identical. The original WAL admission expression is AST-identical. Ten small boundary checks of the actual new admission-expression AST passed, including rejection of code 1544, base code 8, extended CANTOPEN, either sidecar, empty main and a file larger than 128 MiB. This is a predicate/static contract, not an I/O or live qualification.

The cloud environment refused bubblewrap namespace creation. An attempted synthetic permission-only SQLite engine fixture also did not reproduce Pocket's code 14: its actual read failed with `SQLITE_READONLY_DIRECTORY` / 1544. The original failed component and capability observations are preserved. No kernel guard was mocked, the candidate admission rule was not broadened to accommodate that environment, and this component is not reported as passed. The candidate's actual private-copy I/O and kernel-readonly behavior still require the separately reviewed fresh Pocket preflight.

## Frozen pins

| File | SHA256 |
| --- | --- |
| `candidate-r3/pocket_first_cycle_inputs_r1.py` | `d60ee11225295434f63babf2446bd6627443565776097cec8d708477cdcbef1b` |
| `candidate-r3/pocket_first_cycle_launch_r3.py` | `b5f86e11bf8f848a39466f5d979799de4c191a714a9c590bc7a1e15d41cc8f69` |
| `candidate-r3/pocket_first_cycle_prepare_r3.py` | `298281e39a56d23d52d56bfdc95450e9ae422ebf2fa8f9ad81f699c995774c9d` |
| `qa-pins-r3.public.json` | `c8a6820b8f8f12a8b4fb4078d4a0833b2fe01c782d4793cbdd487896a0db3790` |
| `r2-to-r3-registry-main-only.review.diff` | `e7097f29d22a0f9fd4ee208f0e17175fb188fd21bb4de1334b2ca76d8b658181` |
| `registry-inputs-r2-to-r3.review.diff` | `5de58d8d83e2d0f8de20e46fa1ff26ee64fd958c8523823d695d04cb808d76d4` |
| `observations/registry-r3-static-boundary-contract.public.json` | `5489b36f308c2e22e8f4fe2fcd27ff382a29a51609ea20aad880c0b138e89426` |
| `observations/registry-r3-sqlite-engine-component-failed.public.json` | `98a104a3ea23e8ea39ec95ca825d9f1813958c436e4a19e8cfa94469c591b552` |
| `observations/registry-r3-cloud-validation-limit.public.json` | `64e4e7048f11f6219e9d24d4a829df8dcf164b15dac34c8ba66775afae731a95` |

No r3 source has been staged to Pocket and no r3 runtime has been started. Review authorization is required before the new single preflight. No live first-cycle authorization is implied.
