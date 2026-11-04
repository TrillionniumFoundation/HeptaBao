# R10 Pocket real AuthBus first-cycle candidate

## Scope and current status

This is a source-only rebind of the already reviewed R8 Pocket first-cycle harness to canonical R10 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`. R10 Linux and Mac normal44 have actual independent root-reviewed terminal passes. No R10 Pocket source stage, artifact transfer, preparation, preflight, consumer or native process has been executed for this candidate.

The finite target is Pocket's two configured agents, `main` and `tg8687951891`, using the actual installed SDK and managed native 0.144.3 factories in the original private PID/network namespace. This candidate does not qualify Mac/ROG consumers, production activation, a service-manager restart, provider availability, an installed coordinator owner or full OpenBao replacement.

## Exact change

Seven source files are byte-identical to the published R8 candidate: the consumer, current-input reader, raw auth-row CAS helper, six-cache CAS helper, native observer, trusted-input projector and coordinator core.

Only three files change:

| File | Change |
| --- | --- |
| `pocket_shared_first_cycle_live_r2.py` | Five exact constants: product commit, tree, server SHA, normal build receipt SHA and native receipt SHA. |
| `pocket_first_cycle_launch_r10.py` | Fresh QA/artifact/prepare/preflight/live paths and the three product pins written into the launch intent. |
| `pocket_first_cycle_prepare_r10.py` | Fresh QA/output paths and the two actual R10 normal-build receipt pins. |

The last two filenames are renamed from the historical `r6` names solely within the new QA directory. Reversing the seventeen unique literal substitutions reconstructs all three original source files byte-for-byte. The review diff includes explicit old/new filename mappings. No control-flow, request, admission, rollback, cleanup, native RPC, SDK or business-predicate change is present. Source comparison is complete; this packet does not claim a new Python AST or runtime execution.

The original limits remain HTTP 10 seconds, consumer 70 seconds, rollback 35 seconds and launcher child 440 seconds. The old remote process supervisor cap has not been recovered. The plan explicitly proposes a NEW 600-second remote supervisor envelope around the unchanged launcher; it does not claim equivalence to an unknown historical outer cap. This proposal is subject to root review before any actual run.

## Historical reference and metadata correction

All ten original source files were recovered from validation commit `1197a56a396e8b6aee2928c2503983cba9e2ce19`, candidate subtree `d9e04aac084757bf649bf0d2a5daeb86e320f481`, and checked against the original QA manifest.

The R8 actual recap and independent root review bind physical R8 `384c9576 / d5a0f91a`. They record 66/66 core checks, initial/cold 128/128 each, two 95/95 rollback phases, four real native factories/eight real RPCs, preserved default local identity 5 and independent user-native identity 4, actual managed-generation 1/2 writes, and complete owned cleanup. Those historical receipts remain unchanged and do not constitute R10 acceptance.

The original R8 QA manifest retained obsolete `33cafa / cdc2376` descriptive source fields. Its original bytes are included unchanged. The new manifest correctly names R10; this correction does not retrospectively rewrite or requalify the old R8 run. Actual R8 product identity was enforced by its controller constants and raw build receipts.

## Frozen credential and client contract

Reuse only the already owned private input packet:
`shared-first-cycle-inputs-r1/managed-profile12.private.json`,
SHA `40fc5cd1f2558994c3097b60e3359bf3044f5fdd1a40ba91ff0fe5bd406bb8fe`.

Its existing public projection SHA is `df47c9d560868fea6a88eb60f035c53efcdd101046bfb7ea55778a1ba073f21a`. These are previously verified frozen generations, not a claim that they are the latest active provider credentials. Their private bytes are not retrieved, copied off-host or published by this source packet.

The original controls continue to require:

- Current production config, installed plugin/SDK/native bindings, exact registry row, auth stores, native-user identity, held-unit states and nine protected input hashes.
- The actual effective/local inheritance of both agents, default local identity 5 and all identity/order/usage semantics. A profile-free primary row is not falsely treated as zero raw SQL rows.
- Shared managed identities 1/2 only. Original `publishNew=true`, both order exclusions and shadow semantics remain intact. Normal inbox events from ungranted identities remain deferred by the exact coordinator core; the shared manifest is not expanded.
- Initial and real killed-server/cold-process phases, actual native initialize/login responses, and the original full store/effective store/raw-row rollback followed by exact six-cache byte/mode/absence restoration.
- One guarded rollback attempt per phase. Unknown dispatch, incomplete owned cleanup or CAS conflict is preserved and stops progression. No provider recovery, credential refresh, identity reordering, implicit grant, baseline fabrication or automatic retry is authorized.

A fresh preflight must validate the current source state again. If a frozen pin no longer matches, the run fails with evidence; it does not quietly recapture a different baseline.

## Fresh destinations and input provenance

All paths are under the existing Pocket project:
`/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1`.

| Purpose | New relative path |
| --- | --- |
| QA sources | `shared-first-cycle-r10-qa-r1/` |
| R10 artifact custody | `shared-first-cycle-r10-artifacts-r1/` |
| New preparation receipt | `shared-first-cycle-inputs-r1/prepare-r10-r1.public.json` |
| Read-only preflight | `shared-first-cycle-r10-preflight-r1/` |
| Actual owned fixture | `shared-first-cycle-r10-live-r1/` |

Existing R8/R5 passes and earlier failed/unknown fixtures remain untouched.

The three public artifacts are sourced from the already root-accepted desktop directory:
`/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming`.
The exact source versions, sizes, SHA values, modes and proposed fresh Pocket mappings are in `plan.public.json`.

The normal receipt is copied without byte rewriting from `normal-release-result.public.json` to the harness's historical target basename `normal-build.result.public.json`. Its embedded original ROG provenance remains unchanged. The Pocket transport/receiver and actual destination custody still need their own reviewed, observed closure. This source plan does not claim that the artifacts have reached Pocket.

The existing `P/source` directory remains a read-only frozen helper source used by this harness. R10 product provenance comes from the actual R10 executable and both exact raw normal-build receipts. This plan does not pretend that `P/source` has become a canonical R10 Git checkout.

## Proposed sequence and acceptance

After root review and release of the HA quiet window: review and perform one create-only public source/artifact stage, verify actual target bytes/custody and complete endpoint cleanup, then execute the new preparation once. Next run one fresh read-only preflight. A live run is eligible only when that exact R10 preflight and its preparation/QA hashes have passed and root grants runtime authorization.

The precise commands, fixed job keys and source pins are recorded in `plan.public.json`. The current packet is not permission to start them.

Any live result must be independently read back in full: authority, original intent, core result, outer result, all four phase records, native stop evidence, source/config/cache/unit fences and the original protected public projections. The core/outer result and actual process authority must agree. A partial, unknown or cleanup failure remains a failed new generation and is not replayed under a new path or key.

All production paths stay read-only under the original namespace boundary; only the new run directory is writable. No gateway/hold changes, production traffic switch, J3160 contact, provider/model request, token refresh or human login is part of this candidate.
