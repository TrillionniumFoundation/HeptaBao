# Native numeric and storage witness candidate — 2026-10-19

This candidate continues exact parent `22cdbc19679cceffe082c6ced8b8e8bb7567058e`. It is a qualification candidate; complete OpenBao 2.7.1 replacement, LAN fault qualification, production traffic cutover, and old-service deletion remain unproven.

## Product and validation changes

KV2 data responses now have an explicit OpenBao 2.7.1 float64 projection, based on the pinned official Mac process observations. The stored native payload and import graph keep their existing precise numeric representation. Ordinary KV2 writes reject non-finite binary64 input before creating a version. The new root-authorized `POST sys/internal/storage/kv2-version-witness` reads an authenticated native paged payload and reports its precise canonical SHA256 and byte count, including retained soft-deleted versions and explicit destroyed absence. It retains the original Actor, clock, deadline, native root custody, and mandatory terminal audit. The endpoint currently refuses HA custody with HTTP 501; it is not HA qualification.

The two-process migration controller captures the actual official API baseline independently of raw storage, requires a storage witness after import, cold restart, and snapshot recovery, and preserves each observed mount incarnation, source root, and publication generation. All 31 migration checks remain required. The source's original JSON number spelling, the target's precise canonical JSON, and the OpenBao API projection are three distinct contracts. The current decoder canonicalizes some zero/exponent spellings; this candidate does not claim a byte-for-byte lexical roundtrip for every JSON spelling.

The historical fixture now observes the actual migration source after ordinary admission. Its restore expectation is independently captured by fresh ReadIndex after the same request's actual admission, before transfer. A detached root comparison permits only the separately checked Auth clock-floor change. Cold rejoin also checks its original eight-second deadline on the successful readiness branch. The witness expiry fixture anchors its wait after the actual token-issuance response, retaining the same token TTL and original request budget.

The host runner and CI select 55 cases: the prior 43 cases, eight new API/witness cases, and four existing cases directly affected by the numeric response changes. Original selectors, request deadlines, and command budgets remain unchanged. A low-memory compiler profile remains available for X230.

## Actual evidence already available at integration

| Evidence | Actual result and limit |
|---|---|
| Official Mac numeric raw readback | 85 completed read-only GET/LIST requests; 21 raw records matched across two acquisitions. All six accepted number spellings remained in raw payloads. Rejected `1e400` left neither payload nor metadata. The new clone was stopped, and all 19 original fixture files were unchanged. |
| Physical Mac parent 22cd historical group | Compiled successfully; five of six passed. The remaining failure moved from migration-source admission to the pre-admission root comparison at historical test line 310. That failed summary and raw log remain exact. The newly edited expectation is awaiting execution. |
| Physical X230 parent 22cd | The one-job, zero-debug compile was still running when this candidate was assembled. No server test success is inferred. Earlier actual global OOM, controlled group termination, and dependency-fetch evidence remain in the parent history. |
| AuthBus first SDK caller | Actual SDK loaded, but the scoped SQLite seed was filtered through main-store inheritance. The failed receipt remains exact. |
| AuthBus owner r1 | Actual scoped SQLite and trusted initial admission passed; the usable fixture failed because its expiry was inside the SDK's actual 300,000 ms refresh margin. |
| AuthBus owner r3 | Seventeen checks passed, including scoped-owner selection, four unowned refresh entry denials, and the managed refresh sequence. `manager:old_wire_cannot_use_successor` failed. The original overall scenario flags remain false; this is not a passed SDK refresh qualification. Six attempted package-root metadata reads remained blocked. |
| Controller local regression | Thirteen cases passed, including the synthetic pinned-TLS helper. A prior sandbox socket refusal is retained separately. This is not a real Bao migration run. |

Exact public receipts are under `qa/openbao-acceptance/evidence/resumed-20261019/`. The existing actual 293-check owned-credential canary and 21-check actual SDK SQLite bridge remain valid for their recorded scopes, without being promoted to provider refresh, LAN HA, per-host cutover, or full replacement.

## Remaining execution gates

Run this exact candidate's 55 selected cases and build the server on the physical Mac and Linux hosts. Then run the actual pinned OpenBao 2.7.1 full-34-MiB two-process migration, restart and snapshot restoration with API and storage evidence. Close the independently observed AuthBus old-wire admission bypass before any credential or traffic cutover. Physical Mac/ROG/Pocket4 kill-leader, re-election, ReadIndex, persistence and restart still require same-candidate binaries and actual LAN execution. Per-host real credential read/write, restart and rollback precede traffic changes; complete client and backup migration precedes cleanup.
