# Native KV2 mount fixture correction — actual Mac R2

The original three mount tests pass on the actual Mac at source commit
`f4603486e77771beeec982610bf1a6f8e4e810b8`, tree
`afce15ab6476fb0c0ad2500d39da98c2e9ea7406`. The run completed at
2026-10-19 14:07:46 UTC. All 3,536 source files and their modes were verified
against that Git tree before and after the run. Rustfmt, compilation, the exact
three-test inventory, and execution all passed. No production code was changed.

## Two distinct fixture errors

The empty fixture initialized an actual V4 owner, but native V6 activation
requires an actual V5 record owner. Commit `3aea914` creates and deletes a real
KV1 mount through the Service API to exercise the supported V4-to-V5 transition.
The graph remains free of seeded KV2 data. Activation no longer fails before the
mount test reaches its intended boundary. The first corrected run still failed
later, at the nested seal request; its failed summary and log remain in `mac-r1`.

The after-audit hook deliberately interleaves a second Service request while the
first response is still owned by `complete_native_auth_delivery`. The normal
request guard correctly rejects reentry with an active `native_request_binding`.
Commit `f460348` suspends and restores only that test-only bookkeeping slot around
the interleaved request. The original delivery capsule, Actor, source, clock,
deadline and checkpoint remain owned by the original completion path. Assertions
reject pending delivery or failure state on either side of the hook. The second
request still uses actual Service admission, mutation, audit and retirement.

This proves deterministic interleaving and stale-response rejection. It does not
claim that the synchronous Service normally dispatches two concurrent requests.
An independent code review by the X230 workstream found no blocking issue in
either correction, with the same scope limitation.

## Actual original test denominator

| Test | Actual Mac R2 |
|---|---|
| Native mount create/tune, cold reopen, snapshot, delete and recreate | PASS |
| ACL, CAS and unsupported-backend refusals | PASS |
| Seal after actual audit and cold recovery of the committed mount; later policy publication vetoes the old read response | PASS |

The actual test log records 3 passed, 0 failed, with all remaining tests filtered
by the original mount selector. Test execution took 7.162 seconds, after a
345.363-second compilation. Request deadlines, the 1,800-second command budget,
production admission checks and all original assertions were retained.

The canonical host runner previously omitted this new module. The follow-up
runner change adds this exact three-test group to the existing 55 cases, for an
explicit denominator of 58. The R2 receipt is a three-test run; it is not a claim
that the enlarged 58-test suite has already executed.

## Evidence custody and limits

`retrieval.json` records the original Mac paths, byte sizes, SHA256 digests and
remote file versions. `mac-r2/summary.json` binds the exact source, compiler,
command arguments, log hashes and before/after source verification. The original
Mac materializations remain on the external disk. These are synthetic component
tests; no production credentials, traffic cutover or old-service deletion are
qualified by this receipt. Physical HA and actual client migration have their
own required executions.
