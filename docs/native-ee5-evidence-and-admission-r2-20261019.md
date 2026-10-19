# Actual ee5 evidence and the next controlled fixes

The candidate `ee53a4039c5b60a06e26b4505f29d17bd3d66050` is **not a full OpenBao 2.7.1 replacement qualification**. [The complete checkpoint](../qa/openbao-acceptance/evidence/resumed-20261019/ee5-physical-and-ci/checkpoint.json) preserves both passing and failing observations.

## Actual results

The physical Mac completed all 43 selected tests: 42 passed and one historical restore fixture failed at its migration-source digest assertion. Its exact source remained unchanged and a 72,169,184-byte arm64 server was built, SHA-256 `f767cc5804d5ccf2504eb5bf9c64b7501b1f19ae7ca10c92e68f7c7c458165bd`. The 15 native-large tests passed; that is not the two-process 34 MiB official migration gate.

Independent Ubuntu CI completed 42/43 with the same digest assertion. macOS CI completed 41/43: the same assertion and a cold restarted peer's refused ReadIndex before unseal. The full original logs, including the unavailable quorum observation, remain in the evidence directory. A locally passing cold test does not invalidate that CI failure.

X230 r1 could not compile with its incomplete offline cache. An explicit locked dependency fetch completed without changing Cargo.lock. During r2 the kernel killed rustc after it consumed about 6.5 GiB of resident memory. The two peer tests passed, while the 41 server tests were blocked. The root-owned remaining build process group was stopped after verifying its identity, and its partial summary and full compiler output remain intact. A separate resource-stop receipt explains why the partial summary still says running for its final command.

The first real OpenBao 2.7.1 source fixture completed its seed writes but failed its old numeric API oracle before any export/import invocation. Actual API reads rounded the wide integer and long decimal; independent raw acquisitions retained their original precision. A new stopped-source clone additionally observed 1.0 -> 1, -0 -> -0, 1e-6 -> 0.000001, 1e-7 -> 1e-7, 1e20 -> 100000000000000000000, and 1e21 -> 1e+21. OpenBao rejected 1e400 with HTTP 400 and its subsequent GET returned 404. Every POST had a response and none was retried. The seven-case diagnostic's raw tail failed with KeyError; its overall completion remains false. Both diagnostic clones were stopped, and the original fixture's 19 files were unchanged.

## Fixes in this continuation

The historical fixture previously captured a V5 source before ordinary request admission. A pre-existing precise token legitimately causes admission to publish an observed clock floor before the native migration is planned. A test-only, thread-confined, single-use observer now reads the actual V5 identity at that pre-plan boundary. The assertion still compares an independently observed source with the quorum-published migration lineage; it does not copy the final published digest into its own expectation. No production clock, Actor, root guard or deadline changes.

Cold historical fixture setup now observes a real committed ReadIndex on a restarted peer within the existing eight-second readiness budget before sending its single unseal request. Only read-only setup observations may repeat. It does not replay an archive, unseal or any other mutation, and the actual request retains its original 15-second deadline.

The host runner has an explicit low-memory compiler profile: one build job, no compiler debug information and no incremental cache. It records the chosen settings. Test selectors, counts, assertions and the existing per-command build budget remain unchanged. This addresses the measured X230 resource failure; it is not a claim that the new profile has already passed.

## Gates still open

The formal 34 MiB official-source import, cold restart and snapshot recovery must compare actual source API behavior separately from precise raw storage witnesses. The new numeric and native witness implementation is still under development. Physical Mac/ROG/Pocket4 fault regression, AuthBus actual SDK refresh on native control, every host's real credential canary/rollback and client/backup inventory closure remain required before traffic cutover or any old OpenBao removal.
