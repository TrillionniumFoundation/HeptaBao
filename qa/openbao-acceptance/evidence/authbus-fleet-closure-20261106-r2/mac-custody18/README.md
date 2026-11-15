# Final DR process-custody checks on the Mac

The final unchanged process-custody module passed **18/18 existing named tests**
on the real Mac, using the three exact files from source
`09c14eae7a3b52dee8ce3af3175dad5900ac59ec`, tree
`dfb0df97a2c74b1c0154f45342f3debb0ce438ab`.

The actual job is `1a1b0f0b31e-fc05-7438`, with stable operation key
`heptabao-mac-final-custody18-09c14-20261106-r1`. Its authoritative terminal state
is succeeded, exit 0, no timeout, complete durable output and confirmed terminal
publication. The unchanged tests took **1.192 seconds**; source binding and
post-execution observations took **1.228452458 seconds** in total. The original
60-second outer budget and all per-test and cleanup deadlines were preserved.

This closes the specific evidence gap where the first 15 Darwin tests belonged
to an earlier helper hash while only the three raw `killpg` guards had run on
the final helper. The old 15-case and 3-case receipts retain their original
scope and are not modified or added together as a new execution.

## What was observed

- Every one of the complete module's 18 names ran and passed, without ignored,
  expected-failure, skipped or unexpected-success cases.
- The real subprocess tests exercised cancellation, original-child identity,
  process-group retirement, timeout retention, retained Darwin zombie identity,
  direct `killpg` routing and rejection of unknown or already retired groups.
  The module also includes deliberately mocked negative identity observations;
  passing the module does not turn those mocked cases into independent kernel
  experiments.
- `Popen`, `killpg`, signal handlers and the helper's active-owner state were
  restored. A final non-reaping `waitid(P_ALL, WNOWAIT)` observation reported no
  remaining direct children. The existing tests asserted their own descendant
  group retirement. This does not claim containment of hostile session escapes.
- All three original and copied input files matched their fixed hashes both
  before and after execution. Independent file reads retrieved the exact
  selection and final result; the final file equals the JSON emitted in the
  original stdout.

## Scope

The run used a new private directory at
`/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-authbus-custody18-r1`.
It started only disposable test processes. It did not start HeptaBao, OpenBao,
another compiler, the product's 107-test campaign, or the full34/DR25 recovery
workload. No production configuration, existing service, real secret, backup or
previous evidence was changed.

This is process-helper qualification. Formal storage recovery, physical HA,
AuthBus credential migration, client cutover and legacy cleanup still require
their own complete results.

`runtime-*.original.json` preserves the native tool payloads. `stdout.original`
and `stderr.original` preserve the complete returned stream bytes. The exact
input files, launcher, runner, input-binding record and independently read
selection/result are included. `verify_evidence.py` reconciles these originals
without contacting a host or rerunning any test.

One local preparation attempt encountered `ENOSPC` before copying input files
and before any remote submission. The preparation was completed after space
became available. The actual Mac test was submitted once. A first local log
reconciliation expression was over-escaped; the corrected parser checks the
same unchanged original logs. Neither issue caused a second Mac execution.
