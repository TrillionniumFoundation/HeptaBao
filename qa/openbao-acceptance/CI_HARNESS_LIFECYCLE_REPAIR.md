# Confirmed historical CI harness repairs

These changes repair QA controllers only, on base
`fe10ae499ef3a7302e2480c833652bd7239910a3`. They neither change Rust product code
nor rerun GitHub Actions, start HeptaBao/OpenBao, migrate credentials or qualify
a deployment. No business scenario denominator is changed.

## Original evidence remains failed

The read-only investigation of [PR160 run 42164486987](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42164486987)
is retained at
`evidence/ci-harness-lifecycle-20261106-r1/old-pr160-triage.public.json`.
That run tested head `8f3dd8353aaf9642ad58f7716b0c14813d09983d` and prospective
merge `076f3cd1652d5a4d66b6d4b7cbc79be8153e330e`. Both failed. Their outcomes
are not outcomes for the current candidate, and these source repairs cannot
retroactively turn them into passing runs.

| Observed old step | Confirmed current QA problem | Narrow repair |
| --- | --- | --- |
| 31, 33, 35; inherited path in 37 | The exact startup negative waits for exit 1 and the required terminal diagnostic, then cleanup incorrectly requires live-node SIGKILL exit -9. | A proved original wait is retired and its log closed once. A live-node intentional KILL remains a separate -9 contract; an already dead node fails. Wrong status, stale diagnostic and timeout still fail. |
| 59, 64 | Renewal deliberately crashes and waits the official oracle, then applies the unrelated graceful TERM/0 contract; a second cleanup exception can prevent report publication. | `crash_oracle` requires a live original, KILL, original wait and exit -9. Only a confirmed retired handle is cleared before restart. Normal `stop_oracle` remains graceful TERM/0. Cleanup attempts every remaining resource, retains unretired private roots and publishes the original safe failure. |
| 74 | A native snapshot download is sent to JSON decoding and checked as a JSON `data` object. | One fixed, bounded HTTPS binary download route preserves the 32 MiB/12 second limit, no proxy and no redirect. The receipt records exact byte count/hash and HTTP framing. The original three snapshot/frontier cases remain required, including positive committed and actually purged indices. |

Step 37's inheritance was inferred from source and its early failure count;
its private per-case JSON was not uploaded. Step 74's exact offending wire
byte was also unavailable. The current JSON/binary misuse is independently
visible in the unchanged source. No archive corruption diagnosis is made.

Steps 36, 52 and 72 have unresolved runtime, ACL or OpenAPI differences. They
are not changed here. All downstream scenarios interrupted or skipped in the
old run remain unqualified.

The shared current-candidate `Cluster.run` snapshot call and the current side
of `raft_snapshot_upgrade` also use the binary reader, retaining their original
15-second socket timeout and the same 32 MiB body bound. The upgrade's first
snapshot call uses the independently pinned old `d26ed9d5c3bfd1cac6c669f7b767c753adc2f823`
artifact. Its immutable source explicitly returns JSON, so that one old-version
call keeps the JSON reader. The source commit, file blobs and relevant excerpts
are retained in `evidence/ci-harness-lifecycle-20261106-r1/legacy-d26-snapshot-contract.json`.
There is no content-sniffing fallback that could silently accept the wrong
protocol from a current candidate.

The unchanged HTTP budget is the original socket timeout plus a post-read
elapsed-time rejection. It is not a hard process-level interruption at exactly
12 or 15 seconds; the returned result cannot pass once that original interval
has elapsed. This repair introduces neither a larger budget nor a new worker.

## Regression boundary

`tests/test_ci_lifecycle_regressions.py` uses short-lived Python child processes
to distinguish expected rejection, live intentional kill, already dead
originals, repeated cleanup and a failed wait. The HTTP and renewal objects
are explicit test doubles. They do not authenticate a real provider or run a
product service. Both renewal entry points are exercised through their actual
`finally` paths with injected stop/provider failures and real private report
files; exception payloads cannot be published as failure labels.

Snapshot byte count, a gzip prefix and SHA-256 are transport observations.
They do not authenticate or restore an archive. A successful download still
cannot replace the original committed-frontier and log-purge observations.
Missing, Boolean or inconsistent frontiers fail. The fixed scenario names
`snapshot_waits_durable_readback`, `snapshot_committed_frontier_exists` and
`prejoin_logs_really_purged` remain unchanged.

The selected local regression command is:

```sh
python -B -m unittest discover -s qa/openbao-acceptance/tests \
  -p test_ci_lifecycle_regressions.py -v
```

The retained selected-suite runner additionally runs the existing HA guards,
RADIUS and Kubernetes renewal guards, oracle-version guards and compact
snapshot observation guards. Its JSON includes the exact selected modules,
actual unittest count, original log hash, source pins and failed/skipped counts.
These are controller checks, separate from any future real HA, AuthBus, full34,
DR25 or per-machine migration evidence.
