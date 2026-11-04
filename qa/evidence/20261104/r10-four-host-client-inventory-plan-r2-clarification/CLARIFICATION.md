# Inventory read-plan clarification R2

This adds to the immutable source-only plan in tree
9e4971a0b47268c2eb331c4caa67b11e17ae3ad2. It changes no host, file or service,
and does not authorize an inventory collector. The earlier plan remains evidence.

## Exact original inventory recovery order

Only the finite registration recap's pathname is currently anchored by the
whole recovered primary documentation:

 /home/qian/heptabao-cutover-cleanup-inventory-20261104-r1/finite-cutover-registration-scope-r2.public.json
 SHA256 f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64

After root allocates the read window, recover this exact public original first.
Verify its whole digest and follow only its concrete finite source references.

The four-host client/backup matrix digest
aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0
is independently recorded in the published primary table (blob
9edacae976af3fb0ca2ac89ecab6fa55f7bbc593). That table does not establish
its filename. The earlier plan's proposed four-host-cutover-cleanup-assessment
basename is an earlier coordination pointer, not a currently verified path.
Do not dispatch a read on the strength of that asserted filename alone.
Resolve the exact matrix path and the nine recovery scopes from the recovered
f458 recap or a directly referenced existing source record. If neither supplies
the path, report that finite unresolved reference to root instead of scanning
directories, guessing files, or claiming the second original was recovered.

The recovered published primary table also reports that its finite registration
scope had not identified a confirmed scheduled Bao/AuthBus backup or restore
registration. That is a bounded historical finding, not proof that no recovery
assets or concrete restore dependencies exist. This plan does not invent a backup
job, a new global discovery gate, or a need to search hypothetical manual paths.

## Complete path denominator, fixed passes

The earlier phrase “32 registered objects” must not collapse an agent database
and its sidecars into one observation. Main database, -wal and -shm each occupy
their own planned path entry even when absent.

For the concrete collector implementation, the 32-per-pass limit is interpreted
more conservatively as explicit filesystem metadata observations. Every intended
lstat and fstat, including before/after checks and an ENOENT result, is charged
once. Explicit parent-directory safety checks are charged too. A regular bounded
file normally has two path lstat observations and two descriptor fstat
observations. A database in this metadata-only pass has before/after lstat only;
it is never opened. Byte-reading calls and bytes also have explicit counters and
retain the original per-file and total byte limits. The implementation must not
hide additional intended path probes in an uncounted resolution helper.

A source-reviewed fixed manifest defines all paths, observations and passes
before execution. A pass whose exact parent guards would exceed32 is split into
another explicit finite pass before source review. No pass dynamically stops at
32 and treats the rest of its paths as absent or completed.

Proposed ROG grouping, using the paths already listed in the original JSON:

| Pass | Fixed regular or database paths | Planned handling |
| --- | --- | --- |
| r-config-native | openclaw.json; .codex/auth.json; .codex/config.toml | Three bounded files; file and explicit parent observations charged |
| r-role-files | ca.crt; role_id; secret_id | Three private bounded files; public metadata/digests only |
| r-cache-a | applied-profiles.json; publish-baseline.json; bad-refresh-quarantine.json | Three exact present-or-absent entries |
| r-cache-b | refresh-backoff.json; lease-epochs.json; status.json | Three exact present-or-absent entries |
| r-gateway | gateway unit and its three known drop-ins | Four bounded files plus exact unit query; preserve query outcome separately |
| r-db-a | main and azi2; each main/-wal/-shm | Six paths, twelve before/after lstat observations, plus explicit parent guards |
| r-db-b | azi3 and azi4; each main/-wal/-shm | Same complete six-path denominator |
| r-db-c | azi5 and zbj-llm-runtime; each main/-wal/-shm | Same complete six-path denominator |

Thus all six ROG agent databases and all twelve sidecars remain in the
denominator. Metadata absence is observed, never inferred from a missing row in
the report. The three database passes, for example, can account for their seven
known parent directories twice and their six paths twice within26 observations.

Mac's five recorded agents similarly use three fixed database passes
(main/trnm, hepta-ui/hepta, hepta-backend). Pocket's two agents use one. Their
configuration/credential/cache/registration groups follow the same conservative
small-group rule. Pocket's exact hold files and source-map input have their own
explicit groups. Unknown legacy helper/relay/backup names are not populated
until the original finite inventory is recovered and reviewed.

All passes on a host share the same NEW45-second original monotonic controller
deadline, NEW60-second outer supervisor cap, total8MiB read ceiling and64KiB
public output ceiling. A pass is a reporting/grouping unit, not a new deadline.
The original maximum10 seconds per subprocess is still min-capped by the
remaining original host deadline. No product or existing service deadline changes.

If the complete host denominator cannot finish in that window, the final result
is incomplete. It preserves all unobserved entries and their reason. A later
new finite read intent requires a separate root decision and never retroactively
turns the first incomplete result into a pass.

The source implementation and its exact observation counts still require review
before dispatch. No collector, SDK, SQLite connection, Docker action, credential
refresh, provider request or J3160 connection has run under this plan.
