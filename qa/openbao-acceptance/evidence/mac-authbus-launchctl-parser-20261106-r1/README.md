# Mac AuthBus launchd parser recovery — 2026-11-06

## What was established

The historical owner-bind attempt and the later `home-launch-r2` attempt both
ended with `ManagerRefused: typed_launchctl_integer`, before any AuthBus business
check or phase completed. The r2 terminal report records a successful bootstrap
command, zero completed manager operations, and unknown registration and lineage
closure. A successful bootstrap is not a successful wrapper or server startup.
The safe projection is in `r2-terminal-summary.public.json`.

The current r2 source already handles the exact string `78: EX_CONFIG` as numeric
78. Its existence therefore does not explain away the r2 failure. Both current
r2 standard-output and standard-error files were empty when read. Its plist uses
the home directory for its working directory and both output paths. These facts
do not establish an operating-system permission denial or a HeptaBao storage
configuration error. The original public result did not retain the rejected field and literal. A
subsequent bounded read-only inspection established the current actual values
and reproduced the parser failure, as described below. No owner-bind retry or
service mutation was executed during this audit.

The separate home/T5 context probe reached `ready` and then failed its original
child admission deadline before entering T5. That is a different failure from the
integer parser and is not repaired by this source change.

## Narrow source repair

`prepare_macos_launchctl_parser_patch.py` prepares a distinct local source file.
It requires the full observed input SHA-256 and one of two exact observed
`parse_print` source hashes. It does not import or run the manager. The r2 diff
adds five lines: the exact `last exit code = (never exited)` sentinel becomes
`None`. A registration which has not exited cannot satisfy the existing
`state.get('last exit code') == 0` completion check. The already observed
`78: EX_CONFIG` case remains failure code 78. Unknown status strings, invalid PIDs,
duplicate fields and unrelated manager source are not broadened by this change.

The observed parser fragments and their provenance are stored in
`tests/fixtures/macos_launchctl_observed_parsers.json`. The fixtures are source
code, not invented live execution evidence. Both original parser functions fail
the synthetic never-exited record. Seventeen local regression tests pass after the
repair, including no-success admission, nonzero exits, nested/duplicate fields,
input hash mismatch, unknown parser source, and create-only output. The exact
captured full r2 module was also patched locally; every AST node outside
`parse_print` is unchanged. The original deadlines, process custody checks and
`no_business_after_unknown` guard remain identical.

## Actual Mac read-only reproduction

Inspection job `1a1b0f5b0e9-fc05-7458` completed with authoritative exit 0,
complete durable output, no timeout, and confirmed terminal publication. It
read the exact r2 source, verified full source SHA-256
`8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4`, constructed
the five-line repair in memory, and verified candidate SHA-256
`59aa264489cc8ebea2943a0a7bab68c419da52d645532391ec369b973d555941` against
the prepared local candidate. It compiled only the AST for the pure `parse_print`
function; it did not import or run a manager.

The same observed launchctl bytes were passed to the original and repaired
functions. Only the following safe top-level status fields were published; argv,
environment, credentials, private plan contents and their digests were excluded.

| Existing GUI registration | Current state | Runs | PID | Raw last exit code | Pure parser result |
| --- | --- | ---: | ---: | --- | --- |
| `mac-authbus-4e808-owner-r1.server` | not running | 1 | absent | `78: EX_CONFIG` | r2 and repaired parsers retain failure 78 |
| `mac-authbus-4e808-home-r2.server` | running | 1 | 32527 | `(never exited)` | original r2 refuses `typed_launchctl_integer`; repaired parser returns `None` |

The repaired result **does not satisfy numeric zero exit** for either record.
The live r2 observation reproduces the identified parser defect with the actual
source and actual service output. The original failed run did not preserve its
raw launchctl output, so its historical rejected literal remains unrecorded.
The new observation does not prove that either old registration or lineage has
been safely reconciled, and does not authorize a business retry. A process
shown as running still needs its original generation, plan, PID, birth and
executable custody checks before cleanup or reuse.

The inspection source, exact authoritative tool status, exact process-read
receipt, and sanitized stdout are saved alongside this document. No remote file
was changed. The CLI preparer now reads at most 1 MiB plus one byte before
validating the source-size ceiling, following independent review. The reviewer
passed all original 16 tests and the unchanged non-parser full-module AST; the
final local suite passes 17 tests including oversized-input refusal.

## Credential and replacement boundary

The r2 result explicitly describes its projection as
`frozen_previously_verified_generation`, with
`latestActiveGenerationClaimed=false` and `providerAvailabilityQualified=false`.
Its input-closure result says current production databases were not opened.
Neither this audit nor the parser repair substitutes a new credential source.
The failed r2 attempt cannot establish active provider validity, current-client
cutover, business restart, rollback, or complete replacement of OpenBao 2.7.1.

The production transport and independent coordinator remain separate candidates:

- `tools/authbus/production-transport/qualification/current-mac-stage-20261103.md`
  records earlier real SQLite/SDK migration and cold-start checks, together with
  the expired-access-credential and untested-provider boundary.
- `tools/authbus/authbus_coordinator.py` still requires
  `production_cutover is False`; its explicit source/owner authorization,
  manifest-CAS, confirmed journal and no-replay-on-unknown rules must be preserved.
- `tools/authbus/README.md` describes the uninstalled coordinator and unsupported
  refresh-scheduler actions. Parsing launchd state does not complete those gaps.

After the original GUI registration and lineages are reconciled, any new attempt
needs one fresh explicit source binding and the unchanged original admission
and business deadlines. The earlier bootstrap is not replay authorization.

## Handoff of existing registration recovery

A separate read-only host-process observation at Unix millisecond
1793970417156 identifies PID 32527 as the Python kernel image, UID 501, with
`ps` birth identity `Fri Nov 6 20:49:39 2026`. It is not an observation of the
HeptaBao server image. The contemporaneous bounded `launchd` directory listing
contains the initial bootstrap intent, both server plans and the cleanup intent;
it contains no ready, admission or exec-ready receipt. The original terminal
entry has `wrapperIdentity=null`, `execIdentity=null`, no recorded owned groups,
and only a completed bootstrap attempt. The original failure-cleanup method
requires one of those recorded identities before signaling a live PID.

The original wrapper source has a 30-second budget starting at its own `START`.
No ready receipt published `START` or `UNTIL`, so process wall-clock age by itself
cannot establish exactly when that monotonic budget began if interpreter startup
or imports stalled. No deadline was extended and no new business attempt was
started. Recovery is handed to the separate custody reviewer to bind the exact
registered argv, immutable plan, current birth and executable before proposing a
new explicit cleanup intent. This parser repair alone cannot restore missing
historical custody or justify repeating the original cleanup call.
