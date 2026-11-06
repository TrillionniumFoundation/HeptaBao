# HeptaBao personal and agent credentials

This work implements separate credential-use and personal-vault paths on the
PR #160 integration base. All observations below use synthetic credentials.
No phase inherits an older source revision's passing result. Production use,
full OpenBao replacement and independent security review remain unqualified.

Updated: 2026-11-06. Browser and Android observations are being collected on
separately frozen candidates; this document distinguishes completed evidence
from implementation in progress.

## Acceptance matrix

| Phase | Implemented and observed | Remaining boundary |
| --- | --- | --- |
| P0: selected credential service | Normal Linux server entry point, loopback TLS/private CA, Shamir, root-namespace KV2, userpass and scoped tokens: **57/57**, including real expiry/revocation, ACL denials, SIGKILL and cold recovery. The separately frozen r3 QA revision passed all three complete destructive, network-partition and replay-epoch profiles against that original server binary. | This is the fixed single-node/three-node synthetic scope. Older r1/r2 failures remain recorded; full compatibility, other snapshot regressions and broad replacement remain HOLD. |
| P1: agent/developer use | Executable Rust CLI/SDK, local socket broker, exact-operation owner grants, controlled loopback API use, SSHSIG and actual `git commit -S` followed by `git verify-commit`. The bounded-read repair passed **19/19 on Linux and separately 19/19 on macOS**: the original thirteen tests plus six real socket regressions. Durable unknown outcomes are never automatically retried. | Task/run labels are owner-issued, not attested HeptaRuntime identities. Current runtime aliases use the same trusted OS account. External HTTPS APIs and SSH login are unsupported. |
| P2: personal vault | Encrypted login/note/API entries, password generation, RFC-vector TOTP, local health, bounded sessions, offline CLI, encrypted backup/recovery, explicit JSON import/export and password change. Independent process and actual SIGKILL recovery observed. The separate frozen macOS vault passed **14/14**. | The observed Linux and macOS CLI/filesystem combinations trust the owner account; no hostile-owner isolation, hardware anti-rollback, third-party import or independent security review. |
| P3: daily clients | Real headed Chromium/native-host login and rejection profile: **26/26**. Physical two-device opaque synchronization: **14 stages and 18 authenticated transfers** across ai395 and ROG retained conflicting edits and restored both histories. Native backpressure fix: **8/8**. | The latest c7/QA14 Android run r11 failed after **2/12** completed checks, as did c6/QA13 run r10. The authorization-rejection cause remains undetermined. Browser observation covers the fixed Chrome 157 Linux combination. Sync is an explicit CLI workflow, not an automatic daemon or field merger. |
| P4: extended vault | The fixed Android native fixture completed real CredentialManager create/get, ordinary encrypted SAF backup, same-device app-data reset/new-process restore, and independent RP stale-backup rejection. The r8 original ledger remains **16 passed, 2 failed**; three separately declared supplements passed **3/3**. | Original G07/G10 failures and G08's causal limit remain recorded; M05 has a launch-audit gap. This is one synthetic native fixture and same-device recovery, not physical two-device Passkey migration. Credential exchange, sharing, device revocation and additional platforms remain unsupported. **P4 remains unqualified.** |
| P5: production adoption | The fixed old/new broker binaries completed **27/27** real same-format upgrade/rollback checks, including interrupted-operation fencing and exact denial behavior. Published `3ada83a` passed its own synthetic-core CI and both workflow-trust combinations. The clean `c447536` Python preflight passed 1988 tests with five explicit platform skips. | The `2280c36` full workflow retained three HA failures before cancellation; `7e77aa3` was cancelled and `3ada83a` has not passed the full gate. Independent security review, measured long-term stability, signed releases, arbitrary-version/data-format migration and operational support remain incomplete. |

These are separate acceptance boundaries. For example, a real local Git signing
test does not establish a malicious same-account agent cannot read owner files;
two real devices do not establish automatic background sync or a separate
server security principal; a mocked browser scheduling test is not real browser
execution evidence.

## Source and artifact provenance

The frozen core source is
`a1b6ff4506f52082a0893b7167fafb4ff95610be`, tree
`5f685c1aaf647f016afed0555a6710cd4a76c317`, based on
`8f3dd8353aaf9642ad58f7716b0c14813d09983d` (PR #160).

The [evidence manifest](../../qa/personal_credentials/evidence/20261106/manifest.json)
pins byte-identical original receipts, including build inputs, original process
handles and artifact digests. A named-ref Git bundle preserves the original
tested local commit objects and requires the public PR #160 base. Publishing
the same source through an API that supplies different commit metadata does not
change the original receipts or authorize relabeling them to a new commit.

Run `python3 -B qa/personal_credentials/verify_evidence.py` to check the archive's
bounded index, unique names, exact lengths and SHA-256 values. Its 24 synthetic
self-tests include tampering, unsafe paths, missing/extra files and independent
CLI exit-status checks. This verifies archive integrity only. Receipt contents
and test outcomes are opaque to it; a retained failed receipt can correctly
pass an integrity check. It grants no authenticity or qualification authority.

| Observed artifact | SHA-256 |
| --- | --- |
| ROG normal `heptabao-server` build | `c27a0c223d227d3b2b5292e1e3ab6cf0230562baee36b6465b22a7ddf17be172` |
| ai395 original broker | `389cc15a0926ef9f30cd149b56424a484dfad600a308252ed111f2869b5b9175` |
| ai395 bounded-read repair broker | `6f9324480fb9e9f9ce08a182cd9822d5236cb866146578d5851845719319d9f5` |
| macOS bounded-read repair broker | `efa4b1f9394f3a2afc8d63d3812e9e8997b6809c16feb34dc168519d58e5b466` |
| macOS frozen `c447536` vault | `237d8e1f5f5bc6e6a6754dd678487e5b8b6feabf7991bc81d3a69f94056dad97` |
| ai395 final vault | `b0cccc3c204d6be5e2e20ee5830e34cb1242d3ac03ea42cd3b7e26a3ea416358` |
| ai395 final browser host | `e6eaa6210b6d8a6480a20d4d1be65c221c548e08803ed76558a7b72eb3cd2f7d` |
| ai395 final sync CLI | `c82a17b0c148423b6223dd4a77540cd9c188f354c76309944cbb2091f2836663` |

Cargo's test commands rebuilt the ai395 vault executable after the first combined
build. The final artifact receipt explicitly distinguishes that binary from the
initial build output; subsequent browser and physical synchronization runs used
the frozen final copy. Build attribution based on sequential Cargo execution and
compiler logs is labeled as an inference in that receipt.

The [P0 report](../../qa/personal_credentials/P0_STATUS.md) retains the older
174/176 and 180/181 failures as historical results. They are not silently replaced
by the newer, smaller 57-case profile. x230 formal-34 preflight remains preflight.

### Actual HA follow-up on the fixed server

The full-workflow failure exposed a QA cleanup mismatch: a bootstrap-negative
child had already exited with the required status 1 and exact rejection
diagnostic, but cleanup still required a SIGKILL exit. The corrected path accepts
status 1 only after that exact observation; failed assertions still preserve
their original error while reaping the owned child. The separate real-process
owner controls cover the correct rejection, an exit-zero counterexample and a
wrong diagnostic. This does not change the process-owner library globally.

All three r1 real profiles then failed when the legacy JSON helper decoded the
native gzip snapshot response as UTF-8 JSON. The original failures and complete
Runtime invocation/termination records remain in
[the r1 packet](../../qa/personal_credentials/evidence/20261106/ha-cleanup-r1-remote-originals.tar.gz).

The r2 helper performs one native download with private-CA verification, no
proxy or redirect, exact response framing, a 32 MiB wire bound and a 64 MiB
expanded bound. It rejects truncated, corrupt, concatenated or trailing gzip
data. Its report explicitly does not claim archive authenticity or successful
restore. Against the same `c27a0c22` server, the complete destructive and
network-partition profiles passed, with 22 and 66 recorded scenarios
respectively. Replay stopped after 46 recorded scenarios at
`multi_epoch_snapshot_purged_pre_rejoin_log_frontier`. These overlapping
scenario counts are not added into a new test denominator. All original
children were reaped, without fallback cleanup or deadline expiry. See the
[r2 summary](../../qa/personal_credentials/evidence/20261106/ha-snapshot-r2-real-profiles.public.json)
and [complete original packet](../../qa/personal_credentials/evidence/20261106/ha-snapshot-r2-remote-originals.tar.gz).

The r3 QA source uses the existing authenticated compact operation before the
separate native export. It captures the applied index first, keeps all three
requests inside the original shared budget, never replays the mutation and
requires the observed purge to cover that captured index. A positive purge
left over from an older snapshot is insufficient. The exact original `a1b6ff4`
server source was checked independently to establish this route distinction.
New host controls passed 12/12 for the maintenance/frontier changes and 25/25
for the original cleanup/download checks. All three new real profiles then
completed successfully: destructive recorded 22 scenarios, partition 66 and
replay 53. Replay observed target applied index 61, snapshot index 61 and purge
index 61 after two read-only polls, then completed lagging-voter recovery,
leadership, latest-epoch writes and acknowledged-value read-back. Original
240/360/600-second outer budgets were unchanged; no deadline or fallback cleanup
was used and every registered original child was reaped. These results bind
the exact `403d10c5`/`a9cfb31d`/`73bac79c` QA files and original `c27a0c22`
server, not the entire latest PR tree. Neither r1 nor r2 was relabeled.
The [r3 summary](../../qa/personal_credentials/evidence/20261106/ha-snapshot-r3-real-profiles.public.json)
and [86-member original packet](../../qa/personal_credentials/evidence/20261106/ha-snapshot-r3-originals.tar.gz)
retain all three reports, original process ownership/termination records, host
controls, frozen source and actual Runtime inputs.

### Evidence recovery boundary

After the executor was replaced, the old temporary working directory was
unavailable. The clean public `7e77aa3` tree was cloned again and checked against
tree `44b5f1ae9f0c7ff1994d096c26f2456bc4a75c06`. Unpublished sources were
recovered only where their complete bytes matched their previously recorded
hashes. The remote phone, HA and upgrade packets survived and were read back
with pinned versions, exact lengths, EOF and full SHA-256 checks.

Some local-only root and peer host-test outputs, the r9 local supplementary
packet and unpublished grouping archives were unavailable. Their observed
metadata does not substitute for those missing originals. New executions and
new grouping containers are explicitly labeled as new. The
[recovery packet](../../qa/personal_credentials/evidence/20261106/workspace-recovery-originals-and-limits.tar.gz)
records those limits, original read envelopes and recovered source identities.

### Separately qualified Ed25519-only broker

The internal [dependency review](DEPENDENCY_REVIEW.md) found two RustSec version
matches reached through unused RSA/ECDSA features at baseline `8cd4761`.
Local source `c447536ae0343731d84c18291d2dcd712b3bea08`, tree
`50835fd4df6e7bdd2b551941a3fa012281c931c2`, narrows only the broker's feature
selection. Its fixed executable SHA-256 is
`6fe0b6c78213e4bb1184ca4c4be7fc3e44dce4117f22097aab14efa567ac8a08`.
All eleven existing real process tests and two new valid-key rejection tests
passed against that exact executable; its bytes and both test executables were
checked before and after execution. The original failed runner attempt is
preserved alongside the successful continuation.

The selected Linux and macOS normal graphs no longer contain `rsa` or
`crypto-bigint`. The server still selects broader crypto features, and the
full-workspace graph could not be resolved offline because a dependency was
not cached. This is a selected-build correction, not a whole-workspace clean
audit. New vault/browser/sync artifacts built in that run receive only their
actual build/Clippy observations; older functional results remain bound to
the original artifacts above.

## Browser observation

The original r10 run on ai395 used clean source
`802c57cdf386e2dbfb4da9c20dbdd37700343197`, tree
`e8eb1d2bdb0479c10dd5bad2683b6532dbde4cc0`, with the frozen native host and
vault binaries above. Chrome for Testing was `157.0.8103.38`, driven by
Playwright `1.57.0` in real headed mode under owned Xvfb/Openbox processes.
The actual unchanged extension action was invoked through CDP
`Extensions.triggerAction`, which granted `activeTab` for the exact tab.
The fixture accepted its own self-signed TLS certificate; this was not a TLS
trust qualification or a physical-monitor observation.

All 26 required observations completed: actual action popup, exact-origin item
selection, real native-messaging fill, no automatic submit, fill-and-lock
acknowledgement, explicitly submitted successful login, locked/fake-origin stale
selection denials, nine independently controlled real-renderer negative cases,
native-session closure and unchanged source/artifact identities. Renderer
component cases are labeled separately from the full extension/native path.

The original report SHA-256 is
`9517ac358ca1b9ff8ef9cf2f0b497f4a9f2da9a923b808736a004311a174b4a7`.
Earlier failed observations remain in the archive. They exposed the difference
between opening popup UI and granting `activeTab`, parent-window focus reporting
while an action popup is active, and real popup ports omitting a sender document
ID. The final implementation binds the exact static extension-page port once
to the browser's unique registered popup context. This is a registry association
for this scope, not a claim that every port carries its own document ID.

The worker has 64 deterministic scheduling tests. These use mocked Chrome APIs
and remain separate from the 26-case actual-browser observation.

## Android candidates and independent observations

The Autofill target is one owned Motorola XT2551-3 running Android 16/API 36.
The provider accepts only the exact synthetic native fixture package, signing
certificate, activity and native view mapping. It has no Internet permission,
is not debuggable and disables Android backup. Filling requires a fresh local
unlock and explicit approval; the result is an ephemeral authenticated dataset.

Autofill candidate 4 passed 12 Rust-to-Java format checks but did not complete
its phone profile. The five original phone reports remain archived: r1 completed
0 of 12 cases, and r2 through r5 each completed 1 of 12. These runs exposed
driver foreground/task-stack problems and an authentication activity that did
not remain visible after choosing the system candidate. The later diagnostic
activity may itself change lifecycle state, so it does not prove the original
failure's cause. Every run restored its original Autofill setting and removed
only its own installed packages; a separate final probe confirmed the release.

Candidate 5 changes the handling of `TRIM_MEMORY_UI_HIDDEN` and adds bounded
authentication-entry diagnostics while preserving request cancellation,
background invalidation, timers and final caller/target checks. Its 18 source
files match its build receipt exactly, and its new Rust-to-Java profile is
12/12. Its own QA8 phone run r6 still failed after **1/12** completed checks:
the authorization Activity was not observed. The original setting was restored
and all three owned packages removed. Read-only diagnostics found no own Auth
Activity start or explicit background-launch refusal; an empty fixed-tag log
does not establish a root cause. The later `memory_locked` observation came
after opening the provider's Main Activity and is explicitly not proof of the
earlier state. The UI-hidden change has not been shown to solve the failure.
Both original source archives, build receipts and failed device results are
retained. A full successful device profile is still required.

The same c5 APK's QA9 run r7 also stopped after **1/12**. The ordinary Request
Autofill button was pressed and the system menu was visible, but the driver's
foreground guard classified the context as unavailable/other and did not tap
the menu. Immediately beforehand, the package-scoped query found no own
PendingIntent record. Two `memory_pressure_locked` events were observed before
opening the diagnostic Activity. Those events do not identify the callback
level or prove physical memory pressure, and absence of a PendingIntent does
not distinguish cancellation from one-shot delivery. These observations do
not retroactively establish r6's cause. The fourteen original r7 packet files
and their index retain the failed run, actual wrapper and durable Runtime
requests/results. Independent release verification confirmed the original
Autofill setting and exact installed/retained absence of all three owned
packages before handing the phone back to the Passkey run.

Candidate 6 now separates plaintext invalidation from the single opaque
locked challenge. Every trim notification clears login/handoff and advances
the KDF epoch; the existing challenge keeps its original PendingIntent,
timer and deadline. Cancellation, expiry, import, replacement and Auth
backgrounding still invalidate the full request. A stale KDF result is
cleared before fresh input is enabled for the same still-live foreground
request. The author and a separate internal reviewer each ran all sixteen
host lifecycle checks on the actual two product classes, using minimal
Android, crypto and policy stubs. These results do not exercise the actual
Android lifecycle, PendingIntent delivery or Autofill framework, and do not
qualify candidate 6 on the device.

The c6 source archive contains twenty exact files: eighteen product files and
two build/fixture scripts. Its fifty build commands returned zero, twelve
Rust-to-Java checks passed, and the separate actual-APK review passed twelve
checks of signatures, decoded manifests, backup exclusions and fixed source
identities. The transport patch was replayed only on a new copy and verified
against the full target APK digest; this is transport verification, not an
upgrade/rollback qualification.

The QA10 driver passed its initial 44 host checks but was withheld from the
phone after internal source review found a client-output ambiguity in
`dumpsys activity -p`. Its counterexample and original passing host report
remain archived together. QA11 uses the server's fixed `top-resumed` dump
without client output, verifies unique fields and binds the exact parent
Window, task, user and Activity. The author and root each passed 57 host
checks; an additional internal reviewer executed two targeted controls.
Those checks do not establish OEM format compatibility.

The c6/QA11 phone run r8 subsequently failed after **1/12**, before touching
the visible Autofill menu or entering a master password. The closed diagnostic
was `activity_identity_unavailable`. Before the later diagnostic Activity,
the current provider log contained
`trim_background_before_p1l0h0_after_p1l0h0_epoch_advanced` and the package
query observed one own PendingIntent. This establishes that the opaque request
survived that observed trim; it does not establish successful delivery or
filling. The exact OEM text responsible for the refusal was not retained and
must not be inferred from this code alone. Independent release verification
confirmed the original Autofill setting, installed and retained absence of
all three owned packages, and the driver's failed terminal state.

QA12 subsequently adds bounded phase/count/shape diagnostics and accepts the
canonical integer ActivityRecord representation emitted by the
[Android 16 QPR2 ActivityRecord source](https://android.googlesource.com/platform/frameworks/base/+/android16-qpr2-release/services/core/java/com/android/server/wm/ActivityRecord.java),
blob `aa8d93e991328f9fcfa8e99a3cc431fda9596a47`. Record tokens remain literal;
different decimal/hexadecimal spellings are never merged by numeric value.
Incomplete, finishing/exiting, duplicate, null and wrong-target records remain
refused. Fifteen critical function/method ASTs and the original twelve-case
inventory remain unchanged. The author and root each passed **66/66** host
checks, and an additional reviewer read the full diff without claiming a
third execution. This source-backed compatibility correction does not prove
the old r8 phone text or qualify a new phone run.

The c6/QA12 phone run r9 again failed after **1/12** completed checks. This time
the actual server WMS/top-resumed identities passed, including the canonical
decimal ActivityRecord representation, and the ordinary system-menu touch was
issued with a fresh bound observation. The provider recorded `auth_context_bound`
and a closed trim event with no pending request, plaintext login or handoff.
Those bits do not prove a successful fill, request consumption or a lifecycle
cause.

The preserved failure expected the native fixture title
`HeptaBao synthetic native login` while the system Autofill UI was still visible.
Combined with the unchanged driver's control flow, this supports a failure in
the return wait after Cancel. It does not support the initial interpretation
that the Auth title had never appeared. No master password or successful fill
was observed, and the uncompleted locked-fill case stays uncompleted. Independent
release verification confirmed the original setting and installed/retained
absence of all three owned packages before the phone changed owners. A new
driver candidate must retain the full twelve-case inventory and validate the
original WMS window, ActivityRecord, task and owner before any ordinary popup
dismissal.

The [r9 result](../../qa/personal_credentials/evidence/20261106/android-c6-r9-phone.public.json)
and [available original packet](../../qa/personal_credentials/evidence/20261106/android-c6-r9-available-originals.tar.gz)
retain the failed outcome and independent release. The old local 22-member
supplement was not completely recovered; eleven original files, their original
remote carrier and the root release observations are available.

QA13 now captures the original WMS window, ActivityRecord, task and owner at
the existing fixture setup. A return may dismiss only a positively bound locked
placeholder, after refusing any visible plaintext-fill presentation. The one
ordinary Back input remains explicitly bound to display 0 by the existing
input wrapper. Fresh focus and the same original identity are required before
and after the action and again after observing the fixture title. This is not
an observation of Android's internal Autofill session ID.

Review of the first 100-check candidate found late query results could escape
the three-second transition deadline and a title observation needed a final
identity check. Five actual new counterexamples failed against that held
candidate. The corrected `5e6ba13b` source passed all 66 existing plus 38 new
host checks; a peer independently reran those 38 with zero external-process
attempts. That [separate peer packet](../../qa/personal_credentials/evidence/20261106/android-qa13-peer-review-originals.tar.gz)
retains the actual harness, outputs, external-call audit and source comparison.
The original twelve-case inventory, cancellation time limits and
product APK are unchanged. The [host packet](../../qa/personal_credentials/evidence/20261106/android-qa13-host-originals.tar.gz)
retains both candidates, all original outputs and the counterexample failures.
No QA13 phone success is inferred from this host evidence.

The subsequent c6/QA13 run r10 completed the actual ciphertext import and
locked-fill rejection, then failed at the wrong-master-password case: the
driver expected `Unlock failed`, while AuthActivity showed `Authorization
rejected`. It remains **2/12**, with no successful fill or later case inferred.
The elapsed whole-profile time includes an earlier request and is not proof
that the current request's 120-second lifetime expired. The later diagnostic
MainActivity decision also follows a lifecycle change and cannot identify the
original rejection branch.

Candidate c7 adds only closed diagnostic codes and state bits around existing
authorization/lifecycle decisions; it retains the existing guards, lifetime and
operation order. QA14 extends only the diagnostic code filter. Its original
SDK build completed 50 commands, the actual Rust/Java format checks passed
12/12, and the separately decoded APK review passed 12/12. The candidate's
first host packet used a colliding test filename; the corrected second packet
renames the new lifecycle test so the original diagnostic tests are preserved.
Both original packets remain available.

Actual c7/QA14 run r11 again completed only import and locked-fill rejection,
then encountered the same `Authorization rejected` text in the wrong-master
case: **2/12**, failed, with a complete durable Runtime result and no timeout.
Its failure-time filtered provider log result is `available: true, codes: []`.
The driver did not retain raw byte counts, discarded-line counts or the process
identity relationship between Auth entry and collection. This result cannot
show whether events were absent, discarded or collected from a later process;
it cannot choose the pre-KDF or post-KDF rejection branch. No self-Autofill,
cancellation, process restart or actual timer-expiry cause is established.

The [r10/c7/r11 history packet](../../qa/personal_credentials/evidence/20261106/android-r10-c7-r11-public-history.tar.gz)
retains six byte-identical candidate, build, failed-phone and internal-review
archives, the additional read-only log-gap review and the original release
observations. Both phone runs restored the original Autofill setting and
confirmed all three owned packages absent from installed and retained-package
queries. Those observations apply to each recorded handoff. The next c8/QA15
candidate is diagnostic work in progress and has no inherited phone result.

Passkey candidate r4 has 28 source files matching its original build inventory.
It implements a separate Android credential provider for one pinned native
fixture and relying-party ID. Its password-protected `.hbv` store preserves the
Rust format and recovery wrapper. The ordinary app uses local Storage Access
Framework documents for bounded encrypted import/export and fresh private
stores for restore; these UI paths require their own phone observation.

The r4 phone run subsequently selected the fixed encrypted seed through the
ordinary SAF UI, then reported `unsafe_directory` before any password entry.
Its eighteen-case ledger records M01 failed, M07 cleanup passed and the other
sixteen cases blocked. No phone passkey was created and the RP recorded zero
create/get operations. Final cleanup verified all three original settings,
successful exact absence queries for the three owned packages, removal of the
owned reverse mapping and removal of tracked synthetic documents/media rows.

That run also exposed a missing package URI in the app's settings shortcut
and a platform settings selection that changed the Autofill component to the
verified system CredentialManager bridge. The original guard stopped on that
unexpected change. A separately reviewed, exact-state correction restored the
original Autofill value while preserving both credential fields and the
original failed observation; final cleanup then restored the complete original
state. No original allowlist was retroactively expanded.

The observed phone error is `unsafe_directory`. The
[AOSP Android 16 QPR2 ContextImpl source](https://android.googlesource.com/platform/frameworks/base/+/android16-qpr2-release/core/java/android/app/ContextImpl.java)
(file blob `a1cbb22021fcf7d24b737a94534b0cb5899d026f`) suggests the platform
`files` directory's initial 0771 mode explains the strict 0700 check,
but the private phone directory mode was not directly measured. A new r5b
candidate restricts normalization to the fixed Context files leaf, checks its
type/UID/mode and stable descriptor identity, tightens it to 0700 and retains
strict later checks. The first r5 SDK34 compile failed because its SDK stub had
no `OsConstants.O_DIRECTORY`; the original compiler stderr and failed receipt
are retained. That failed source and the corrected r5b source archive remain
separate originals. New builds and device observations
must retain their own identities.

The r5b build receipt `b46691b4...` binds all 28 product source files to that
archive before and after its 48 successful build/inspection commands. Its own
host profile `4db33700...` passed ten top-level checks, including the separate
17- and 18-check negative groups. Both originals are archived. A new 615-byte
phone seed, digest `bb527d9a...`, was produced by the frozen core `b0cccc3c`
vault executable, with the original `a1b6ff4` source/build receipt and actual
producer wrapper separately bound. This closes the new seed's producer chain;
it does not change the r4 seed's historical provenance limit.

The r5b phone run selected that exact seed through ordinary SAF and returned
`operation_failed`, before any master-password entry. Its eighteen-case ledger
records M01 failed, M07 cleanup passed and sixteen dependent cases blocked.
Final cleanup restored all three original settings and confirmed absence of
the three owned packages, reverse mapping and tracked synthetic document,
media index and directory. All thirteen owned jobs were terminal and the RP
was stopped before the phone was released. No phone CredentialManager
create/get result has been established.
This differs from r4's `unsafe_directory` observation. The frozen candidate's
generic error does not reveal the exception class or failing stage, so a cause
has not yet been established. Its host checks do not override the phone failure.

Candidate r6 preserves the staging operation and adds closed, bounded error
codes for unexpected staging exceptions. Forty-one exact source-frame
bindings identify only known sites; an unknown/absent line returns UNKNOWN,
without guessing a caller. The mapper exposes no exception messages, raw
stack traces, paths, URIs or credential material. Existing typed failures,
ENOENT handling and `save_outcome_unknown` behavior remain unchanged. The
fourteen host diagnostic checks passed for the author and an independent
internal rerun, separately from Android execution.

Its source archive `90d66751...`, build receipt `cb70894e...` and host result
`69a03e93...` are archived as new originals. All twenty-nine product files and
four QA files match the source archive, and the build's before/after source
inventories agree. Its ten host cryptography/format checks passed, with
`android_device_exercised=false` and `credential_manager_exercised=false`.
The newly pinned r6 phone profile retains all eighteen cases and their causal
requirements; it reuses only the still-empty seed with the established
`b0cccc3c` producer chain.

The r6 phone selected that seed through ordinary SAF and reported
`stage_failed:PUBLISH_LINK:ERRNO:EACCES`. The fixed source and actual DEX line
table bind this to the initial `Os.link` publication attempt. M01 failed,
M07 cleanup passed and sixteen cases remained blocked; no password was entered
and no CredentialManager create/get operation ran. Successful UI phase
commands did not pass M01. An earlier media-index poll timed out on the
`/sdcard` alias; a read-only canonical-path query reconciled the same existing
document without repeating its creation. Both observations remain archived.

The [Android 16 QPR2 app policy](https://android.googlesource.com/platform/system/sepolicy/+/android16-qpr2-release/private/app_neverallows.te),
blob `941472d374b73007e406641f038793ad69146661`, prohibits untrusted-app file
hard links. This is consistent with the observed EACCES, but no OEM AVC log
was collected to prove that specific cause. Final r6 cleanup restored all
three settings, removed the exact owned packages, reverse mapping and tracked
documents/media rows/directory, and stopped the RP. All eight recorded jobs
were terminal before release. The full packet retains fifty-seven original
files plus its manifest, including actual execution inputs and failed-poll
stderr.

Candidate r7 replaces initial hard-link publication with a synchronized
temporary file, a second ciphertext/absence comparison, atomic rename,
parent synchronization and read-back under an explicit live Guard. It
protects cooperating writers; it does not provide kernel NOREPLACE against
same-UID code that ignores the lock. A process-wide admission token is held
before any lockfile open so another local attempt cannot close a descriptor
and release the process's existing file lock. Raw data descriptors have one
explicit owner; the lock uses an owning PFD duplicate, closing the original
before locking. Uncertain lock cleanup fences that process, and publication
followed by an uncertain result requires inspection after reopening.

The unchanged actual r7 storage and diagnostic classes passed thirty-four
host fault cases in the internal review and a separate root execution,
including short writes, the second CAS, unknown cleanup, idempotent and
cross-thread close, collision preservation and a fresh JVM reopening the
same prior fenced directory. The Android APIs and lock bookkeeping are
explicit mocks; these are not ART/OEM filesystem or cryptography results.
The original 33-case execution is also retained.

The final r7 source archive `e2e79c7e...` matches all twenty-nine product and
four QA files; the earlier README checkpoint `93e1c7fa...` remains distinct.
Build receipt `e12bd68d...` has forty-eight successful commands and unchanged
source inventories. Its new ten-case host format/cryptography result is
`173a3777...`. Actual javac/DEX inspection found thirty-six of thirty-nine
diagnostic positions; the three absent positions are multiline open-argument
continuations with their operation's first line present. Unknown positions
still report UNKNOWN. The new r7 phone declaration retains all eighteen
cases and separately pins this build, host result, line check and four APKs.
No phone result is inherited from an earlier candidate.

The completed r7 phone ledger contains eighteen unique cases: M01, M02, M04,
G01, G08, G09, G10 and M07 passed; M03 failed; M05, M06, G02 through G07 and
G11 are blocked. M02 traversed the actual Android CredentialManager, the
provider's ordinary approval UI and independent RP registration. M04 exported
and read back the encrypted backup through ordinary SAF. M03 reported
`platform_invocation_failed`; the RP accepted zero authentications and its
counter stayed zero. No provider reset was executed.

Source inspection found that the fixed fixture called `addAllowedProvider`
without declaring the platform's normal
[`CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS` permission](https://developer.android.com/reference/android/Manifest.permission#CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS).
This is a source-backed explanation consistent with the failure, not an
observed OEM exception class. No runtime permission grant or allowlist
weakening was used. The RP's later natural 3600-second timeout is retained as
a process outcome and is not used as evidence for any negative case.

The [r7 phone packet](../../qa/personal_credentials/evidence/20261106/passkey-r7-phone-originals.tar.gz)
preserves 381 original files plus its manifest, all 29 actual Runtime
invocations and terminal observations, phase failures, the complete
[case ledger](../../qa/personal_credentials/evidence/20261106/passkey-r7-phone-cases.public.json)
and final release. Every one of its 286 phase-result citation occurrences was
resolved to the exact original file digest. Cleanup verified all three original
settings, installed/retained absence of the three owned packages, removal of
owned documents/media entries and reverse mapping, and a closed RP listener.

The r8 product delta is the fixture's normal
`CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS` permission. All other product
source bytes and the `b16e8291` provider APK are unchanged. Build receipt
`97a6daec...` records 33 successful SDK commands and separately verifies all
three new fixture APK manifests and certificates. The r7 provider's host/DEX
evidence is reused with its original identity; it is not a new r8 host
execution. The r8 declaration retains all eighteen cases and pins the new
input/reset helpers, artifact identities and backup roles. The
[ingress packet](../../qa/personal_credentials/evidence/20261106/passkey-r8-ingress-originals.tar.gz)
preserves the new build and author host controls.

The completed r8 original ledger records **16 passed and 2 failed**, with all
eighteen cases executed and none blocked or missing. Actual Android
CredentialManager create and get responses were accepted by the independent
RP. Ordinary SAF exported and read back an encrypted backup. M05 then cleared
only the initially absent, exact-owned provider's app data under its reviewed
checkpoint, observed a new process, and restored through ordinary SAF. M06
authenticated the same credential and SPKI public key with the RP counter
advancing from 1 to 2 and authenticator flags 29 after restore. This is same-device OS
app-data reset/new-process recovery; it does not establish physical two-device
Passkey migration or direct inspection of a private store's inode.

G11 used a separately observed current recovery backup and retained the actual
older M04 ciphertext as stale input. Its separately admitted single reset and
ordinary SAF restoration produced a real CredentialManager assertion that the
RP rejected with `counter_rollback_or_replay`; the accepted key and counter
stayed unchanged. Counters advanced only through ordinary create/get operations
and RP validation. Neither side's counter was manually altered to obtain the
result. Both M05 and G11 retain their individual intent, result and completion
witness; no third reset or uncertain reset replay was performed.

Original G07 and G10 remain failed. G07's one-Back controller did not establish
the final cancellation callback within the admitted original request window.
G10 reached `choose_backup_destination_first`, because an earlier Write had
already consumed the destination, and did not test wrong-key rejection.
The original G08 report remains present with an explicit causal limitation:
its refusal also followed a previously consumed destination, so that result
alone did not prove clearing a newly selected, unconsumed destination.

Three separate one-case supplements then passed **3/3**, without changing the
original eighteen-case denominator. Fresh G07 observed the same request's
Operation Back followed by the system chooser Back, the exact cancellation
callback, unchanged RP acceptance and the original 180/300-second timing
bounds. Fresh G08 selected an unconsumed target before beginning a new picker
and cancelling; Write was refused and the nonempty target digest stayed
unchanged. Fresh G10 used a newly selected target, reached
`wrong_key_or_corrupt` and preserved that target. The 615-byte ciphertext used
to make these two targets nonempty was explicit QA fixture preparation, not a
product export. The unconsumed-target statement is their precondition; G10's
attempted Write consumes the selected URI when it begins.

G02's original Runtime job remains failed with exit 1: after the actual
wrong-password rejection and timing assertions, its create-only report writer
collided with an existing control-result filename. An independently reviewed,
read-only reconciliation supplies the case's behavior result; no phone action
was repeated. G11's auxiliary export also retains its original mistaken summary
reference and the distinct correction pointing to the actual new backup
receipt. Neither original result was rewritten.

M05's ordinary-restore launch reported `audit_recorded=false`. Later product
success and a durable terminal outcome do not repair that control-plane audit
gap. The host-only output-materialization job
`1a1b1b76f32-fc05-7a72` has no observed terminal status; its files were separately
read and hashed. The later final packet job `1a1b1c54169-fc05-7abe` completed
successfully with exit zero and durable, complete output. That separate
success does not supply the earlier job's missing terminal observation.

The [r8 final public packet](../../qa/personal_credentials/evidence/20261106/passkey-r8-final-public-evidence.tar.gz)
groups the unchanged original phone archive, its manifest/receipt/assessment,
the local integrity verification and the actual archive Runtime binding.
The original inner archive has 1,744 regular members, including originals and
explicit derived summaries. It retains all 34 tracked run invocations and
terminal observations, exact stdout/stderr bytes, 1,195 public phase records,
frozen sources, original failures and supplements. Canonical structured
metadata copies are distinguished from original source and log bytes.
The [final internal peer packet](../../qa/personal_credentials/evidence/20261106/passkey-r8-final-internal-peer-review-r1.tar.gz)
adds selected original Runtime bindings and 121 host-only consistency checks.
These are not phone test cases or an external security review.

Final cleanup and an independent release observation verified all three
original settings, installed/retained absence of all three owned packages,
the absent owned reverse mapping and all twelve owned synthetic files, six
directories and corresponding MediaStore rows absent. The original RP emitted
its stopped message and reached terminal state before document cleanup.
All tracked phone jobs were terminal before handoff. This qualifies only the
stated synthetic native-fixture observations on the current device:
`p4_qualified=false` and `production_qualified=false` remain explicit.

The archived r4 packet contains the complete eighteen-case ledger, cleanup and
correction receipts, a twenty-four-attempt index and five actual QA source
files. It does not contain every original inline wrapper's complete argv.
That provenance limit remains explicit; the source files are not presented as
a complete reconstruction of all twenty-four invocations.

The r4 host profile passed 10 top-level checks. Its two nested format/negative
groups passed 17 and 18 checks respectively. Separate Java processes created a
credential and produced signatures verified by the independent RP, advanced
the counter, restored the latest backup into a fresh directory, and reopened
both RP and authenticator state. An older backup whose counter had already
been exceeded was refused. The profile explicitly records
`android_device_exercised=false` and `credential_manager_exercised=false`.

A separate Rust process then restored the final Java ciphertext with the
recovery key into a new private root and reopened it with the password. It
confirmed revision 5, one passkey record, counter 4, backup state and the same
SPKI public-key digest as the independent RP. This is actual cross-language
format/recovery evidence, still separate from the Android system UI profile.
The seed and this first read-back used local binary
`9269c070399493f634055bc9e002ea141988f1368cce8358fcc05bbf98d9bfb1`.
Its independent build provenance has not been established. These observations
must not be attributed to the separately qualified `b0cccc3c` core binary;
the original reports retain their actual identities.

A later independent observation used the frozen ai395 `b0cccc3c` executable,
bound to core source `a1b6ff4` and original final build receipt `fa166952...`.
Three independent processes restored, listed and read the same Java ciphertext
through the recovery-key path. Revision 5, one item, counter 4, backup state and
the RP's original SPKI digest all matched. This closes that reader's source and
artifact binding without retroactively establishing the seed producer's build
provenance. It does not claim a password-path read in that later observation.

| Frozen mobile artifact | SHA-256 | Current evidence boundary |
| --- | --- | --- |
| Autofill candidate 5 provider APK | `5c643afa5a08c6e8dd0baf751fe56dadf0f66947284d119d2da7051f4ab88ff8` | Build/decoded manifest and 12 host format checks; its r6 and r7 phone profiles each failed after 1/12 checks. |
| Autofill candidate 6 provider APK | `10028da82fede388096362d0bf2c6d106bd1e8823a12c17c022f8115adcf262a` | Separate build, 12 host format checks and 12 actual-APK checks; QA11/r8 and QA12/r9 each failed after 1/12. QA13/r10 completed 2/12 before authorization rejection. |
| Autofill candidate 7 provider APK | `164c10fbc97b6db8e6f3dbe1e435f37dae64ec25aae319d0ecda8f10bf5b7c20` | Diagnostic-only candidate: actual SDK build, 12 Rust/Java format checks and 12 decoded-APK checks passed; QA14/r11 failed after 2/12 with an empty filtered log result and an undetermined authorization-rejection cause. |
| Passkey r4 provider APK | `e96218bc0ab1c228120471d5168a336e6b526bfd5e39e1a0a533335300d7c6e8` | Build/decoded manifest and 10 host checks; phone import failed before any credential creation, with all eighteen cases retained. |
| Passkey r5b provider APK | `9985457ba13ddef5c286c6017d6c675cb0e64bafa97f119516a3fc4fcce5fc3a` | Separately fixed source/build and 10 host checks; its first ordinary-SAF phone import returned `operation_failed` before password entry. |
| Passkey r6 provider APK | `0240a545d9ed9518201cfda945a26c5f7dc8742534d1ab21d5e84f23bf9c4ac7` | Separate diagnostic build and 10 host checks; phone M01 failed PUBLISH_LINK/EACCES, cleanup passed, sixteen blocked. |
| Passkey r7/r8 provider APK | `b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459` | The unchanged r7 provider retains its separate storage build, 10 host checks and DEX evidence. Original r7 phone: 8 passed, 1 failed, 9 blocked. With the newly permissioned r8 fixtures: original 18-case ledger 16 passed/2 failed, plus three independent supplements 3/3; original G08's causal limit, M05 audit gap and unqualified P4 scope remain explicit. |

### Case-bound synthetic reset helper

The separate `passkey_reset_provider.py` helper is frozen at SHA-256
`2a21f7bcc013abab41f3eba38f612afb6ec869933aee438053a7a5abc81cf48b`.
That original helper is pinned to r5b and is not admitted for a different
candidate. The r7 declaration requires a separately frozen and reviewed
`passkey_reset_provider_r7.py` before M05 or G11; earlier ordinary cases may
proceed independently of a reset. The r7 helper and its 49 author-defined host
controls were subsequently frozen and reviewed; the completed phone run never
reached a reset admission. The r8 helper adds six backup-role/path rejection
controls, for 55, while preserving the original reset and completion-witness
logic. Its input helper has twenty host-only controls.
It supports only the reset portions of M05 then G11, once each, after checking
actual ordinary-SAF backup observations, the current RP key/counter, the exact
owned APK, all three settings and a nonempty old provider PID. The latest
recovery backup and G11's historical stale input are separately bound.

Internal review found that the first version could retain a success-looking
result after its directory fsync failed and the failure diagnostic could not be
written. The corrected helper requires a matching completion witness created
only after the result's file and directory synchronization return successfully.
Recovery re-syncs an existing witness; it never creates a missing witness or
repeats an uncertain `pm clear`. Missing, failed or mismatched prior records
fence both cases.

The author's **46/46 host-only checks** were independently rerun internally,
with subprocess and HTTP calls disabled. Two targeted regressions leave the
success-looking file visible after the real atomic-write rename and inject
either a second write failure or a simulated in-process termination. Both
prevent later resets. This is fault injection, not an actual phone or power-loss
test. The original 44-check report, first source, correction diff and internal
review are archived. The helper confirms only a reset step; ordinary restore,
subsequent authentication and each complete phone case need separate evidence.

The peer who reviewed the r7 reset delta authored the older reset core and
completion-witness correction. Their new execution is a fresh peer rerun of
author-defined controls, not a new independently authored test suite. The
authorship supplement records that boundary and the separately observed root
rerun. The old root rerun's full local-only output was lost during executor
replacement; the surviving peer and author originals remain distinct. Each
actual M05/G11 operation still requires its own current checkpoint, backup,
RP state, exact APK, settings, process identity and durable completion evidence.

All mobile material is synthetic. The device QA driver enters synthetic
passwords through real EditText controls, with a temporary value in the
innermost ADB input argv. This is explicitly not evidence of an end-to-end
argv-free production credential path. Neither provider exposes a QA password
Intent, debug endpoint or password-file bypass.

## Published CI observations

The first published source, `e6d7871`, passed
[synthetic-core run 42179078591](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42179078591).
Its workflow-trust run rejected an unregistered artifact-upload action, and its
full qualification stopped at the missing documentation/closure records for
the three new crates. Those failures remain failures; neither reached a passing
full replacement result.

The artifact-upload action was removed without changing the workflow trust
registry. Three bounded public receipts are instead emitted to the job log.
On published source `a38dab74508e6898bea64560cd090932ba1e3706`,
[synthetic-core run 42179532002](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42179532002)
and both source combinations of
[workflow-trust run 42179531970](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42179531970)
completed successfully. The three original core receipts were reconstructed
from those log envelopes and checked byte-for-byte against their original
SHA-256 values before archival.

The later source `0a0bed8cb98e0e80fe3130bf43c43358ebbaad19` adds the missing
module guides, closure records and updated 52-module inventory. Its own
[synthetic-core run 42181992169](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42181992169)
and both combinations of
[workflow-trust run 42181992170](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42181992170)
completed successfully. Its original three core receipts are also archived.
These results were observed on 2026-11-06 08:17 UTC.

Mobile-source publication `2280c3645b6b2c2bd81ed0bde2bfe602773000c2`
exactly matches local tree `2efb7f30c715af3404b2c03329d1c65e2e1f9ef4`.
Its own [synthetic-core run 42186444165](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42186444165)
and both combinations of
[workflow-trust run 42186444305](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42186444305)
completed successfully. Its three original public core receipts are archived
after byte-identical SHA-256 verification. Its separate
[full replacement run 42186444220](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42186444220)
was cancelled at 12:13 UTC after three prospective-merge HA steps had failed.
Both combinations had passed complete locked Rust workspace tests, strict
Clippy and documentation. Those successful earlier steps do not make the full
run successful. The failed HA cleanup records are retained in the recovered
original decoded job log; the subsequent local corrections require their own
qualification.

Published `7e77aa3f4319e9e6c8fbc6e0d200dc2cde8af7c6` subsequently passed
[synthetic core 42215657954](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42215657954)
and both combinations of
[workflow trust 42215657871](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42215657871).
Its three bounded core receipts were recovered from original log lines with
all original SHA-256 values verified. At the 13:34 UTC observation,
[full replacement 42215657729](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42215657729)
was still running complete locked Rust workspace tests in both combinations.
That workflow was subsequently cancelled after publication of the next source;
its terminal cancellation was observed at 14:43 UTC. No newer source inherits
its earlier successful steps.

Source `3ada83a7b1008948a1b24a2e8cf585ee89357336`, tree
`6196647cf9d8e3811347b95e5f984b5c1234ca70`, passed its own
[synthetic core 42233353626](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42233353626)
and both combinations of
[workflow trust 42233353627](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42233353627).
All three core receipts were recovered from the original decoded job-log
envelopes with their original byte lengths and SHA-256 values verified. The
[original core packet](../../qa/personal_credentials/evidence/20261106/ci-3ada-core-originals.tar.gz)
and [core result](../../qa/personal_credentials/evidence/20261106/ci-3ada-result.public.json)
retain the exact source, build and artifact bindings and the explicit false
flags for broader qualifications. The later recorded observation of
[full replacement 42233353960](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42233353960)
showed twelve successful steps in both source combinations, including complete
locked Rust workspace tests, strict Clippy and documentation; the real TLS
service step was in progress. It has no passing full result. The
later bounded-read source overlay does not inherit that older source's CI
results. This draft remains unmerged.

### Real same-format broker upgrade and rollback

The original `389cc15a` broker and separately built Ed25519-only `6fe0b6c7`
broker completed the actual sequence old to new to old to new using the same
format-1 durable state. All 27 declared checks passed. Completed results stayed
stable across versions; revoked, expired and wrong-target operations were
rejected. An actual SIGKILL after target contact left an unknown operation that
was not automatically dispatched again. The synthetic target observed exactly
four authorized effects and zero effects for the denial cases. All owned
processes terminated and both executable identities stayed unchanged.

The [original result](../../qa/personal_credentials/evidence/20261106/broker-upgrade-r1.public.json)
and [complete 72-original-file packet](../../qa/personal_credentials/evidence/20261106/broker-upgrade-r1-remote-originals.tar.gz)
bind the 33 actual commands and 66 original stdout/stderr files. This qualifies
that two-binary, same-format, trusted-owner loopback exercise. It does not
qualify an installer, signed release, arbitrary rollback, data-format migration,
physical power loss or long-term production stability.

### macOS selected clients and the bounded-read repair

The separate clean `c447536` Mac source was recovered without changing its
tree. Earlier attempts retained the tool-path failure, network timeout and
offline `autocfg 1.5.1` cache miss. The fourth offline attempt completed formatting
but Clippy exited 101 because `base16ct 0.2.0` was absent from its private cache.
It did not freeze new binaries or run the planned functional tests. Existing
matching public cache archives may be verified and copied into a new private
attempt; the lockfile, selected features and test gates are not relaxed.
The [available Mac originals](../../qa/personal_credentials/evidence/20261106/mac-r2-r4-available-originals.tar.gz)
retain fifteen exact source, preparation, inventory and failed-run files. This
partial recovery does not claim all earlier command logs are available.

Subsequent public-archive preparation retained its failures: the second HTTP
prefetch held 145 of 157 selected versions, while a separate local-link attempt
accepted no connections and supplied no new archives. A private cache with
375 of the lockfile's 387 registry versions was then sufficient for the actual
selected Darwin build. The twelve absent archives were not required by those
three selected crates; no complete-workspace cache or build is claimed.
The [available preparation and original build packet](../../qa/personal_credentials/evidence/20261106/mac-preparation-and-original-selected-build-history.tar.gz)
preserves three unchanged original archives and explicitly identifies the
unavailable first-prefetch archive. No missing individual output is recreated.

Against unchanged `c447536` source on macOS arm64/Rust 1.98.0, formatting,
strict Clippy, all four CLI builds and test compilation passed. Actual vault
tests passed 14/14, the edge library passed 1/1 and its independent Python
process profile passed 4/4. The original broker passed only 4/13. The
Linux-specific eight-case native-backpressure profile explicitly refused this
platform; it is unsupported here, not eight Mac passes. No Mac browser
integration was observed.

Per-stage diagnostics located a Darwin `EINVAL` at a read-timeout update after
the reply header had already been received. A controlled TCP comparison also
failed at a later timeout update when the peer closed with an unread request
body; the fully drained-body control read the complete status successfully.
The original r2 diagnostic had supplied the CLI `issue` arguments in the wrong
order. Its `invalid_ttl` and incomplete diagnostic remain recorded as a caller
mistake, not a product defect.

The repair waits for readiness and uses a per-call nonblocking receive, without
changing socket blocking mode or ignoring timeout-setting errors. Frame header
and body retain their original shared deadline; the upstream status line keeps
its five-second budget and 128-byte bound. Interrupted reads and temporary
unavailability do not restart the budget. A final successful read after the
deadline is refused, and a closed peer's queued bytes remain readable before
EOF is classified. Target, grant, revocation and durable-unknown behavior are
unchanged.

The first IPC-only candidate passed 16/19 and retained three HTTP failures.
The final three-file overlay, including `lib.rs` SHA-256
`3617799f6de0368fa3b4b4c1343510fe9d202ee3a31fc0e067eb312c40732001`,
passed **19/19 independently on both macOS and Linux**. This comprises all
thirteen original broker tests and six real Unix-socket regressions for queued
peer closure, truncated frames, invalid size, fragmentation, a silent peer and
the shared header/body deadline. Both platforms completed locked offline
builds. Formatting and strict Clippy were additionally executed on Mac; the
Linux packet does not claim those checks. Original source and frozen artifacts
remained unchanged. The new overlay is separately identified from the original clean
source. The [Mac original evidence and Runtime bindings](../../qa/personal_credentials/evidence/20261106/mac-broker-read-fix-public-evidence.tar.gz)
and [Linux original evidence](../../qa/personal_credentials/evidence/20261106/broker-poll-fix-linux-public-evidence.tar.gz)
retain failed attempts alongside the successful profiles. These results do not
expand browser support, Runtime identity attestation or production scope.

### Separately observed Python integration preflight

An isolated ai395 clone of source `c447536` retained exact tree
`50835fd4df6e7bdd2b551941a3fa012281c931c2` before and after this observation.
The real published history was fetched, and both pinned PostgreSQL migration
source commits were verified as exact-tree ancestors. An owned virtual
environment used Python 3.14.4 and the declared direct pins PyYAML 6.0.2,
jsonschema 4.23.0 and cryptography 46.0.4. Transitive Python dependencies were
not fully locked by that requirements file.

Repository/schema/module/surface validators and all three unittest commands
returned zero. The results are **300 passed** repository tests, **1509 passed
and one skipped** acceptance tests, and **179 passed and four skipped** client
tests. The skips are an alternate non-Linux process-owner path and four Darwin
filesystem/proxy-specific cases. The original receipt and complete stdout and
stderr are archived, with every file digest checked against the receipt.
Runtime job `1a1b0200c30-fc05-6e49` reported succeeded, exit zero, complete
durable output and no timeout.

The earlier local run's four acceptance errors and two client errors remain
archived. They involved prohibited Unix sockets, the local system ELF loader's
ownership precondition and missing real Git history. The relevant Python test
and validator sources are unchanged between that earlier local baseline and
this frozen source. The later run passed the formerly failing cases in the
supported Linux environment without changing those tests or their gates.
This is Python preflight evidence; it did not execute the server, the complete
Rust workspace, device flows or an OpenBao replacement qualification.

## Actual supported entry points

- [Credential broker and Git signing](../../crates/heptabao-credential-broker/README.md): trusted-owner issuance, narrow API execution and exact Git payload binding.
- [Personal vault CLI](../../crates/heptabao-personal-vault/README.md), [API](../../crates/heptabao-personal-vault/API.md) and [format design](../../crates/heptabao-personal-vault/DESIGN.md).
- [Chromium/native-host and opaque store](../../crates/heptabao-personal-edge/README.md): explicit fill, exact origin/document checks, timed locking and conflict-preserving publication.
- [Android Autofill preview](../../clients/android/README.md): one exact signed native fixture, fresh authorization and ephemeral datasets.
- [Android Passkey preview](../../clients/android-passkey/README.md): native CredentialManager, encrypted counters, local document import/export and explicit recovery limits.
- [Runtime identity analysis](RUNTIME_IDENTITY.md): what current operator jobs prove, what they do not prove and the required separate-principal boundary.
- [Internal dependency review](DEPENDENCY_REVIEW.md): pinned advisory/database scope, selected-build correction and the remaining wider-workspace boundary.
- [Operations and recovery](OPERATIONS.md): evidence checks, clean staging, unknown outcomes and backup/restore procedures.

## Reproduction gates

Use Rust 1.98.0 and the repository lockfile. The synthetic core workflow checks
the three Rust crates, actual independent CLI/socket processes, Git signing,
browser scheduling and native-pipe failure handling. It explicitly records
`p0_service_qualified=false`, `real_browser_qualified=false`,
`android_qualified=false`, `physical_two_device_qualified=false` and
`p5_qualified=false`; those require their own evidence.

```sh
CARGO_BUILD_JOBS=2 cargo +1.98.0 test --locked -p heptabao-personal-vault -- --test-threads=1
CARGO_BUILD_JOBS=2 cargo +1.98.0 test --locked -p heptabao-credential-broker -- --test-threads=1
CARGO_BUILD_JOBS=2 cargo +1.98.0 test --locked -p heptabao-personal-edge -- --test-threads=1
node --test qa/personal_credentials/browser_worker_test.mjs
CARGO_BUILD_JOBS=2 cargo +1.98.0 build --locked -p heptabao-credential-broker -p heptabao-personal-vault -p heptabao-personal-edge --bins
python3 -B qa/personal_credentials/personal_edge_live.py -v
```

Record a fresh work directory and original job identity for every observation.
Keep synthetic master passwords, recovery documents, signing keys, fixture
private keys, raw UI hierarchies and runtime transport secrets out of repository
files and public reports. A missing test, skipped device or failed cleanup is a
missing or failed observation, never a passing platform result.
