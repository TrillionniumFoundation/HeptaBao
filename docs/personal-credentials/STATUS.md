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
| P0: selected credential service | Normal Linux server entry point, loopback TLS/private CA, Shamir, root-namespace KV2, userpass and scoped tokens: **57/57**, including real expiry/revocation, ACL denials, SIGKILL and cold recovery. | This exact single-node profile only. HA, full compatibility, old failing snapshot actor regression and broad replacement remain HOLD. |
| P1: agent/developer use | Executable Rust CLI/SDK, local socket broker, exact-operation owner grants, controlled loopback API use, SSHSIG and actual `git commit -S` followed by `git verify-commit`. The separately frozen Ed25519-only build passed **13/13 integration tests**, including all original eleven tests and real RSA/ECDSA rejection. Durable unknown outcomes are never automatically retried. | Task/run labels are owner-issued, not attested HeptaRuntime identities. Current runtime aliases use the same trusted OS account. External HTTPS APIs and SSH login are unsupported. |
| P2: personal vault | Encrypted login/note/API entries, password generation, RFC-vector TOTP, local health, bounded sessions, offline CLI, encrypted backup/recovery, explicit JSON import/export and password change. Independent process and actual SIGKILL recovery observed. | Linux/Unix private local filesystem, trusted owner account; no hostile-owner isolation, hardware anti-rollback, third-party import or independent security review. |
| P3: daily clients | Real headed Chromium/native-host login and rejection profile: **26/26**. Physical two-device opaque synchronization: **14 stages and 18 authenticated transfers** across ai395 and ROG retained conflicting edits and restored both histories. Native backpressure fix: **8/8**. | Target Android Autofill qualification is in progress. Browser observation covers the fixed Chrome 157 Linux combination. Sync is an explicit CLI workflow, not an automatic daemon or field merger. |
| P4: extended vault | Android native Passkey provider and CredentialManager fixture implemented. Frozen r4 host cryptography/format profile: **10/10**, including separate JVMs, latest-backup recovery, restart and stale-counter rejection. Independent RP: **68/68** per tested backend and **21/21** real loopback HTTP/restart cases. | The r4 phone run failed import before password entry: **one failed, one cleanup passed, sixteen blocked**, retaining all eighteen cases. No completed phone create/login/recovery evidence yet. Credential exchange, sharing, device revocation, additional browsers/platforms remain unsupported. |
| P5: production adoption | Published `a38dab7`, `0a0bed8` and `2280c36` each passed synthetic-core CI and the workflow-trust checks for both exact head and prospective merge. A separate clean `c447536` Python preflight has no failures across 300 repository, 1510 acceptance and 183 client tests, with five explicit platform skips. Immutable evidence, an internal dependency review, runtime trust analysis and an operations/recovery procedure are available. | Full replacement qualification for `2280c36` is running and has not passed. No result is inherited across heads. Independent review, measured long-term stability, signed releases, tested upgrade/rollback and operational support are not complete. |

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
| ai395 final broker | `389cc15a0926ef9f30cd149b56424a484dfad600a308252ed111f2869b5b9175` |
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
strict later checks. The first r5 SDK34 compile failure and the corrected r5b
source archive remain separate originals. New builds and device observations
must retain their own identities.

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
| Autofill candidate 5 provider APK | `5c643afa5a08c6e8dd0baf751fe56dadf0f66947284d119d2da7051f4ab88ff8` | Build/decoded manifest and 12 host format checks; its r6 phone profile failed after 1/12 checks. |
| Passkey r4 provider APK | `e96218bc0ab1c228120471d5168a336e6b526bfd5e39e1a0a533335300d7c6e8` | Build/decoded manifest and 10 host checks; phone import failed before any credential creation, with all eighteen cases retained. |

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
was running at the 2026-11-06 09:20 UTC observation: both exact head and
prospective merge passed repository/fixture preflight and were executing the
complete locked Rust workspace tests. The older results do not qualify a newer
publication, and an in-progress run is not a passing gate. This draft remains
unmerged.

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
