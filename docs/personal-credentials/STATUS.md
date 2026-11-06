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
| P1: agent/developer use | Executable Rust CLI/SDK, local socket broker, exact-operation owner grants, controlled loopback API use, SSHSIG and actual `git commit -S` followed by `git verify-commit`: **11 integration tests**. Durable unknown outcomes are never automatically retried. | Task/run labels are owner-issued, not attested HeptaRuntime identities. Current runtime aliases use the same trusted OS account. External HTTPS APIs and SSH login are unsupported. |
| P2: personal vault | Encrypted login/note/API entries, password generation, RFC-vector TOTP, local health, bounded sessions, offline CLI, encrypted backup/recovery, explicit JSON import/export and password change. Independent process and actual SIGKILL recovery observed. | Linux/Unix private local filesystem, trusted owner account; no hostile-owner isolation, hardware anti-rollback, third-party import or independent security review. |
| P3: daily clients | Real headed Chromium/native-host login and rejection profile: **26/26**. Physical two-device opaque synchronization: **14 stages and 18 authenticated transfers** across ai395 and ROG retained conflicting edits and restored both histories. Native backpressure fix: **8/8**. | Target Android Autofill qualification is in progress. Browser observation covers the fixed Chrome 157 Linux combination. Sync is an explicit CLI workflow, not an automatic daemon or field merger. |
| P4: extended vault | Android native Passkey provider and CredentialManager fixture implemented. Frozen r4 host cryptography/format profile: **10/10**, including separate JVMs, latest-backup recovery, restart and stale-counter rejection. Independent RP: **68/68** per tested backend and **21/21** real loopback HTTP/restart cases. | Host and RP observations do not exercise Android CredentialManager. No completed phone create/login/recovery evidence yet. Credential exchange, sharing, device revocation, additional browsers/platforms remain unsupported. |
| P5: production adoption | Published `a38dab7` passed synthetic-core CI and the workflow-trust checks for both its exact head and prospective merge. Immutable evidence, runtime trust analysis and an operations/recovery procedure are available. | Newer `0a0bed8` CI remains queued/pending at the last observation. No result is inherited across heads. Independent review, measured long-term stability, signed releases, tested upgrade/rollback and operational support are not complete. |

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
12/12. The old phone results do not qualify this new APK; its own complete
12-case device run is still required. Both original source archives and build
receipts are retained.

Passkey candidate r4 has 28 source files matching its original build inventory.
It implements a separate Android credential provider for one pinned native
fixture and relying-party ID. Its password-protected `.hbv` store preserves the
Rust format and recovery wrapper. The ordinary app uses local Storage Access
Framework documents for bounded encrypted import/export and fresh private
stores for restore; these UI paths require their own phone observation.

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

| Frozen mobile artifact | SHA-256 | Current evidence boundary |
| --- | --- | --- |
| Autofill candidate 5 provider APK | `5c643afa5a08c6e8dd0baf751fe56dadf0f66947284d119d2da7051f4ab88ff8` | Build/decoded manifest and 12 host format checks; device profile pending. |
| Passkey r4 provider APK | `e96218bc0ab1c228120471d5168a336e6b526bfd5e39e1a0a533335300d7c6e8` | Build/decoded manifest and 10 host checks; CredentialManager/SAF profile pending. |

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
module guides, closure records and updated 52-module inventory. Its new runs
were still queued/pending at the last observation on 2026-11-06 07:49 UTC.
The older core and trust results do not qualify that newer source, and a queued
run is not a passing gate. This draft remains unmerged.

## Actual supported entry points

- [Credential broker and Git signing](../../crates/heptabao-credential-broker/README.md): trusted-owner issuance, narrow API execution and exact Git payload binding.
- [Personal vault CLI](../../crates/heptabao-personal-vault/README.md), [API](../../crates/heptabao-personal-vault/API.md) and [format design](../../crates/heptabao-personal-vault/DESIGN.md).
- [Chromium/native-host and opaque store](../../crates/heptabao-personal-edge/README.md): explicit fill, exact origin/document checks, timed locking and conflict-preserving publication.
- [Android Autofill preview](../../clients/android/README.md): one exact signed native fixture, fresh authorization and ephemeral datasets.
- [Android Passkey preview](../../clients/android-passkey/README.md): native CredentialManager, encrypted counters, local document import/export and explicit recovery limits.
- [Runtime identity analysis](RUNTIME_IDENTITY.md): what current operator jobs prove, what they do not prove and the required separate-principal boundary.
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
