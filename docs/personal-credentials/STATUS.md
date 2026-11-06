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
| P4: extended vault | Android native Passkey provider and real CredentialManager fixture are being implemented, with independent RP verification. | No completed platform create/login/recovery evidence yet. Credential exchange, sharing, device revocation, additional browsers/platforms remain unsupported. |
| P5: production adoption | Narrow synthetic CI, immutable evidence archive, runtime trust analysis and an operations/recovery procedure. | CI has not yet run on this published candidate. Independent review, measured long-term stability, signed releases, tested upgrade/rollback and operational support are not complete. |

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

## Actual supported entry points

- [Credential broker and Git signing](../../crates/heptabao-credential-broker/README.md): trusted-owner issuance, narrow API execution and exact Git payload binding.
- [Personal vault CLI](../../crates/heptabao-personal-vault/README.md), [API](../../crates/heptabao-personal-vault/API.md) and [format design](../../crates/heptabao-personal-vault/DESIGN.md).
- [Chromium/native-host and opaque store](../../crates/heptabao-personal-edge/README.md): explicit fill, exact origin/document checks, timed locking and conflict-preserving publication.
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
