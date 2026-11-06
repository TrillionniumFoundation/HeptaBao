# Observed combinations and support boundaries

All observations below use synthetic credentials. They qualify only the named
source, artifact, platform and profile. This project does not yet have a
production release or an independent security-review approval. The
[full status](STATUS.md) and [evidence index](../../qa/personal_credentials/evidence/20261106/manifest.json)
identify the original runs, retained failures and exact artifact hashes.

## Credential service and developer clients

| Combination | Actual observation | Boundary |
| --- | --- | --- |
| Fixed Linux service, private-CA loopback TLS, Shamir, root-namespace KV2, userpass and scoped tokens | 57/57 selected authentication, authorization, audit, expiry/revocation and crash/recovery checks | Other auth engines, namespaces and production topologies need separate evidence. |
| The original Linux server with frozen r3 HA profiles | Complete destructive, partition and replay profiles; captured replay frontier, rejoin, leadership and subsequent reads/writes | Profiles overlap. These results do not qualify every HA mode, snapshot behavior or the complete newer source tree. |
| Bounded-read broker on Linux and macOS arm64 | 19/19 on each platform, including six real socket regressions and the original thirteen tests | The owner account is trusted. The Mac result is separate from the retained 4/13 original and 16/19 intermediate failures. |
| Controlled API operation through the broker | Exact owner grant binds task/run labels, operation, target, method, path, body digest and expiry | Only the implemented numeric-loopback HTTP target is admitted. External HTTPS APIs, DNS destinations, redirects, arbitrary headers and returning an upstream response body are unsupported. This is separate from the credential service's TLS profile. |
| SSHSIG and Git commit signing | Ed25519 signature use and actual `git commit -S` / `git verify-commit` | SSH login, an SSH agent socket, RSA and ECDSA signing are unsupported. |
| HeptaRuntime invocation | Ordinary operator-controlled processes execute the clients | Owner-issued labels and Runtime shadow admission do not establish an attested task principal. The deployed task-isolation and credential-use boundary remains open; see [Runtime identity](RUNTIME_IDENTITY.md). |

## Personal vault and daily use

| Combination | Actual observation | Boundary |
| --- | --- | --- |
| Linux personal-vault CLI | Encrypted login/note/API entries, password generation, RFC-vector TOTP, local health, bounded sessions, offline use, backup/recovery, JSON import/export and password change; independent-process and SIGKILL recovery | Owner-controlled files and processes are trusted. No hardware anti-rollback or hostile-owner isolation is claimed. |
| Frozen macOS personal-vault CLI | Separate 14/14 tests | This does not qualify a Mac browser extension, native-messaging session or every filesystem. |
| Google Chrome 157 on the tested Linux desktop, with the fixed extension and native host | Original 26/26 actual headed login/refusal cases; a separate new 26/26 run passed against the Firefox-capable `f1913261` native host and unchanged extension | The fixture's TLS exception and `--no-sandbox` launch do not qualify production browser isolation. Renderer components and full extension/native cases retain separate labels. Other browser versions, Firefox, Safari, Windows and Mac browser combinations need their own observation. |
| Linux native-messaging pipe | 8/8 backpressure and closure checks | The Linux-specific pipe profile reports the Mac combination as unsupported; separate Mac edge checks do not replace those eight cases. |
| Firefox native-host launch candidate on Linux | 13/13 real CLI/pipe cases, 43 started child processes reaped; the original Chrome pipe profile separately passed 8/8 against this executable | Private installer staging and Firefox manifest-path/add-on-ID parsing only. No Firefox browser, profile, native-host registry or Snap/portal permission was exercised. Firefox browser login remains unqualified. |
| Opaque encrypted synchronization between the two observed physical machines | 14 stages and 18 authenticated transfers retained conflicting edits and restored both histories | Explicit CLI transfers under the trusted owner; no automatic sync daemon, server authentication principal, field merge or device revocation. Offline edits do not establish a physically disconnected-network test. |
| Android Autofill preview on Motorola XT2551-3, Android 16/API 36 | c9/QA17 r15 passed seven original cases including actual system fill/login, cached-dataset refusal, explicit lock and actual expiry, following separate Rust/Java ciphertext and signed-APK checks | r15 failed at 7/12 at the cancellation-cause observation; r13 4/12 and r14 1/12 remain separate failures. Cases from these runs are not combined. The remaining device cases have not passed. WebView/browser filling is unsupported. |

## Passkey creation, login, transfer and recovery

| Operation and combination | Actual observation | Boundary |
| --- | --- | --- |
| Create and register, one fixed Android native CredentialManager fixture and relying party | Real credential creation and RP registration | No browser/WebAuthn site combination, general relying-party acceptance or provider certification is claimed. |
| Authenticate, same fixed fixture and RP | Real assertions with counter progression; RP verifies the response | The original eighteen-case ledger remains 16 passed / 2 failed. Three independent supplements passed 3/3 and retain their separate denominator. |
| Restore, same physical Android device | Ordinary encrypted SAF backup, owned-app data reset, new-process restore and subsequent authentication with the same credential/public key | Same-device recovery; not migration to a second physical device. Original launch-audit and causal evidence limits remain in the full status. |
| Restore an older encrypted backup | Independent RP refusal after counter rollback/replay | This depends on that RP's retained state; it is not a hardware anti-rollback guarantee. |
| Platform credential exchange, shared vaults, device revocation, additional provider platforms | Unsupported | The product's encrypted backup/restore format is not a claim of platform credential-exchange compatibility. Existing knowledge of a decryption key cannot be revoked from an old backup. |

P4 remains unqualified. Each new creation, authentication, transfer or recovery
combination needs its own actual observation; related host checks or a different
successful combination do not supply it.

## Recovery and production gates

A lost device can be recovered only if an encrypted backup and its password or
recovery key remain available. Losing both unlocking methods has no recovery
path. Preserve conflicting encrypted versions until each desired history has
been recovered. [Operations](OPERATIONS.md) gives the actual procedures and
unknown-outcome handling.

The observed old/new broker upgrade and rollback rehearsal passed 27/27 checks
for two exact binaries and one durable format. The bounded-read Linux broker
also completed a separate thirty-minute, sixty-cycle continuity trial: 491
protocol requests, sixty distinct effects each exactly once, and recovery
through seven sequential broker processes. All 621 child processes were reaped.
Its sampled resource observations and requested limits are described in the
[full status](STATUS.md); they do not establish load capacity or continuous
resource enforcement. Installer rollout, arbitrary format migration, signed
distribution, measured long-term stability and operational-support commitments
require separate work. The bounded short trial cannot establish long-term
reliability.

The draft integration also requires the complete exact-head and prospective-
merge CI gates. Broader dependency findings and the externally reviewable
security questions remain documented in [dependency review](DEPENDENCY_REVIEW.md)
and [independent-review scope](SECURITY_REVIEW_SCOPE.md). Internal agent reviews
are not an external security audit.
