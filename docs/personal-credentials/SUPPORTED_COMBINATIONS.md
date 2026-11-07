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
| Exact `8f3dd835` base and separately built `3ada83a` candidate, private three-node loopback rolling profile | All 49 original scenarios passed within 480 seconds, with no rescue cleanup and unchanged source/binary bindings | Exact artifact pair only; no multi-host, skipped-version, mixed-version replay-epoch or production compatibility claim. |
| Exact newly built `3ada83a` candidate, five-process same-version loopback membership | All 41 original scenarios passed within 360 seconds, including prejoin purge, learner catch-up/promotion, real dead-voter grace and cleanup, failover/restart | Native pre-enrolled membership; not OpenBao join-challenge/API parity, compact-snapshot qualification, archive authenticity or backup restore. |
| Exact `3ada83a` source plus the formatted three-file consistency/audit delta, Rust 1.98.0 on Linux | Actual four-test red/green: original normal-429 GET hint assertion failed while three controls passed; fixed source passed all 4/4, including GET/HEAD/POST in the normal case | Server library regression only, CPU400%/Cargo jobs2/24 GiB with separate build and unchanged test budgets. No full CI, new live API/client/proxy profile or new server-executable qualification. |
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
| Android Autofill preview on Motorola XT2551-3, Android 16/API 36 | Same c10 APK, fresh QA19 r17: all 12/12 original cases passed together, including actual fill/login, cache refusal, lock/expiry/cancellation/background denial, process restart/recovery and wrong package/certificate refusal; cleanup independently verified | One fixed native fixture and exact APK/device combination. Browser/WebView filling and arbitrary apps are unsupported. Earlier r16 6/12, r15 7/12, r13 4/12 and r14 1/12 remain separate failures. QA19's new prebinding branch did not occur on r17; r16's exact failure cause remains unknown. |

## Passkey creation, login, transfer and recovery

| Operation and combination | Actual observation | Boundary |
| --- | --- | --- |
| Create and register, one fixed Android native CredentialManager fixture and relying party | Real credential creation and RP registration | No browser/WebAuthn site combination, general relying-party acceptance or provider certification is claimed. |
| Authenticate, same fixed fixture and RP | Real assertions with counter progression; RP verifies the response. Fresh r9 original ledger: 17 passed / 1 blocked / 0 missing | r9 cancellation remains blocked before its negative executes; a separately declared second attempt is also blocked. r8's 16 passed/2 failed and separate 3/3 supplements retain their original denominators and limits. |
| Restore, same physical Android device | Ordinary encrypted SAF backup, owned-app data reset, new-process restore and subsequent authentication with the same credential/public key; both r9 M05 launches recorded their audit | Same-device recovery; not migration to a second physical device. The new audit observation does not rewrite r8's earlier launch-audit gap. |
| SAF selection cancellation and wrong-password destination protection, fixed Android fixture | Fresh r9 G08/G09/G10 guards passed; fresh unconsumed selections and 615-byte nonempty target baselines are explicit | These destination baselines are QA ciphertext, not an earlier product export. This is distinct from CredentialManager cancellation, which remains blocked. No Passkey expiry negative was executed. |
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
