# Android native Autofill preview

This is a runnable, read-only Android Autofill provider and a separate synthetic native login application. It is an experimental qualification target. It does not establish production adoption, general Android compatibility, or support for arbitrary applications.

The initial device target is the previously identified Motorola XT2551-3 running Android 16 / API 36. The APK is compiled with Android SDK 34, minimum API 34, and target API 34. A host build or a passing Java crypto harness is not evidence of device Autofill success; the device report must identify the installed APK hashes and the actual system operations.

## Supported behavior

The provider package is `org.heptabao.personal.preview`. It imports an existing encrypted `.hbv` into its own private application directory. Import is explicitly confirmed locally. Unlock accepts the master password only in the non-exported authentication Activity. Each successful authentication authorizes one native fill; there is no exported unlock API, network permission, credential save API, or plaintext export.

This preview maps one vault item (`android-fixture`, origin `https://native-fixture.heptabao.invalid`) to one native application (`org.heptabao.synthetic.fixture`) and one exact current signing certificate digest generated during the synthetic build. The origin selects the intended vault item. It is **not** evidence of Android application ownership. Application identity is independently checked with the system activity component, the installed signing certificate, and the actual result-receiving Activity.

The fixture packages contain only the encrypted Rust-created vault and SHA-256 commitments to high-entropy synthetic login values. The master password and APK signing keys remain in private QA directories. A second package signed by the correct fixture key and a same-package APK signed by a different key supply independent application and certificate rejection cases.

## Authorization and expiry

The service accepts only the pinned native Activity, native EditText fields with the expected resource package/IDs and Autofill hints, and a single window. It rejects WebView, HTML metadata, web domains, compatibility requests, other applications, changed certificates, duplicate fields, and unknown structures. Multi-signer APKs and certificate rotation are unsupported.

The service creates an opaque random handle in an explicit, one-shot, mutable PendingIntent to the non-exported authentication Activity. Android needs the mutable flag to add authentication arguments. Identity and authorized field IDs remain in the provider process; arguments supplied with the Intent cannot replace that authority. The authentication Activity compares the original and current structure, verifies `getCallingActivity()`, and rechecks the installed certificate before releasing a result.

Requests expire after 120 seconds. A successful local unlock lasts at most 20 seconds and never outlasts the request. The user must press **Fill once**. An independent scheduler clears the application's mutable credential buffers; every access also checks monotonic elapsed time. Cancellation, backgrounding, explicit lock, and process restart invalidate authorization. An unlock calculation already in progress can finish, but its result is discarded after cancellation and its password byte array is cleared on return.

The authentication Activity's `onPause` invalidates the complete request. Every delivered memory-trim callback clears the unlocked login and any pending credential handoff, and advances the generation that invalidates an unlock calculation already in progress. A still-locked opaque challenge retains its original one-shot PendingIntent and 120-second deadline; the callback cannot extend its lifetime or authorize a fill. A subsequent unlock must pass the same target checks and local password authentication. This distinction covers `TRIM_MEMORY_UI_HIDDEN`, which can describe an earlier settings/import Activity, and background-LRU notifications that do not by themselves prove memory pressure. Android API 34 and later do not guarantee delivery of the historical trim levels; a host callback test is not evidence of a device test under operating-system memory pressure.

Each service invocation owns only the challenge returned by its own successful `begin`. An incoming self, wrong-target, unsupported, or malformed request that fails before that point receives no dataset and cannot clear another pending challenge, unlocked login, or credential handoff. If an invocation fails after creating a challenge, it revokes that exact object only while it remains current; a late failure cannot revoke a successor. A valid new request still replaces the previous challenge, and the original request's cancellation listener, authorization Activity pause, deadlines, and final certificate/recipient checks still apply. A failure to install the request expiry timer clears the partially created challenge before `begin` can return. Rejection codes may still update the separate global diagnostic decision; that value does not grant or revoke authorization.

The provider emits only closed policy codes and before/after presence bits for authentication and lifecycle diagnostics. The diagnostic candidate distinguishes rejection before local unlock from the identity check after the KDF, cancellation from the service listener or authentication Activity pause, challenge replacement, actual deadline/timer branches, and explicit login lock. A service request's already-observed package is classified only as expected, self, or other; no package string is logged and diagnostics perform no additional identity query. Codes contain no vault contents, password, token, target, field value, or exception body. Newly added messages are queued as prebuilt closed strings, so log delivery can lag an event or a direct trim message. A process buffer may include earlier cases. These diagnostics do not identify an Android Autofill session, prove which request a later message belongs to, or replace the device profile's actual success and refusal assertions. They do not change any expiry, cancellation, target, password, or final-delivery guard; earlier failed device runs remain failed.

The diagnostic preview also has a read-only **Authorization diagnostic** field. Only the existing rejection branches before unlock and after the KDF update it, using their already-captured stage and rejection code. The original authorization status, buttons, and decisions are unchanged. The field includes a closed mapping of the application's previous global decision, read once after catching the rejection and before the existing full lock. That snapshot is not tied to a request identity: another thread can update the global decision, so it must not be described as the exact cause of the rejection. Unknown values become `other`; no additional request, ticket, certificate, or system identity lookup is performed. This field is diagnostic evidence, not a replacement for the required device success and refusal checks.

The result is a dataset-level authenticated **ephemeral Dataset**. Android fills that dataset directly and does not replace the cached authentication placeholder with reusable plaintext. The opaque handle and one-shot PendingIntent cannot authorize another fill. The fixture's **Clear fields** button deliberately leaves the system session intact so the device test can detect unwanted cached plaintext reuse.

The application retains a revocable handoff record until final delivery. It rechecks expiry/cancellation after system identity calls and immediately before `setResult` and `finish`. PendingIntent cancellation executes outside the authorization monitor. After the system receives an authorized dataset, the provider cannot recall credentials already delivered to the target application. Locking does not erase fields that have already been filled.

## Encryption interoperability

The reader enforces the Rust format 1 parameters and authenticated header order:

| Element | Exact supported encoding |
| --- | --- |
| KDF | Argon2id, version 19, 65,536 KiB, 3 passes, 4 lanes, 32 output bytes |
| Password | Original UTF-8 bytes, no normalization, 12–1,024 bytes |
| Cipher | Platform JCE AES-256-GCM, 12-byte nonce, ciphertext followed by the 16-byte tag |
| Base64 | Standard alphabet, no padding, canonical decode/re-encode equality |
| Wrapping | Authenticated role-specific JSON array; password unwrap yields a random 32-byte DEK |
| Body | Exact ordered Rust header AAD, including both password and recovery wraps |
| Limits | 8 MiB file, 4,096 items, duplicate/unknown fields refused, fixed KDF only |

`VaultCrypto` uses the pinned Bouncy Castle 1.86 lightweight Argon2 implementation and platform JCE for AES-GCM. It does not register Bouncy Castle as a system security provider. The dependency is `bcprov-jdk15to18-1.86.jar`, SHA-256 `fc50334d4d87b4272e72fa95ca748ead05bdef02ef760a5b13f64ffee317cd81`, from the [official Maven distribution](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15to18/1.86/bcprov-jdk15to18-1.86.jar). The dependency's own license notice is included in the provider APK.

The plaintext payload must bind its vault ID and revision to the outer envelope. All item IDs must be unique and field sizes/types are validated. Revisions larger than Java's signed 64-bit range are explicitly unsupported. Notes, API entries, and TOTP configuration are parsed and validated, but this preview only fills the explicitly mapped login. Recovery unlock, vault edits, TOTP display, password generation, synchronization, and password health UI are unsupported here; existing Rust functionality is not automatically an Android feature.

The Java harness reads a newly generated envelope from the actual Rust CLI, verifies both credential digests, and rejects a wrong password, a changed authenticated revision, unsupported KDF parameters, duplicate/unknown fields, out-of-range revisions, a wrong item mapping, noncanonical Base64, invalid UTF-8, and oversized input. It prints only counters and nonsecret evidence.

## Storage and memory boundaries

Only ciphertext is persisted in the provider. AtomicFile publication is confined to the application-private directory. Import uses a content URI grant, a bounded read, a background worker, and a logical 10-second deadline; a blocked content provider cannot cause a late accepted publication after that deadline. The cancellation/close call runs off the expiry thread. If an uncooperative provider never returns from I/O, this preview remains locked with import in progress until the process restarts; this is not a promise of forcibly interruptible Android Binder I/O.

Backup is disabled in the manifest. Data extraction rules exclude cloud backup and device transfer in both credential-encrypted and device-encrypted domains. The UI uses `FLAG_SECURE`, disables password state saving and Autofill on the local master-password UI, and requests no personalized keyboard learning. Credentials are never deliberately written to logs, saved-instance state, or diagnostic output.

Java/Android and JCE create immutable String and framework copies that cannot be reliably zeroed by application code. Clearing the owned password/DEK/plaintext byte arrays and the selected login's character arrays is not a claim of a residue-free Java heap. The pinned Bouncy Castle implementation clears returned Argon2 blocks on its normal completion path; abnormal VM termination or allocation failure does not provide a complete heap-erasure guarantee. A trusted Android OS, application sandbox, and local input environment remain part of this preview's assumptions.

## Build and qualification

Use `qa/personal_credentials/android_prepare.py` to create fresh synthetic material through a specified, hashed Rust vault binary. Use `qa/personal_credentials/android_build.py` with explicit source, private fixture, JDK, SDK, dependency JAR, and a new output directory. The build uses `javac`, `aapt2`, `d8`, `zipalign`, and `apksigner`; it performs no dependency download or device operation.

The build records every command, tool/input hashes, source inventory before and after, certificate digests, host interoperability checks, APK hashes, and decoded manifest logs. It creates new synthetic signing keys under its private output directory. A failed build retains its failed receipt and logs; it must not be described as a usable APK.

Device qualification is a separate operation. The driver must select the device internally by its previously authorized serial hash, never log a raw serial, record the original Autofill setting privately, and change only these new preview packages. It must restore the original setting only if the current setting still equals the value it installed. If another actor changes the setting, it must not overwrite that actor's choice. No screen lock, accessibility service, or other application's data is changed.

Failure diagnostics read only the provider's fixed log tag and one observed provider PID. The driver reports original stdout byte/line counts, recognized and discarded line counts, query durations, and whether PID observations match the baseline captured after the existing authorization/locked UI checks. It never returns the PID or raw log lines. A PID match does not prove a process generation, an empty buffer does not prove no events occurred, and queued log delivery does not establish event order. The fixed UI diagnostic is read only while the exact provider authorization Activity owns the foreground, with the diagnostic node bound to that package. These observations do not change the twelve required device cases or turn a failed case into a pass.

The required device cases are actual native login, wrong package, wrong certificate, locked fill, expired authorization, explicit cancellation/background lock, process restart with ciphertext import retained, and a successful-fill-then-clear attempt that cannot reuse cached plaintext. WebView/browser filling, passkeys, platform credential exchange, sharing, device revocation, and broad platform compatibility remain unsupported by this Autofill preview.

The private device driver reads a random **synthetic** master password locally and types it into the real password EditText after checking its application, Activity, password-field type, focus, and display. The provider never reads the QA password file or receives a password through an Intent. This particular QA method uses `adb/input text`: the innermost child-process argument list briefly contains the synthetic value. The value is not returned to the model or printed by the driver. The receipt explicitly labels this `synthetic_only_adb_input_text_argv` and `production_qualified: false`. These device tests are not evidence of a complete model-to-device secret transport with no password in any argument list, and do not authorize adoption of real credentials through that QA input method.

### Platform references

- [Android AutofillService](https://developer.android.com/reference/android/service/autofill/AutofillService)
- [Dataset authentication and mutable PendingIntent](https://developer.android.com/reference/android/service/autofill/Dataset.Builder#setAuthentication(android.content.IntentSender))
- [Ephemeral authentication dataset](https://developer.android.com/reference/android/view/autofill/AutofillManager#EXTRA_AUTHENTICATION_RESULT_EPHEMERAL_DATASET)
- [Actual Activity result recipient](https://developer.android.com/reference/android/app/Activity#getCallingActivity())
- [Android backup and device-transfer behavior](https://developer.android.com/about/versions/12/behavior-changes-12#backup-restore)
- [Memory callbacks and UI-hidden notification](https://developer.android.com/reference/android/content/ComponentCallbacks2)
