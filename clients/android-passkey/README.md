# Native Android Passkey preview

This is an isolated Android 14+ provider preview for one synthetic native relying
party. It calls the platform `CredentialManager` and implements the real
`CredentialProviderService` query/selection/result flow. The fixture application
does not generate keys or signatures. A separate Python RP verifies the returned
WebAuthn responses, using a mature EC implementation.

Source and host tests are not phone qualification. The target combination is the
owned Motorola XT2551-3, Android 16/API 36; actual installation, provider selection,
creation, authentication and recovery need their own result manifest. Other
devices, websites, browsers, Digital Asset Links discovery, credential exchange,
cross-platform migration, sharing and hardware attestation are unsupported.

## Deliberately narrow trust boundary

The provider accepts only `org.heptabao.passkey.fixture`, exactly one current
signing certificate pinned into the build, and `passkeys.heptabao.test`. It checks
both framework `CallingAppInfo` and the installed package signer. Non-null
privileged origins, externally supplied client-data hashes, multisigner packages,
unsupported algorithms/extensions and wrong RP IDs are rejected. The RP checks
the exact `android:apk-key-hash:` origin computed from the fixture certificate.
This private test association does not stand in for general website ownership or
Digital Asset Links verification.

The provider has no Internet permission. The fixture communicates only with the
explicit local RP at `http://127.0.0.1:38491`, intended for an approved ADB reverse
connection during qualification. The RP stores public keys, counters and one-use
challenge state; it never receives the vault password, DEK or private passkey.
Both APKs disable `debuggable` and Android backup. The APK builder creates fresh,
short-lived synthetic signing keys, retained only in its private output root.

## Vault, unlock and approval

Private P-256 keys are PKCS#8 values inside encrypted `api` entries in the existing
HeptaBao `.hbv` format 1. The initial empty vault is created with the Rust vault
CLI. Its random DEK, Argon2id password wrap and recovery wrap are preserved.
Parameters remain Argon2id v1.3, 64 MiB, three passes, four lanes, a 16-byte salt
and 32-byte output; encryption is AES-256-GCM with fresh 12-byte nonces and the
existing vault/schema/revision-bound AAD. No new password format is introduced.

Unlock caches only public credential IDs and labels for five monotonic minutes.
Every create or get selection requires entering the vault password again and
pressing **Approve passkey operation**. Password verification supplies the
knowledge-based user verification, and the approval supplies user presence. No
biometric or device-bound key claim is made. Passwords are never read from
Intents, document URIs, test files or a debug IPC endpoint. Password fields disable
autofill, state saving and personalized IME learning; sensitive screens set
`FLAG_SECURE`.

Mutable byte/character arrays are cleared where controlled. Java JSON strings,
allocator copies, JCA key representations and provider internals cannot be
guaranteed to be erased. This is not a whole-heap zeroization guarantee.

## Ordinary import and encrypted export

1. Choose an encrypted `.hbv` file with the Android Storage Access Framework.
2. Enter its vault password and explicitly import it. Authentication occurs
   before activating a fresh private store; prior stores are retained.
3. Enable the provider through Android's credential-provider settings and launch
   the synthetic fixture. Unlock the public list before invoking create/get.
4. To back up, choose a new document destination, then enter the vault password
   and explicitly write the encrypted backup. No private key plaintext is exported.

Imports accept bounded `content://` documents from the system external-storage
or downloads document provider. Export requires one of those local SAF providers
offering a regular, fsyncable file descriptor and readable content for digest
verification. Streaming/cloud providers are refused. A new selection, cancellation
or failed import staging clears the prior target's ready marker; import additionally
binds the staged ciphertext digest. The private encrypted backup is retained on
export failure.

Document operations have a 15-second logical deadline and cancellation signal;
already opened file descriptors are closed on a separate cleanup thread. A system
provider that does not respond to Binder cancellation cannot be forcibly stopped
by this app. The operation then remains failed/cancelled until it unwinds or the
process is restarted. Password bytes are cleared immediately after vault unlock,
before external document I/O. File fsync and read-back verification cover the
returned descriptor's content; the external provider owns filename/parent-directory
publication and its power-loss behavior. The app does not extend its own directory
durability guarantee to that provider.
Normal import/export does not require ADB, `run-as`, root or a debuggable APK.

The lost-device path is an externally retained encrypted backup plus its password.
If the password is lost but the recovery key was retained, the existing desktop
Rust vault CLI can restore with that recovery key and change the password before
an Android import. The Android preview itself currently accepts password unlock,
not direct recovery-key entry. Losing both unlock material and the backup has no
server-side recovery path.

## Counters and recovery limits

Creation starts at counter zero. Each assertion increments and durably commits
the encrypted counter before a signature is generated or returned. A restored
backup remains backup-eligible and sets the backup-state flag. The strict test RP
requires a counter greater than its last accepted value.

The supported recovery case is the **latest confirmed backup**, restored into a
new private store and a new process, followed by successful RP verification.
If an original device has advanced the RP counter after an older backup was made,
that stale backup may be unable to authenticate. Counter rollback is rejected;
the preview does not guess, reset or silently raise counters. Arbitrary historical
backup recovery and concurrent passkey use across devices are not supported.

## Cancellation, concurrency and uncertain results

One process-wide admission token is acquired before opening the lock file, then
one file lock serializes cooperating processes. Another thread is rejected before
it can open or close the same lock inode: on Android, closing another descriptor
for that inode can release the process's file locks. The token remains owned until
every lock descriptor has been closed. Uncertain lock-descriptor cleanup fences further storage
operations in that process; restart and inspect the current state before retrying.

Private filesystem paths reject symlinks, unsafe ownership/modes and extra hard
links. Every publication takes the live Guard explicitly, checks the expected
ciphertext or target absence twice while holding it, writes and synchronizes a
temporary file, and commits with a same-directory atomic rename. File and parent
directory synchronization and read-back verification follow. First creation and
updates therefore protect against conflicting **cooperating writers**. Android
forbids app hard links, so this protocol does not provide a kernel `NOREPLACE`
guarantee against code in the same UID that ignores the lock. The private directory
and application sandbox remain the access boundary. A failure after publication,
including uncertain lock cleanup, is reported as an unknown outcome.

Raw private-file descriptors have one explicit owner and use `Os.read`/`Os.write`;
short writes are completed, and zero progress fails closed. The lock descriptor is
duplicated into an owning `ParcelFileDescriptor`, with the original closed before
locking. Closing a non-owning `FileInputStream` or `FileOutputStream` wrapper alone
is not used as evidence that a raw Android descriptor was closed.

KDF, package-manager calls, key generation, signing and filesystem work run off
the UI thread. Atomic session invalidation and a volatile cancellation flag do not
wait behind those operations. The worker rechecks expiry, foreground state,
request binding and revocation at each boundary. The final UI handoff rechecks
the current session immediately before finishing the system selection activity.

Cancellation may arrive during a write that already entered the filesystem.
A counter, import or encrypted backup may then be committed while no response is
delivered. That outcome requires reopening and inspecting current state; it does
not authorize blindly retrying a mutation. A response already handed to Android
cannot be withdrawn. Going back and selecting a consumed entry again requires a
new CredentialManager request in this restricted preview.

## Build and verification

`qa/personal_credentials/passkey_build.py` builds with explicitly supplied JDK,
SDK 34/build-tools 34.0.0 and pinned Bouncy Castle 1.86; it performs no dependency
download or phone action. Its private receipt binds sources, build tools, APK
digests and fixture/provider certificates. `NOTICE` records the official
AndroidX 1.6.0 source used for the small platform Slice serialization adapter.

`tests/.../HostInterop.java` is a host-only format/cryptography harness and is
excluded from APKs. `qa/personal_credentials/passkey_rp.py` independently checks
challenge consumption, origin, RP hash, public-key format, UP/UV/BE/BS flags,
signature and monotonic counter. Host cryptographic tests, local RP HTTP tests
and real phone CredentialManager tests are reported separately.

This preview has not received an independent external security review and does
not establish production suitability. Use only newly generated synthetic data.
