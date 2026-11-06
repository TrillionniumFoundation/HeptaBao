# Independent security review handoff

Review target: [HeptaBao PR #161](https://github.com/TrillionniumFoundation/HeptaBao/pull/161),
stacked on PR #160. Resolve and record the exact PR head, tree and build artifacts
before beginning a review; the draft will continue to receive client work.
The [status matrix](STATUS.md) and [evidence manifest](../../qa/personal_credentials/evidence/20261106/manifest.json)
separate exact observations from unsupported combinations.

No independent external review has completed. Internal parallel review,
synthetic tests and an automated scan must retain their actual identities and
scope in any later assessment. They do not establish production qualification.

## Security principals and released data

| Component | Trusted principal | Protected material and release point |
| --- | --- | --- |
| Credential broker | Owner issuer, broker OS account, pinned executable | Synthetic upstream token/signing key remains in broker state; the caller receives sanitized status or a public SSHSIG. |
| Personal vault | Local owner account and trusted caller holding an unlock secret | The synchronized envelope contains encrypted entries and wrapped data keys; explicit local get/export or an authorized adapter can release plaintext. |
| Chromium adapter | Installed static extension, native host, browser and owner OS account | An explicit fill releases username/password to the exact authorized page. That page can subsequently read and use them. |
| Opaque store | Authenticated owner transport; clients retain their own frontier | Stores ciphertext and immutable publication receipts. It must never receive the master password or recovery document. |
| Android Autofill preview | Android platform, signed provider, one exact signed native fixture | Each successful fill requires fresh local authorization and returns an ephemeral authenticated dataset to that fixture. |
| Android Passkey preview | Android CredentialManager, signed provider, one exact signed native fixture | Each operation requires fresh password verification and explicit approval; a public WebAuthn response crosses the platform boundary. |

Current HeptaRuntime operator jobs do not isolate an untrusted task from the
owner account. See [RUNTIME_IDENTITY.md](RUNTIME_IDENTITY.md) for the exact gap.
Task/run strings and environment variables must not be treated as workload
attestation. This boundary blocks real-agent credential adoption independently
of the broker's application-level authorization tests.

## Review entry points and questions

### Rust vault and persistence

Start with `crates/heptabao-personal-vault/src/{crypto,filesystem,lib,main}.rs`
and the shared `heptabao-filesystem-guard`. Review fixed Argon2id parameters,
bounded parsing, canonical encoding, nonce generation, authenticated-data
composition, password/recovery separation and error handling before allocating
expensive KDF memory.

Check descriptor ownership, link counts, modes, concurrent mutation detection,
revision/digest CAS, fsync/rename ordering, recovery-document publication and
the distinction between definitely rejected and possibly committed writes.
Review plaintext export and secret buffer lifetimes, including third-party
cryptographic implementations and caller-owned copies.

### Broker and ordinary developer entry points

Start with `crates/heptabao-credential-broker/src/lib.rs`, its executable and
`tools/heptabao_git_signer.py`. Review grant canonicalization, target/method/path
and body binding, task/run/operation separation, clock rollback, expiry,
revocation, ledger capacity and the durable-before-effect ordering.

Attempt redirect/target confusion, operation-ID reuse with changed bytes,
partial response parsing and crashes before/after each publication barrier.
Confirm that an uncertain effect cannot be retried under the same operation,
that denial/non-2xx exit status is meaningful, and that the ordinary Git adapter
cannot issue grants, select another checkout or sign changed payload bytes.
Copied SSHSIG/Git objects remain portable; local checkout binding is not a
cryptographic anti-copy guarantee.

### Browser and native host

Start with `clients/chromium/{worker,popup,fill}.js`, the unchanged manifest,
`tools/install_personal_browser.py` and `heptabao-browser.rs`. Review the real
popup registry association, port disconnect/replacement, window focus,
document navigation, pending Chrome calls, lease expiry and lock acknowledgment
after an already accepted dispatch.

Attempt hidden/ambiguous forms, external associated submitters, overridden form
targets, GET submissions, child frames, forged origins and stale selections.
Check that native stdout backpressure cannot retain an unlocked session, that
closing the action releases the native process, and that no diagnostic path
returns credential values. Native manifest caller routing is not same-UID
process attestation. JavaScript garbage collection does not guarantee immediate
erasure of every string copy.

### Synchronization and recovery

Start with `crates/heptabao-personal-edge/src/sync.rs` and the two-device
controller. Review generation-aware heads, immutable exact-operation receipts,
capacity accounting including orphan objects, repair admission, fsync failure
fencing and historical fetch. Challenge the A-to-B-to-A case and stale offline
writers. A conflict must preserve both recoverable histories.

Whole-store rollback by a hostile server and a production device-enrollment
protocol are not implemented. The physical-device experiment used an
authenticated operator transport and a store sharing device A's trusted OS
account. Review a future client frontier and separate service principal before
claiming those stronger boundaries.

### Android clients

Review final source/APK manifests and installed signer digests, not only Java
source or an application label. The Autofill preview needs exact package,
certificate, activity, native view and fresh request binding, including
cancellation, backgrounding, expiry and system-cached dataset reuse.

The Passkey preview needs browser-independent native caller verification,
one-time selection tickets, exact final-request binding, UP/UV semantics,
P-256 key handling and counter persistence before signing. Review the real
CredentialManager path and separate RP verifier together while retaining their
independent roles. None attestation does not prove hardware or biometrics.

Import/export must operate on bounded ciphertext, require an explicit local
choice, preserve a recoverable private copy on uncertain publication and avoid
debug-only access as the claimed ordinary user workflow. Review the fresh-store
restore path and the explicit rejection of old backups whose counters have
already been exceeded. Java strings and JCA internals are not completely
zeroizable by application code.

## Evidence required before expanding support

An external assessment should identify its reviewer/service, date, exact source
and artifact identities, tested threat model, affected paths, reproducible
findings, severity reasoning and unresolved limits. Remediation needs a changed
source identity and a regression that demonstrates the original failure as well
as the corrected behavior. Preserve earlier failed observations.

The release decision also requires a deployed task-isolation boundary, supported
platform receipts, actual upgrade/rollback rehearsal, recovery from loss of a
device, retained compatibility results, measured stability over an explicit
duration and operational ownership. Code inspection cannot substitute for those
runtime or operational observations. Real credentials remain outside this
synthetic preview's acceptance scope.
