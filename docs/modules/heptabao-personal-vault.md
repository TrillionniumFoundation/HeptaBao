# heptabao-personal-vault

Status: `IMPLEMENTED_REVIEW_REQUIRED` / V3. This is an offline Unix library and
CLI candidate evaluated with synthetic data. It is outside the executable
`heptabao-server` dependency closure. Shared rules are in
`docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`; the
[module closure dossier](../module-closure/heptabao-personal-vault.md) records its
design and acceptance boundary.

## Purpose and non-goals

The crate stores encrypted login, note and API entries, generates passwords and
TOTP codes, counts local password-health findings and supports explicit backup,
restore, import and export. It works without a server. It does not own browser
page identity, Android application identity, Passkey creation, sharing, remote
device revocation or an automatic cloud synchronization service. Independent
security review and production adoption remain outside this implementation claim.

## Public API and ownership

`crates/heptabao-personal-vault/Cargo.toml` defines the library and
`heptabao-vault` executable. The direct internal dependency is
`heptabao-filesystem-guard`. `src/lib.rs` owns `VaultSession`, `VaultItem`,
`ItemKind`, metadata, mutations and revisions; `crypto.rs` owns the envelope
and key wrappers, `filesystem.rs` owns safe publication, `otp.rs` owns
`TotpConfig`, `totp` and `generate_password`, and `main.rs` owns the JSON CLI.

`VaultSession` provides `create`, `create_with_recovery_file`, `open`,
`open_with_recovery`, `metadata`, `summaries`, `get`, `login_for_origin`, `put`,
`delete`, `change_password`, `encrypted_backup`, `restore`,
`restore_with_recovery`, `export_plaintext`, `import_plaintext`, `health` and
`lock`. Callers own input and any intentionally returned plaintext. The library
cannot revoke a borrowed item reference or erase a copy retained by its caller.

## State and data model

`vault.hbv` is a format-1 JSON envelope containing a random vault ID, revision,
fixed KDF profile, password and recovery key wrappers, and encrypted payload.
The payload has login/note/API items and at most 4096 entries. Serialized
plaintext is capped at 4 MiB; files are capped at 8 MiB; secret and note fields
are bounded at 65536 bytes each. A live session owns the directory fence, data
key, decrypted payload, expected envelope digest and monotonic absolute expiry.
The lifetime must be positive and no longer than one hour.

## Invariants and authorization

AES-256-GCM encrypts the payload using a random 256-bit data key and a fresh
96-bit nonce on each write. Password wrapping uses Argon2id version 1.3 with
64 MiB, three iterations and four lanes; a separately generated random 256-bit
recovery key supplies the other wrapper. Authenticated data binds the format,
cipher, fixed KDF parameters, vault identity, revision and both wrappers.
Parsing enforces the admitted profile before invoking expensive cryptography.

Every access checks the session deadline; mutations also require the exact
observed revision and unchanged ciphertext digest. Login release requires an
exact canonical HTTPS origin. That string check does not establish browser page
identity: an integration must independently validate its actual caller, target
and top frame before requesting an item.

## Failure, retry and reconciliation

Writes create and fsync a private temporary file, publish relative to the locked
directory, establish directory durability and verify the published bytes by
readback. A failed or uncertain
mutation locks the session. Reopen and inspect the committed revision instead
of repeating a possibly committed replacement blindly. `OutcomeUnknown` does
not mean the old ciphertext remains authoritative. Crash-created orphan files
are not promoted to committed state.

Initialization through `create_with_recovery_file` publishes the separate recovery
document before the first ciphertext; refusal of an existing or unsafe output
does not create a vault. A later vault publication failure may leave an unused
recovery document. Restore authenticates the backup and refuses an existing
vault at the destination. Plaintext import requires the same vault ID, an
explicit replacement request and the current revision.

## Concurrency and ordering

`ExclusiveDirectory` fences cooperating writers for the session lifetime. The
expected revision protects the caller's logical observation; the expected file
digest detects external ciphertext replacement before publication. SDK access
checks do not run a background idle eraser: the embedding program must schedule
`lock()` or drop the session at expiry. The CLI exits and clears its session
after each command; the separate native browser adapter supplies an idle timer.

## Security and privacy

Vault roots are owner-private directories. Paths must be absolute and free of
symlink components; input files must be private regular files with one link.
Secret outputs are create-only private files. Passwords and recovery material
arrive through bounded, non-terminal stdin, never CLI arguments or environment
variables. Normal stdout contains metadata, not item secrets.

The trusted OS account can read decrypted process memory and explicit plaintext
exports. Same-UID adversaries, swap, core dumps and all third-party/allocator
copies are outside the zeroization guarantee. A ciphertext-only server has no
password-derived key or recovery key; keeping recovery documents and plaintext
exports out of that server is a required caller obligation.

## Persistence and compatibility

The envelope accepts only format 1, AES-256-GCM and the fixed KDF profile.
Password changes replace the salt and password wrapper while retaining the data
key and recovery wrapper. They cannot invalidate old backup copies or revoke
the recovery key. Replacing an entire vault with older valid ciphertext is not
detectable without an independently trusted monotonic checkpoint. Plaintext
exchange supports this vault's explicit JSON format, not arbitrary third-party
CSV, platform credential exchange or unrestricted cross-vault migration.

## Observability

Metadata reports the vault ID, revision and bounded item summaries; titles and
origins are intentional local metadata. Password health reports only checked,
empty, short and reused non-note secret counts. It makes no network breach
lookup. `VaultError::code` produces fixed failure codes, while secret-bearing
debug output is redacted. There is no remote metrics exporter or audit server.
Explicit `get`, `totp`, `generate` and `export` write plaintext only to the
requested private output file and must not be republished as diagnostic logs.

## Operations

Build with `cargo +1.98.0 build --locked -p heptabao-personal-vault`. Invoke
`heptabao-vault <absolute-vault-root> <command>` using the stdin fields documented
in `crates/heptabao-personal-vault/README.md`. Create private roots/output
directories beforehand and keep recovery material separate from ciphertext.
For a lost device, restore an encrypted backup into a new root using either the
password or independent recovery key. Losing both unlocking secrets makes
recovery unavailable. Already disclosed plaintext on a lost device cannot be
remotely erased by this crate.

## Tests and executable evidence

Run `cargo +1.98.0 test --locked -p heptabao-personal-vault`. The in-source test
`readback_fault_after_publication_is_unknown_and_not_replayed` in
`src/filesystem.rs` exercises a publication that became visible before readback
failed. Integration tests in `tests/vault.rs` include
`ciphertext_reopen_recovery_and_password_rotation`,
`authenticated_header_and_ciphertext_tampering_fail`,
`revision_fence_lock_expiry_and_orphan_recovery`,
`totp_rfc6238_vectors_and_password_generation`,
`independent_cli_processes_keep_secret_out_of_stdout` and
`killed_owner_releases_fence_and_committed_data_survives`.
They cover crypto validation, independent processes and a real killed owner.
Retained receipts in `qa/personal_credentials/evidence/20261106/manifest.json`
retain their own source/binary/harness binding; listing a test here is not a new
pass receipt and does not qualify a different platform implementation.

## Evolution and open boundaries

Future formats need explicit migration and downgrade behavior. Sharing, device
revocation, trusted rollback detection, hardware key custody, platform providers
and comprehensive password-breach checks require separate designs and execution.
The browser and Android integrations must establish their own identity and
lifecycle evidence. This module's local encryption and recovery behavior does
not imply P3/P4 device qualification or P5 long-term production readiness.
