# heptabao-personal-vault module closure dossier

The closure validator binds this module to the exact Git commit and
`crates/heptabao-personal-vault/src` tree. This is a source/design record with
separate execution requirements, not production, migration or release admission.

## Design and state ownership

The Unix library and `heptabao-vault` CLI use `heptabao-filesystem-guard` as the
only direct internal dependency and are outside the server runtime closure.
`VaultSession` owns an exclusive directory fence, decrypted payload, random data
key, expiry and expected ciphertext revision/digest. `crypto.rs` owns format-1
AES-256-GCM envelopes and password/recovery wrappers; `filesystem.rs` owns
publication and readback; `otp.rs` owns bounded TOTP/password generation.
The entry kinds are login, note and API, with explicit local import/export.

## Module boundaries and trust assumptions

The owner account and SDK caller are trusted. Private files, input bounds and
descriptor-relative access protect the cooperating local workflow but do not
isolate a malicious process using the same UID. Ciphertext-only storage does not
receive the master password, data key or independent recovery key. Browser/app
identity, platform providers, sync transport, hardware custody and sharing belong
to separate integrations. Explicit plaintext outputs remain the owner's
responsibility after release; borrowed values cannot be retroactively revoked.

## Failure semantics and ordering

Every read checks the monotonic session deadline. Mutations require the caller's
exact revision and unchanged loaded-envelope digest, then write/fsync a temporary
file, publish, establish directory durability and read back the published bytes.
Uncertainty locks the session
and requires reopen/inspection; a visible write is not replayed merely because
its acknowledgement failed. Initial recovery material is published before the
first vault, and backup restore authenticates the envelope before create-only
publication. Restore never silently replaces an existing destination vault.

## Acceptance evidence

**Named executable anchor:** `readback_fault_after_publication_is_unknown_and_not_replayed` in `crates/heptabao-personal-vault/src/filesystem.rs`.

Required execution: `cargo +1.98.0 test --locked -p heptabao-personal-vault`.
`tests/vault.rs` separately exercises authenticated header/ciphertext tampering,
reopen and recovery, password rotation, local health, TOTP vectors, private-path
denials and independent CLI processes. The test
`killed_owner_releases_fence_and_committed_data_survives` covers an actual killed
session owner. A passing source test establishes its named behavior, not all
platform integrations or production cryptographic assurance.

Run `python scripts/validate_module_closure.py` and
`python scripts/validate_current_documentation_semantics.py` for source/guide
binding. Retained executions are indexed in
`qa/personal_credentials/evidence/20261106/manifest.json` and remain bound to
their own commits, binaries and harnesses. This dossier does not inherit their
pass status for a later source or platform combination.

## Known gaps and evolution

State is `IMPLEMENTED_REVIEW_REQUIRED`. Whole-vault rollback detection requires
an independent trusted anchor. Password rotation does not revoke old backups or
the recovery key. An SDK owner must schedule idle `lock()`/drop; access-time
expiry checks alone are not background memory erasure. Complete heap/swap
erasure, hardware key storage, arbitrary third-party migration, sharing, remote
revocation and independent security/production review remain open. See the
[module guide](../modules/heptabao-personal-vault.md) for supported recovery paths.
