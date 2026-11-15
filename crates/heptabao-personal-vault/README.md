# Personal encrypted vault candidate

`heptabao-personal-vault` is a Unix client library and executable CLI for an offline encrypted vault. It stores login, note and API entries, generates passwords and TOTP codes, provides a local password health count, and supports encrypted backups plus an explicit plaintext exchange format. This implementation is a candidate evaluated with synthetic data; it has not received independent security review or production qualification.

## Build and run

```text
cargo build -p heptabao-personal-vault
cargo test -p heptabao-personal-vault
cargo clippy -p heptabao-personal-vault --all-targets -- -D warnings
```

Create the vault root and any output directories beforehand (the initial recovery output uses a separate private directory), with mode `0700`, owned by the current OS user. Paths must be absolute, contain no symlink components, and name ordinary local directories. Existing vault, backup and import files must be private regular files with mode `0600` and one link. Secret output files are created once with mode `0600`; overwriting an existing output is refused.

The executable interface is:

```text
heptabao-vault <absolute-vault-root> <command>
```

Each command consumes one JSON object on stdin and reaches EOF before executing. Input is capped at 8 MiB. A terminal stdin is refused, so secrets are supplied by a trusted local program through a pipe or a private file. Passwords, recovery material and entry secrets must not be put in argv, environment variables or command history. The default stdout response contains status and metadata; failures use a fixed error code on stderr and a nonzero exit status.

This minimal local Python caller prompts without echo and supplies the password over the child process's stdin. It does not print entry secrets:

```python
import getpass
import json
import subprocess

root = "/absolute/private/vault"
password = getpass.getpass("Vault password: ")
request = {"password": password}
result = subprocess.run(
    ["/absolute/path/heptabao-vault", root, "list"],
    input=json.dumps(request).encode(),
    capture_output=True,
    check=False,
)
print(result.stdout.decode(), end="")
print(result.stderr.decode(), end="")
raise SystemExit(result.returncode)
```

The Python example has ordinary Python memory behavior; use the Rust library when the caller also needs explicit buffer zeroization. All decrypted exports are deliberate plaintext artifacts and remain until the local owner removes them.

## Command inputs

Except `init`, `restore` and `generate`, commands require either `password` or `recovery_key`. Each invocation unlocks for a single operation and then clears the session. The JSON input may omit unused optional fields; unknown fields are refused. Mutations require the exact `expected_revision` returned by `list` or a prior successful mutation.

| Command | Additional input | Behavior |
| --- | --- | --- |
| `init` | `password`, `output` | Persist the new recovery document in a separate private output directory, then create revision 0. Password is 12–1024 bytes. |
| `list` | None | Return item IDs, kinds, titles, exact origins and a TOTP-present flag. No usernames, passwords, notes or TOTP seeds. |
| `put` | `expected_revision`, `item` | Insert or replace one validated item by ID, advancing the revision. |
| `delete` | `expected_revision`, `id` | Delete an existing item and advance the revision. |
| `get` | `id`, `output` | Write the selected complete plaintext item to a private JSON file. |
| `totp` | `id`, `output`; optional `unix_seconds` | Write only the code to a private file; use current system time unless explicitly supplied. |
| `generate` | `output`; optional `length` | Write a CSPRNG password. Length is 16–128 characters, default 24. No vault password is needed. |
| `health` | None | Count checked, empty, shorter-than-16-character and reused non-note secrets locally. |
| `backup` | `output` | Copy the authenticated encrypted envelope to a new private backup file. |
| `restore` | `input`, and either `password` or `recovery_key` | Validate and decrypt a backup, then publish it to a new root without an existing vault. |
| `export` | `output`, `confirm_plaintext_export: true` | Write all entries and their vault identity to a private plaintext JSON file. |
| `import` | `input`, `expected_revision`, `confirm_replace: true` | Replace the entry set from this vault's plaintext export. A foreign vault identity is refused. |
| `change-password` | `new_password`, `expected_revision` | Generate a new salt and password wrapper; preserve the random vault key and recovery wrapper. |

A login item has this shape. The following values are synthetic examples:

```json
{
  "id": "example-login",
  "kind": "login",
  "title": "Synthetic login",
  "username": "synthetic-user",
  "origin": "https://example.test",
  "secret": "synthetic-placeholder-only",
  "notes": "Synthetic test entry",
  "totp": null
}
```

`kind` is `login`, `note` or `api`. `id` is 1–64 ASCII letters, digits, `_` or `-`; `title` is 1–1024 bytes; `username` is at most 4096 bytes; `secret` and `notes` are each at most 65536 bytes. The vault supports up to 4096 items with a 4 MiB serialized plaintext ceiling. Notes and API entries may omit the origin; login entries require a nonempty secret and exact HTTPS origin.

Origins use lowercase ASCII DNS hosts containing a dot and an optional nondefault port. Paths, userinfo, wildcard domains, suffix matching, uppercase or trailing-dot aliases, query strings, fragments, IP literals and explicit default port 443 are refused. A browser integration must also validate the actual page, top frame and caller before asking `login_for_origin` to release an entry.

TOTP configuration uses `secret_base32`, `algorithm` (`SHA1`, `SHA256`, `SHA512`), `digits` (6–8), and `period` (15–120 seconds). Base32 is uppercase without padding, canonical trailing bits, and at least 128 decoded secret bits. Tests exercise the [RFC 6238 appendix vectors](https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B).

## Encryption, restart and recovery

The on-disk `vault.hbv` is an encrypted envelope. A random 256-bit data key encrypts the item payload using AES-256-GCM, with a fresh 96-bit random nonce on every write. The data key has separate password and recovery wrappers. The password key uses Argon2id version 1.3 with 64 MiB, three iterations, four lanes, a random 16-byte salt and 32-byte output, corresponding to the [second recommended RFC 9106 profile](https://www.rfc-editor.org/rfc/rfc9106.html#section-4). The recovery key is an independently generated random 256-bit value.

Authenticated data binds the envelope format, cipher, KDF profile, vault identity, revision and both wrappers. All parsers enforce the fixed format and parameter limits before invoking the KDF. A server syncing only `vault.hbv` has neither the password-derived key nor the recovery key; do not include recovery documents or plaintext exports in that ciphertext sync stream.

Initialization persists recovery material before the first vault commit. If that output path already exists or is unsafe, initialization returns an error without creating `vault.hbv`. A later vault publication failure may leave an unused recovery document; inspect the vault state and choose a new output path if initialization genuinely needs to be attempted again.

For a lost device, retain an encrypted backup separately from either the password or the recovery document. On a replacement device, create a new private root and use `restore` with the backup and one of those independent unlocking secrets. The recovery document identifies its vault and contains `recovery_key`; pass only that value through local stdin. Missing both unlocking secrets makes recovery unavailable. Tests exercise recovery after independent process restarts and after a real SIGKILL of a session owner.

The existing descriptor-anchored filesystem guard holds an exclusive directory lock for each session. Writes check both the caller's expected revision and the loaded envelope digest, write and fsync a private temporary file, publish by directory-relative rename, and fsync the directory. Failed or uncertain publication locks the session; reopen and inspect the current revision before deciding what remains to change. Orphan temporary files from a crashed writer are not treated as committed vault state.

## Qualified limits

SDK sessions reject every access after a monotonic absolute deadline, capped at one hour. The SDK caller must schedule `lock()` or drop the session at that deadline to clear idle in-memory plaintext; borrowed item references are trusted local access. The CLI clears its session after each command. The Chromium native adapter is a separate crate that supplies the idle timer.

The OS account is trusted, including code that ignores the cooperating-process lock protocol. Zeroization covers application-owned secret buffers and the Argon2 work area, not every possible compiler, allocator, OS swap, core-dump or third-party cipher copy. The SDK neither locks memory nor uses platform key storage.

Restoring an entire old ciphertext envelope is not detected without an external trusted monotonic anchor. Password changes cannot invalidate copies of old backups and do not revoke the recovery key. Already released plaintext on a lost device cannot be remotely erased. Plaintext import currently supports this vault's explicit JSON export, not arbitrary third-party CSV or credential exchange formats. Platform providers, Passkeys, sharing, remote device revocation and real Android qualification are outside this crate.
