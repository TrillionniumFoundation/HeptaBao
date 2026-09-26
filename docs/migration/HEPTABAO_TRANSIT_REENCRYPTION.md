# Explicit Transit ciphertext re-encryption

Current implementation: `clients/python/heptabao/transit_migration.py`.
Executable: `qa/openbao-acceptance/migrate_transit.py`.
This is a bounded migration tool subordinate to the active V2.1 development plan,
not raw-key import, ciphertext-format parity or full-instance cutover.

## Why a real conversion is required

The destination's AEAD binds its namespace, mount and key-name domain. Matching
`vault:vN:` text prefixes do not make an existing OpenBao ciphertext decryptable
at the destination. This tool asks the source Transit API to decrypt an explicitly
supplied ciphertext, encrypts that value under an already existing destination
key/version, and verifies the destination's decryption against the source value.
It never exports a source/destination key or changes source key configuration.

Source API authority is limited to health and the selected Transit decrypt route.
Destination authority needs health, read of `config/keys` and the selected key
metadata, and encrypt/decrypt of that key. Key provisioning, disabling upsert and
freezing administrative changes are separate operator responsibilities. An
administrator changing/removing/recreating keys during migration is outside the
admitted profile: the preflight metadata read is not a distributed lock on key
configuration. Keep both endpoints available and retain source decryption ability
until every output and application-owned cutover has been checked.

## Configuration and input contract

Use owner-only regular UTF-8 JSON files, never secrets in command arguments.
The configuration has exactly these keys (paths and origins are illustrative,
not credentials or defaults):

```json
{
  "source": {
    "address": "https://source.example.invalid:8200",
    "ca_file": "/private/source-ca.pem",
    "token_file": "/private/source-token",
    "namespace": "",
    "mount": "transit",
    "key": "application"
  },
  "target": {
    "address": "https://target.example.invalid:8200",
    "ca_file": "/private/target-ca.pem",
    "token_file": "/private/target-token",
    "namespace": "",
    "mount": "transit",
    "key": "application"
  },
  "target_key_version": 2
}
```

Origins must be distinct HTTPS origins without embedded credentials. TLS uses
frozen host-enrolled CA bytes, not ambient proxies/redirects or trust injection.
Live cluster IDs must also differ. The checkpoint binds both cluster identities,
versions, origins, CA digests, namespaces, mounts, key names, the explicit target
key version and the entire input-list digest. Credential contents are never
stored in that binding; replacing a token does not silently change the target.

The input is a nonempty list of at most 256 objects, each with a unique bounded
`id` and `ciphertext`, plus optional canonical-base64 `context` and
`associated_data`. Unknown fields are rejected. For example an actual input row
is constructed from `{"id":"record-1","ciphertext":<actual source ciphertext>}`;
the placeholder is not accepted JSON and must not be used as a test ciphertext.
Source context is supplied only to source decrypt. AAD is supplied to both source
decrypt and destination encrypt/decrypt; the tool does not discard it to make a
failed conversion pass. Each plaintext is at most 16 KiB and ciphertext at most
24 KiB; these are explicit tool bounds, not the underlying API limits.

The destination key must already exist, `disable_upsert` must be true, and its
type must be `aes128-gcm96`, `aes256-gcm96` or `chacha20-poly1305`, with neither
derivation nor convergence enabled. The requested target version must satisfy
both minimum encryption/decryption versions and not exceed the latest version.
The tool neither rotates nor creates a key. Other profiles need separate adapters.

## Invocation and effects

Create a dedicated empty 0700 absolute state directory in an operator-controlled
parent, and keep configuration/input/token files private. The default is offline
input validation only:

```text
python qa/openbao-acceptance/migrate_transit.py \
  --config /private/transit-config.json --input /private/ciphertexts.json \
  --state-dir /private/transit-run
```

No network request or checkpoint allocation occurs without `--allow-reencryption`.
The dry run cannot establish online permissions or compatible live key metadata.
Adding `--allow-reencryption` explicitly permits decrypt/encrypt/readback effects.
Destination encryption may consume key-use counters even when a response is lost.
The tool never retries an uncertain encryption as though it were a read.

The state directory is descriptor-bound, refuses symlink components and a second
writer, and atomically fsync-publishes 0600 checkpoint files. Each record filename
is `transit-<SHA256(record id)>.json`. The verified `target_ciphertext` field is the
output to associate with that original record ID. Normal stdout contains only
counts and fixed status flags. Application records are **not** automatically
modified: a caller must use verified ciphertexts in its own separately reviewed
transaction/cutover procedure and preserve a rollback mapping.

## Crash and unknown-outcome state machine

```text
no checkpoint
 -> source_pending [persisted before source decrypt]
 -> encrypt_pending [persisted before destination encrypt]
 -> encrypted + actual returned ciphertext [durable before verification]
 -> verified [source/destination decrypts are equal]
```

`source_pending` or `encrypt_pending` on restart is unresolved and blocks all
automatic replay of that record. A source decrypt can itself consume finite-token
or audited service state, so it is not assumed effect-free. Endpoint rejection,
transport errors and failure to publish the returned ciphertext retain the
conservative pending state. The tool does not turn absence of an output into proof
that the encryption never happened. An operator must investigate the preserved
checkpoint and actual source/destination audit/state, and manage any new attempt
explicitly; deleting or editing a checkpoint is not an authorized recovery API.

`encrypted` resumes verification against the saved actual ciphertext, never
re-encrypts it. `verified` is also re-read/decrypted against the live source and
destination on an explicit resumed invocation; it is not trusted as current proof
that keys are still usable. Successful revalidation increments `reused` without
new encryption. A mismatch or revoked/unavailable key cannot yield success.
A crash around verified publication may repeat verification only. Partial runs
retain per-record checkpoints and never claim complete application migration.

## Security, observability and trust limits

No plaintext, base64 plaintext, bearer token, password or exported key is written
to tool-created checkpoints or receipts. Ciphertexts themselves remain sensitive
and are stored only in the private directory. The checkpoint digests detect drift
within trusted local state; they are not signatures against a malicious same-UID
user, root or coherent directory rollback. Protect/back up that directory under
migration custody and do not run competing workflows against it.

Python, TLS and JSON libraries can retain plaintext memory copies; assigning local
references to None does not prove erasure. Use an approved isolated migration
host, disable core dumps, avoid swapping sensitive process memory where possible,
and exclude migration state from ordinary logs/artifacts. Errors are fixed safe
categories, never raw remote response messages or arguments containing credentials.

## Tests and remaining exits

`clients/python/tests/test_transit_migration.py` checks binding drift, endpoint and
key admission, private writer ownership, missing/invalid records, unknown source
and destination effects, checkpoint publication failures, verification mismatch,
revalidation and exact destination version rules.

`qa/openbao-acceptance/transit_migration_live.py` uses only a fresh synthetic
checksum-pinned official OpenBao 2.6.2 and a real TLS HeptaBao process. It invokes
the actual CLI, converts source ciphertexts across rotation with AAD, checks
readback, SIGKILL/reopen/resumption, no new encryption on repeated conversion,
private output/plaintext absence, and a real destination encryption whose response
is deliberately discarded. It checks the pending record is not blindly retried.
Missing official binaries return exit 77 and block CI; no mock substitutes them.

These tests do not qualify external source credentials, derived/convergent target
keys, arbitrary algorithms, customer application cutover, very large batches,
physical-memory confidentiality, or independent migration/security admission.
The aggregate State and replay-ID limits also still apply to destination effects.
