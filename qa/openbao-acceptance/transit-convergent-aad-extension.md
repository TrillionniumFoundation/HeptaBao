# Explicit AAD-bound convergent encryption

This opt-in HeptaBao extension preserves the default OpenBao 2.7 convergent
algorithm and its existing differential profile. The default remains unsuitable
for varying AAD with the same key, context and plaintext: the pinned official
2.7 binary and the compatible implementation both reuse the nonce while
authenticating different AAD. Passing the compatibility profile is not a claim
that this behavior is safe.

NIST SP 800-38D section 8 requires IV/key uniqueness for distinct input sets;
Appendix A explains the authentication risk from reuse. OpenBao's public Transit
documentation describes versioned convergent algorithms and rotating then
rewrapping to migrate older versions. These documents do not specify this
extension or establish its independent security.

Sources:

- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [OpenBao 2.7 Transit API](https://openbao.org/docs/api/secret/transit/)
- [OpenBao convergent encryption](https://openbao.org/docs/secrets/transit/#convergent-encryption)

## Activation and visible differences

Explicit key creation or rotation accepts integer
`heptabao_convergent_version=1` with a non-exportable symmetric key that has both
`derived=true` and `convergent_encryption=true`. The supported types are
`aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305` and `xchacha20-poly1305`.
This is a HeptaBao extension, not OpenBao's historical convergent version 1.

Creation selects it for key version 1. Rotation generates fresh master material,
selects it only for the new key version, and sets an irreversible encryption
floor. Ordinary and automatic later rotations inherit the new mode. Existing
versions retain their original mode and remain decryptable subject to the
existing minimum decryption policy. Rewrap decrypts the old value and encrypts
using the permitted new key version. Explicit old-version encrypt, rewrap or
datakey requests fail, and configuration cannot lower the floor. Request-level
options cannot select or downgrade the stored algorithm.

The opt-in descriptor exposes `heptabao_convergent_version=1`, the encryption
floor, and the algorithm selection for every retained key version. Default key
descriptors remain unchanged. Ciphertexts keep `vault:vN:` followed by nonce and
AEAD ciphertext/tag. The algorithm is selected from the stored key version,
never by trying multiple decryption algorithms. An OpenBao reader cannot derive
new-mode ciphertexts. Key-state migrations must retain the version metadata.

An already exportable legacy key cannot be upgraded; create a new non-exportable
key and migrate application values instead. Safe keys cannot enable exportability
or export bare master/HMAC material. Plaintext backup and BYOK import endpoints
remain unsupported; this change does not claim to implement them. Reading
existing persisted legacy key state and decrypting its ciphertexts remain
supported. It does not rewrite or delete old material.

## Exact construction

All cryptographic primitives come from the existing maintained libraries: ring
HKDF-SHA256, ring HMAC-SHA256, ring AEAD and the existing XChaCha20-Poly1305
provider. No custom cipher, hash, MAC or KDF primitive is implemented.

Let `L` be 16 for AES-128 and 32 for the other supported types. HKDF extracts the
master material with the existing empty salt and expands to `L + 32` bytes. The
new-mode info is the concatenation of:

1. `HeptaBao/Transit/convergent/aad-bound/v1/kdf` and a zero byte;
2. the key-type byte length as unsigned 64-bit big endian and the key-type bytes;
3. the context byte length as unsigned 64-bit big endian and the context bytes.

The first `L` bytes are the encryption key; the final 32 bytes are the nonce PRF
key. Thus the encryption key is also separated from the legacy algorithm, even
when an identical master and context are used. AES-128 uses all 48 expanded bytes
and does not overlap its encryption key and nonce PRF key.

The nonce input to HMAC-SHA256 is:

1. `HeptaBao/Transit/convergent/aad-bound/v1/nonce` and a zero byte;
2. the AAD byte length as unsigned 64-bit big endian and the AAD bytes;
3. the plaintext byte length as unsigned 64-bit big endian and the plaintext.

Truncate the MAC to 12 nonce bytes, or 24 for XChaCha20. Field lengths prevent
concatenation ambiguity. AEAD authenticates the actual AAD separately as before.
Identical context/plaintext/AAD under the same key version remains deterministic;
changing AAD changes the derived nonce except for a possible PRF collision.

## State and limits

New ordinary-only stores keep the existing durable schema 65, including when
the new binary writes and an old schema-65 binary subsequently reads and writes
that store. The first explicit safe key switches the store to schema 66. This
format activation is irreversible, including after deleting the last safe key,
mount or namespace. Auth, provider completions, replay operations and ordinary
mutations preserve the activated format. Unknown schemas are preserved for
admission to reject rather than normalized into a supported format.

Durable schema 66 records the strict per-version `aad-bound-v1` enum and the
irreversible write floor. Missing metadata means the legacy algorithm. Unknown
algorithm names fail deserialization. A safe key in schema 65 or earlier is
rejected by the new reader. Every namespace is checked for a valid derived,
convergent, symmetric, non-exportable mode and a consistent floor. Old readers
must reject schema 66 rather than ignoring safety metadata; actual public refusal
reasons and unchanged authoritative state/journal hashes are recorded separately.

Snapshot JSON, streaming and forced/native restore share the same admission
guard. A schema-66 store cannot restore a schema-65 snapshot. Existing protected
keys and all protected versions must retain their mode and master material;
their write floor and successful-encryption counters cannot decrease. The
prepared snapshot is also bound to the current state identity, preventing a
later mutation from publishing a stale preparation. Authorized key, mount and
namespace deletion remains destructive; the restore guard tracks active keys,
while the durable schema activation remains sticky after their deletion.

The existing per-version cap of 2^32 successful encryptions remains in force.
The truncated nonce has a probabilistic collision bound, not an absolute
uniqueness guarantee. Operators must bound aggregate invocations across copies
of a key state and account for deterministic equality leakage. Neither these
tests nor the use of maintained primitives constitutes an independent review,
FIPS validation, or a full replacement qualification. The legacy default risk,
independent security review and full replacement claims remain open.
