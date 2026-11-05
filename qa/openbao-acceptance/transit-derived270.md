# Derived Transit 2.7 profile

The fixed differential trace covers AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
and XChaCha20-Poly1305 in ordinary, derived and convergent modes. It checks real
decryptions, independent maintained-library HKDF and AEAD verification for AES
and ChaCha, deterministic nonce predicates for all four algorithms, typed
context/AAD input, batch errors, data keys, version selection, rotation,
rewrap, minimum versions, exports and process restart. XChaCha AEAD is checked
by actual encrypt/decrypt; its nonce PRF is checked independently.

Derived keys use HKDF-SHA256 with empty salt and the decoded context as info.
Convergent keys use the versioned derived nonce key and HMAC-SHA256 of the
plaintext, truncated to the algorithm nonce length, matching the pinned 2.7
public API observations. Context and AAD remain inputs to authentication.
Caller-supplied modern nonce fields are ignored by that observed contract.
This is compatibility evidence, with no new FIPS or independent security claim.

Ordinary false derivation flags are omitted from serialized owner records so
their authenticated canonical representation remains readable in both
directions. Schema stays 65. The independent clean 53bfe0fc (schema-65) control
reader returned 503 with the fixed authenticated-record-validation error for
a new true derived/convergent owner record; this was not an explicit schema
identifier rejection. The negative attempt preserved state.hbs, journal.hbj
and all other authority files. Only ledger.hbl changed during its established
nonce rebuild. Reopening with the new reader preserved both true attributes
and successfully decrypted the original ciphertext.

The live report retains only ordered case labels, HTTP statuses and Boolean
predicates. Synthetic key exports, ciphertexts, plaintexts and credentials
stay in fixture memory. A passed trace establishes this profile's exact
scope; whole replacement and production authority remain separate gates.
