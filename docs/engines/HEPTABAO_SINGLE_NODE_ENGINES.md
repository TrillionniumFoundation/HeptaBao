# Single-node secret engine implementation

Status: implemented candidate; explicit API subset; not a production or complete
OpenBao replacement acceptance. This document describes the code under
`crates/heptabao-server/src/engines.rs`, `engines/{kv,transit,totp}.rs` and
`engine_tests.rs`. It is separate from the older in-memory domain-model crates.

## Responsibility and integration boundary

`EngineState` is the serializable, secret-bearing engine state inside the server's
authenticated encrypted snapshot. It owns namespace-local mounts and their
resources. It does not listen on a socket, authenticate a caller, decide whether a
caller is an administrator, or save an unencrypted file. Those responsibilities
belong to `Service`, `AuthState`, the TLS listener and the durable storage adapter.

The call boundary is:

```rust
EngineState::handle(
    &mut self,
    namespace: &str,
    method: &str,
    path: &str,          // no /v1/ prefix
    body: &serde_json::Value,
    now: u64,           // server-supplied Unix seconds
) -> Result<Option<EngineResponse>, EngineError>
```

`None` means the path is not a mounted engine or mount-management route. An error
is an explicit HTTP status and a fixed diagnostic without key material or request
payloads. A response contains `status`, `body` and `mutated`. Its body is already
an OpenBao-style `data` envelope, except a no-content response has JSON null and
HTTP 204. The HTTP server owns outer response fields and request identifiers.

The engine clones the selected namespace, validates and operates on that
candidate, then replaces live engine state only for `Ok(response)` with
`response.mutated == true`. The service additionally operates on a candidate of
the complete server state and commits an encrypted snapshot before exposing the
result. A failed CAS, invalid metadata field, invalid key configuration or failed
AEAD verification therefore cannot partially alter durable engine state.

**HTTP status alone is not a commit decision.** A Transit batch with both
successful and failing items normally returns HTTP 400 with ordered item results.
It must commit if `mutated` is true. Otherwise a successfully returned upserted-key
ciphertext could become undecryptable after restart. All-failed batches leave
state unchanged. TOTP invalid but well-formed guesses return HTTP 200 with
`valid:false` and `mutated:true`, so their attempt counters survive restart.
Invalid syntax returns an error without changing state.

The service must evaluate `required_capability(namespace, method, path)` while
holding the same lock as the subsequent mutation. KV writes distinguish `create`
from `update` based on existing version metadata, including soft-deleted entries;
PATCH requires `patch`. Transit encrypt upsert and key creation, and TOTP key
creation, make the same existence distinction. Mount mutation additionally
requires the service's administrator/sudo authorization. The engine never accepts
a caller-supplied policy decision. A caller of the Rust API is responsible for
authorization; this module is not itself an authenticated public API.

The HTTP adapter can merge validated query values into the body object. Direct
module callers may alternatively leave a query suffix on `path`. Duplicate body
and query parameters are rejected. `version`, `depth`, `after`, `limit` and
`list=true` are supported where relevant.

## Structural isolation and serialization

The identity hierarchy is represented by nested maps:

```text
EngineState.namespaces[namespace]
  .mounts[mount_path_with_trailing_slash]
  .backend.{Kv1 | Kv2 | Transit | Totp}
  .entries[resource] or .keys[key_name]
```

The expression above is a schema path, not a concatenated storage key. Namespace,
mount and resource are distinct serialized fields. For example namespace `a`
with resource `b/c` and namespace `a/b` with resource `c` occupy different maps.
Transit authenticates their identities again as separate fields in AEAD AAD.

Default mounts in a namespace are `secret/` (KV v2) and `transit/`. Defaults are
materialized on the first successful mutation; a read of an otherwise untouched
namespace does not dirty the state. TOTP and KV v1 mounts are explicitly enabled.
Mount paths can have multiple canonical segments. Ancestor/descendant mount
overlaps are rejected, as are reserved `sys`, `auth`, `identity` and `cubbyhole`
prefixes. A disabled mount is removed with its state and stays disabled across
snapshot reload. Recreating a mount creates a new empty backend.

Resource paths reject empty segments, `.` and `..`, controls, backslashes,
percent escapes and query/fragment delimiters, and are bounded to 1,024 bytes.
Namespace canonicalization is performed by the service before calling the
engine. No prefix comparison grants access to another namespace.

State and response `Debug` implementations redact their contents. Stored Transit
material and TOTP seeds are wiped on drop. KV versions, discarded candidates,
overwritten/deleted KV v1 values, custom metadata and owned JSON response strings
are cleared before release. Decoded private material, generated secret bytes,
Transit decrypted plaintext, enrollment URLs and temporary request copies use
drop-based clearing. This is an owned-buffer hygiene measure, not a guarantee
that allocators, compiler temporaries, crypto-provider internals, swap, crash dumps
or historical encrypted snapshots contain no recoverable copies. Operators must
still protect the host and snapshot encryption keys.

## Mount management

| Method and path | Implemented behavior |
| --- | --- |
| `GET sys/mounts` | Namespace-local descriptors, backend types, options and default lease settings |
| `POST/PUT sys/mounts/:path` | Enable `kv`, `kv-v1`, `kv-v2`, `transit` or `totp` after option validation |
| `GET sys/mounts/:path` | Read one mount descriptor |
| `DELETE sys/mounts/:path` | Remove the mount and its namespace-local resources |
| `GET sys/mounts/:path/tune` | Read supported mount configuration |
| `POST/PUT sys/mounts/:path/tune` | Change description; accept an unchanged KV version |

Online KV version conversion, custom lease tuning, local mount replication
semantics, seal wrapping and external entropy sources are not implemented.
Requests for these options return explicit errors. PKI, SSH, database, LDAP,
Kubernetes and other engine types return HTTP 501 instead of registering a
nonfunctional mount. There is no generic plugin-success route.

## KV v1

KV v1 stores JSON objects at arbitrary canonical paths in its own mount. POST and
PUT replace the complete object and return 204. GET returns the object under
`data`; DELETE removes it permanently. LIST emits only immediate children and
adds `/` to folder entries. SCAN emits descendant paths recursively. Missing read
or empty list returns 404. Values are not filtered by per-key ACL during listing;
authorization applies to the requested list path, so secret values must not be
encoded in path names.

## KV v2

Each key stores configuration, current version, oldest retained version,
created/updated timestamps, optional string metadata and an ordered version map.
Each version contains its creation time, optional deletion deadline, destroyed
flag and optional JSON data. The integer version map remains lossless through
JSON serialization and snapshot restart.

| Method and relative path | Behavior |
| --- | --- |
| `GET/POST/PUT config` | Read/update retention, required CAS and deletion duration |
| `POST/PUT data/:path` | Create a full new version; optional `options.cas` |
| `PATCH data/:path` | JSON merge patch of a readable version; creates a new version |
| `GET data/:path?version=N` | Read selected version; zero/omitted selects latest |
| `DELETE data/:path` | Soft-delete latest version |
| `POST/PUT delete/:path` | Soft-delete listed positive version numbers |
| `POST/PUT undelete/:path` | Clear deletion deadline for retained, nondestroyed versions |
| `POST/PUT destroy/:path` | Remove selected version data and retain destroyed metadata |
| `GET metadata/:path` | Return key configuration and version metadata |
| `POST/PUT metadata/:path` | Set key configuration/custom metadata without a new data version |
| `PATCH metadata/:path` | Modify metadata on an existing key; null map entries remove fields |
| `DELETE metadata/:path` | Delete all key versions and metadata |
| `LIST/SCAN metadata/:prefix` | Immediate/recursive key listing, with `after` and `limit` |
| `LIST/SCAN detailed-metadata/:prefix` | Listing plus complete metadata for leaf entries |
| `GET subkeys/:path` | Preserve object shape while replacing values with null; optional depth |

CAS is checked before mutation. An explicit zero succeeds only when no data
version exists. A stale number fails with 400. A soft-deleted or destroyed latest
version does not reset the current version. Engine-wide or per-key required CAS
cannot be bypassed by omitting options. PATCH additionally requires a current
readable version; null removes object members, nested objects merge recursively
and arrays replace as whole values.

GET of a retained deleted or destroyed version returns 404 with its version
metadata and null data. It does not fall back to an earlier live version. A
missing or retention-pruned version returns 404 without synthetic metadata.
Deletion deadlines are checked at read and patch time without dirtying state.
Un-deletion clears the deadline; it does not restore destroyed/pruned data.

Retention resolves from nonzero key `max_versions`, then nonzero backend value,
then a default of 10. New writes remove older records outside that window.
Changing a limit affects subsequent writes. The supported upper bound is 10,000
retained versions per key. Deletion durations support compound integer `s`, `m`
and `h` units and a maximum of ten years. Fractional/sub-second durations return
an explicit error; they are not silently rounded. A key deadline is capped by
a nonzero backend deadline. Timestamps use RFC 3339 UTC at second resolution.

Custom metadata is string-to-string, with up to 64 members, keys up to 128 bytes
and values up to 512 bytes. Unsupported parameters fail before a candidate is
published. Secret JSON data itself can contain nested objects, arrays, numbers,
strings, booleans and null.

## Transit

Each named key stores its type, policy minimum versions, export/delete flags,
soft-deletion state, latest version and a version map. Each version has independent
CSPRNG-generated key material, an independent 256-bit HMAC key, creation time and
a persisted encryption count. Private signing material uses ring's PKCS#8 output.

| Key type | AEAD | Sign/verify | HMAC |
| --- | --- | --- | --- |
| `aes128-gcm96` | AES-128-GCM, 96-bit random nonce | No | SHA-256/384/512 |
| `aes256-gcm96` | AES-256-GCM, 96-bit random nonce | No | SHA-256/384/512 |
| `chacha20-poly1305` | ChaCha20-Poly1305, 96-bit random nonce | No | SHA-256/384/512 |
| `ed25519` | No | Pure Ed25519 | SHA-256/384/512 |
| `hmac` | No | No | SHA-256/384/512 |

All primitives and randomness come from ring and the platform entropy source.
There is no handwritten cipher, hash, entropy generator or signature primitive.

| Method and relative path | Behavior |
| --- | --- |
| `POST/PUT keys/:name` | Create key; return 200 plus public descriptor; existing definition is idempotent |
| `GET keys/:name` | Return policy and version metadata, never symmetric private keys |
| `LIST keys` | Paginated names |
| `POST/PUT keys/:name/rotate` | Generate another independent version; return 200 with updated descriptor |
| `POST/PUT keys/:name/config` | Set minimum versions, explicit deletion permission and one-way exportability |
| `DELETE keys/:name` | Delete only after `deletion_allowed` has been explicitly set |
| `DELETE keys/:name/soft-delete` | Disable cryptographic use without removing material |
| `POST/PUT keys/:name/soft-delete-restore` | Restore use of the retained key |
| `GET/POST/PUT config/keys` | Read/set `disable_upsert` |
| `POST/PUT encrypt/:name` | Base64 plaintext to opaque versioned AEAD ciphertext; authorized upsert if enabled |
| `POST/PUT decrypt/:name` | Verify AEAD and return base64 plaintext |
| `POST/PUT rewrap/:name` | Authenticate old ciphertext and encrypt under selected/current version |
| `POST/PUT datakey/{plaintext,wrapped}/:name` | Generate 128/256/512 random bits and encrypt them; plaintext only on the explicit plaintext route |
| `POST/PUT hmac/:name[/:algorithm]` | Versioned HMAC over base64 input |
| `POST/PUT sign/:name` | Versioned Ed25519 signature over base64 input |
| `POST/PUT verify/:name[/:algorithm]` | Verify signature or HMAC with minimum-version policy |
| `POST/PUT random[/platform][/N]` | Platform CSPRNG bytes in base64 or hex |
| `POST/PUT hash[/:algorithm]` | SHA-256/384/512 over base64 input, in hex or base64 |
| `GET export/{encryption-key,hmac-key}/:name[/:version]` | Explicitly exportable symmetric/HMAC material only |

The opaque envelope is `vault:vN:BASE64(nonce || ciphertext || tag)`. Its AAD is
the JSON tuple of a format-domain identifier, namespace, mount path, key name and
decoded caller `associated_data`. Therefore an identical raw key moved to a
different namespace/mount/name cannot decrypt the original ciphertext. This is
an intentional security/portability boundary: OpenBao ciphertexts are not
promised to decrypt here merely because the text prefix matches. Migrating
Transit data requires source decryption followed by destination encryption, or a
future independently verified import adapter with explicit domain handling.

Encryption, rewrap and datakey use count as mutations. A version refuses further
encryption after 2^32 encryptions. Random nonces still have probabilistic collision
limits; high-volume users must rotate substantially before exhausting a key.
Decryption does not advance the count. Entropy failure returns 503 and never
falls back to deterministic bytes. Authentication failure returns a generic 400
without decoded data. Original ciphertext remains decryptable after rotation
until its version is excluded by `min_decryption_version` or the key is deleted.
No version is silently destroyed by rotation; the key version map is bounded to
10,000 versions.

Encrypt/decrypt/rewrap/HMAC/sign/verify support ordered batches of up to 256
items, individual fixed diagnostics and optional references. Nested batches are
rejected. Partial failure follows the commit rule above. Inputs are bounded to
approximately 4 MiB of decoded material, in addition to the HTTP request limit.

Derived/context keys, supplied nonces, convergent encryption, RSA/ECDSA/XChaCha,
SHA-224/SHA-3, Ed25519ph, BYOK wrapping/import, plaintext backup, automated periodic
rotation and unsupported export formats are explicit errors. Descriptor flags
report the implemented capabilities; for example `supports_derivation` is false
even where an OpenBao key of the same cipher type reports true.

## TOTP provider and generator

Enable with `POST sys/mounts/totp {"type":"totp"}`. TOTP uses ring HMAC according
to RFC 6238, with SHA1, SHA256 or SHA512, six/eight digits, periods between 1 and
3,600 seconds and skew zero/one. SHA1 is confined to the standardized TOTP
compatibility mode; general Transit hash/sign endpoints do not offer SHA1.

| Method and relative path | Behavior |
| --- | --- |
| `POST/PUT keys/:name` | Import a base32 key or otpauth URL, or generate a new key with platform CSPRNG |
| `GET keys/:name` | Public enrollment metadata only; no seed or URL |
| `LIST keys` | Paginated key names |
| `DELETE keys/:name` | Remove key definition and validation state |
| `GET code/:name` | Generate current code, generation/expiry seconds and period string |
| `POST/PUT code/:name` | Validate exact decimal code and persist acceptance/guessing state |

Generated enrollment requires issuer/account name and supports 10–128-byte keys.
With `exported:true`, callers must explicitly set `qr_size:0`; the response
contains a standards-compatible otpauth URL. Requested QR PNG generation returns
501. `exported:false` returns no secret enrollment material. URL import checks
the scheme, duplicate parameters, issuer consistency, percent encoding, base32
padding and supported algorithms. Malformed or whitespace-padded codes return
400. There is no MFA login integration hidden behind this engine: authentication
methods must explicitly add an MFA challenge flow before using TOTP for login.

Successful validation advances a per-key `last_accepted_counter`; the same or an
earlier counter cannot succeed again after restart or a backward clock change.
Re-importing the same seed and algorithm/period/digits preserves that state.
Wrong well-formed guesses increment a per-key persisted failure count, limited
to ten within a time period; further attempts return 429 until the server clock
advances to a later period. Namespace, mount and key all isolate these counters.
A privileged administrator can replace/delete a seed, which intentionally creates
a different credential lifecycle. Host clock synchronization remains an operator
responsibility. The generate-code route requires its own ACL read grant; clients
that only validate codes must not receive that grant.

## Validation and remaining acceptance work

The module suite is executed with:

```sh
cargo test -p heptabao-server engines --lib --offline
cargo clippy -p heptabao-server --lib --tests --offline -- -D warnings
```

Twenty engine tests passed during implementation. They cover KV lifecycle/CAS
atomicity and recovery, structural namespace/mount separation, retention and
deadline behavior, merge patches, lists/scans, all three AEAD implementations,
tampered ciphertext and AAD, exact-key transplantation across domains, rotation
and minimum-version policies, Ed25519 and HMAC verification, RFC 4231 HMAC case 1,
a SHA-256 known value, partial batch recovery, datakey/export behavior, required
capabilities, explicit unsupported modes, all eighteen RFC 6238 TOTP vectors,
RFC 4648 base32 examples, replay across restart/reimport/clock rollback, domain
isolation, URL enrollment and durable guessing limits. The service integration
suite and external TLS/OpenBao observer remain separate evidence; this document
does not relabel unit tests as independent black-box acceptance.

For any addition, extend the backend enum and exhaustive dispatcher, implement
truthful mount descriptors and capability classification, define atomic/error
behavior, add secret-buffer cleanup, document unsupported options and add an
independent known vector or external provider test where cryptography is involved.
Then add a public-HTTP observer case, restart/failure evidence and migration
acceptance. Implementing another route does not establish HA or migration safety.

## Primary references

- [OpenBao 2.6.x KV v2 API](https://openbao.org/docs/api/secret/kv/kv-v2/): API field/path baseline. Actual code semantics and supported limits above are the HeptaBao implementation contract.
- [OpenBao 2.6.x Transit API](https://openbao.org/docs/api/secret/transit/): cryptographic operation paths, version envelopes, batch behavior and key policy baseline. Create/rotate responses were corrected against the actual OpenBao 2.6.2 binary during independent observation.
- [OpenBao 2.6.x TOTP API](https://openbao.org/docs/api/secret/totp/): enrollment/code route baseline, including explicit no-QR enrollment.
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238): TOTP algorithm and fixed interoperability vectors.
- [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231): HMAC SHA-2 test vectors.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648): base32 encoding examples.
