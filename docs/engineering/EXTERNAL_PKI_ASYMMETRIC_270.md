# Bounded EC/RSA external PKI increment

The six public Transit key types are `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`,
`rsa-2048`, `rsa-3072` and `rsa-4096`. A fresh checksum-pinned OpenBao 2.7.0
provider and external PKI consumer supplied 168 ordered safe observations over
verified HTTPS, with a two-second budget on every HTTP call and a 360-second
outer limit. No mutation was retried. This is official-only contract research,
not candidate qualification or independent attestation.

All six remote public keys bound the generated root SPKI. Maintained consumers
verified root, leaf and full/delta CRL signatures, and loaded the returned local
Ed25519 leaf private key against its leaf public key. Each root entered remote
Sign three times, each leaf once and each revoke twice. Cached and restarted
reads entered Sign zero times and returned the original signed public material.
After grant deletion, issuance returned 500 without a certificate or Sign.
Restoring the grant recovered real issuance. Provider rotation retained v1
public material but the fixed-reference issuer rejected new issuance with 500,
without a certificate or Sign. The earlier legacy KMS CSR difference remains.

| Issuer key | TBS digest | Signature AlgorithmIdentifier |
| --- | --- | --- |
| P-256 | SHA-256 | ECDSA with SHA-256, absent parameters |
| P-384 | SHA-384 | ECDSA with SHA-384, absent parameters |
| P-521 | SHA-512 | ECDSA with SHA-512, absent parameters |
| RSA 2048/3072/4096 | SHA-256 | SHA-256 with RSA PKCS1 v1.5, NULL parameters |

Every EC/RSA Sign request uses the actual TBS digest, `prehashed:true`, the
matching `sha2-*` name, `signature_algorithm:"pkcs1v15"` and the fixed version
as a string. Ed25519 keeps its existing pure-message request. The first research
summary deliberately retains its SHA-256-only diagnostic predicates: they are
false for P-384/P-521. Actual public signature verification, their observed
SHA-384/SHA-512 request fields and 48/64-byte lengths are separate predicates;
those old diagnostics are not relabeled as correct hash bindings.

The native increment parses public SPKI with the already locked OpenSSL
provider. It bounds DER to 8 KiB, requires canonical DER re-export equality,
and binds the declared kind to the exact curve or modulus bit length. EC public
validity uses maintained `check_key`; RSA public n/e must be positive odd
values with exponent at least 3 and smaller than the modulus. The maintained
parser already rejected the tested infinity, exponent 0/1/2 and even-modulus
inputs before these additional checks; this is defensive validation, not a
claim that those inputs were previously accepted. Every
remote signature is verified using the real public key and the selected digest
before assembling the certificate, CSR or CRL. TBS and outer algorithm
identifiers use the same closed mapping. No external CA private key is parsed,
requested or stored. Local leaf generation and standard PKCS8 delivery retain
their original owners and zeroizing buffers.

Schema 67 gates typed SPKI. Legacy Ed25519 `public_key` remains the exact
32-byte JSON array. An EC/RSA value is a closed `{kind,spki_der}` object with
unknown fields rejected. Both active and retired typed issuers retain the
schema-67 writer floor; publication cannot lower any valid previous schema.
AAD-bound Transit state still requires schema 66 and the all-namespace writer
selects the greatest required floor. Readers refuse typed material mislabeled
below 67 and all unknown schema numbers. The actual prior schema-66 binary must
refuse encrypted active and retired schema-67 state before this increment can
receive runtime qualification. Authenticated snapshot preparation and the last
local/HA restore admission reject an incoming label below the live protected
67 floor, including after typed-key retirement. They check the incoming label
before HA writer normalization. The original AAD 66 binding/floor checks remain,
and ordinary historical snapshots at or below 65 keep their prior restore policy.

The general writer floor also applies to every older supported version. Legacy
unit fixtures therefore construct their historical authenticated input through
an explicitly `cfg(test)` bounded predecessor helper. Valid historical inputs
must pass their original format gate; intentionally malformed authenticated
graphs use a separate rejection-fixture helper and keep the direct production
commit refusal. Both helpers refuse protected/future state across namespaces,
restore the temporary predecessor label on Result errors and panics, and never
add a production entry point. These tests are current-code codec simulation,
not actual prior-binary qualification. Future-version fixtures use the maximum
supported schema plus one, independently of the unchanged AAD floor.

The existing original Principal, ACL, namespace/mount grant, deployment-enrolled
TLS endpoint, host generation, StateIdentity, durable generation/HA frontier,
deadline, owner, monotonic clock and post-audit delivery-veto gates remain the
authority. One unknown entered effect withholds the entire result; no remote
signing effect or encrypted publication is blindly retried. The native six-key
tests and encrypted restart evidence are development checks. New immutable
production custody and complete curve-specific comparison/prior-reader profiles remain
required. Full PKI, full OpenBao compatibility, production, migration and
independent qualification claims remain false.
