# External PKI issuer public aliases (finite OpenBao 2.7 scope)

The existing single external issuer can be selected by `default`, its immutable
issuer ID, or its nonempty assigned name. References match exactly. An unknown
reference returns HTTP 500 with an error and no public or private material;
it never falls back to the default issuer.

These GET routes disclose only the existing public certificate or an already
signed full/delta CRL cache. They enter no remote provider operation and do not
create another issuer or change durable metadata. Normal namespace, mount,
unseal/HA, audit and public-read admission remain in place. Service still
publishes necessary monotonic clock and revoked-owner maintenance before
public disclosure. A cache that expired or omits a still-valid revoked
certificate returns 503 and is never rebuilt by a public read.

| Suffix after `issuer/<ref>/` | Content-Type | Representation |
| --- | --- | --- |
| `json` | `application/json` | Exactly certificate, ca_chain, issuer_id, issuer_name |
| `der` | `application/pkix-cert` | Original certificate DER |
| `pem` | `application/pem-certificate-chain` | Canonical certificate PEM, one final LF |
| `crl`, `crl/delta` | `application/json` | Exactly crl, canonical PEM with one final LF |
| `crl/der`, `crl/delta/der` | `application/pkix-crl` | Original selected signed CRL DER |
| `crl/pem`, `crl/delta/pem` | `application/x-pem-file` | Canonical selected CRL PEM, one final LF |

The existing `issuer/default/json` representation already has one final LF.
Legacy CA, serial certificate and CRL public projections keep their existing
no-final-LF representation. The public-read alias increment adds no MIME choices, private fields,
serialization fields, schema numbers or restore exceptions. Active and retired
typed external PKI state still requires the sticky schema-67 floor; JWT and
AAD-bound state retain their separate existing writer requirements.

A pinned two-service official 2.7 HTTPS discovery completed its fixed 115
observations: three references, nine routes, absent/empty bearer, unknown
name/ID and encrypted restart. All positives verified actual provider
signatures and original DER; reads and restart entered zero remote signatures.
This is official discovery, not candidate runtime qualification or independent
qualification. Its original report and 2-second HTTP/360-second outer budgets
are retained separately.

Five native regressions cover all six supported EC/RSA issuer types plus
Ed25519, exact reference and byte binding, request/response audit, unknown
references, denied mutation, namespace isolation, independent expiry/rollback,
lease-owner revocation and encrypted restart, and active/retired authenticated
old-format snapshot rejection. The existing external PKI suite passes 41 tests
with these additions. These native tests do not replace fresh source/binary-
bound Linux public HTTP comparison or actual previous-reader qualification.

The finite external issuance increment accepts `issuer/<ref>/issue/<role>`
for the same single issuer, with exact default/ID/name selection. It resolves an
unknown reference to an error before entering the provider. Selection does not
replace the original request path: ACL admission, request/response audit,
typed lease-owner capture, persisted certificate path and lease ID all keep
that path. The existing canonical `issue/<role>` behavior stays in its prior
format. Original actor, namespace, mount grant, enrolled TLS/host generation,
StateIdentity, publication generation/HA frontier, deadline and final delivery
clock checks continue to govern every entered effect; unknown results are not
retried and no external CA private key is requested or stored.

A persisted issuer-specific path changes the reader contract even though it
uses an existing string field. The all-namespace writer requires schema 71
when any such issued record exists, including revoked or expired records.
Deleting the last record or mount retains the already published 71 label.
Readers reject issuer paths under labels below 71 and continue to decode every
previous supported schema, including BYOK 70, JWT 68/69, typed PKI 67 and
AAD-bound 66. Record preflight and final publication refuse a decreased label.
Authenticated snapshot preparation and final local/HA restore admission
refuse an incoming label below the live protected 71 floor before writer
normalization; ordinary historical snapshots at or below 65 keep their prior
policy. Native-codec predecessor snapshot tests are not actual old-reader
qualification. Actual schema-70 binary refusal for active and retired encrypted
71 state, with authoritative state/journal/seal bytes preserved, remains a
separate required scope.

A fresh pinned official 2.7 provider and consumer completed 52 fixed
observations with 2-second HTTP and 360-second outer budgets. Known issuer
paths issued real signed leaves, preserved their original lease path, and
required exact-path ACL and a live external-key grant. Root/leaf/revoke entered
three/one/two actual provider Sign calls; unknown references, grant denial and
provider-rotation rejection entered zero. Maintained private-key loading and
leaf public-key binding were real. The full CRL contained the revoked serial;
the delta CRL had a valid signature and did not contain that serial. This
contract discovery does not qualify a candidate binary. Source/binary-bound
candidate comparison and actual prior-reader scopes remain outstanding for
this increment.

Remaining PKI work includes multiple issuers, issuer mutation/default changes,
import/rotation, explicit issuer sign authority, OCSP, ACME and other
unclosed API contracts. Full OpenBao replacement, production authority and
independent qualification remain false.
