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
no-final-LF representation. This change adds no MIME choices, private fields,
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

Remaining PKI work includes multiple issuers, issuer mutation/default changes,
import/rotation, explicit issuer issue/sign authority, OCSP, ACME and other
unclosed API contracts. Full OpenBao replacement, production authority and
independent qualification remain false.
