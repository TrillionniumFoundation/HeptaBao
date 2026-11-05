# EC/RSA provider review

The native Transit implementation binds the safe `openssl` 0.10.81 API to
`openssl-sys` 0.9.117 with its `aws-lc` feature. The lock file resolves
`aws-lc-sys` 0.41.0, whose packaged source identifies AWS-LC 1.73.0. This feature
builds AWS-LC; it does not select the `openssl-src` vendored provider. The native
regression verifies the running provider identifies itself as AWS-LC.

Private generation, entropy, ECDSA arithmetic, RSA-PSS/PKCS1v15, and RSA-OAEP
are performed by the provider's safe API. The adapter handles the public API's
Base64 framing, digest selection and ASN1/JWS signature encodings. Persisted
private material uses provider-generated PKCS8 DER inside the existing
zeroizing key-version and barrier-protected state owners. Exports use the
provider's traditional EC/RSA PEM serializers; diagnostics expose fixed errors.
Tests compare sensitive values through predicates and never print key material,
serialized secret state, plaintexts or signatures on assertion failures.

Reviewed on 2026-10-01 against primary maintainer advisories:

- [AWS March 2 bulletin](https://aws.amazon.com/security/security-bulletins/2026-005-AWS/): PKCS7 verification and AES-CCM issues were fixed in aws-lc-sys 0.38.0.
- [AWS-LC name constraints advisory](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-394x-vwmw-crm3): patched aws-lc-sys 0.39.0.
- [AWS-LC CRL scope advisory](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-9f94-5g5w-gf6r): patched aws-lc-sys 0.39.0.
- [rust-openssl AES-KW-PAD bounds advisory](https://github.com/rust-openssl/rust-openssl/security/advisories/GHSA-phqj-4mhp-q6mq): patched openssl 0.10.80. The reviewed 0.10.81 version is newer.
- [OpenSSL September 29 advisories](https://openssl-library.org/news/vulnerabilities/): the vendored OpenSSL 4.0.2 provider was avoided. CVE-2026-54872 concerns generic non-NIST EC scalar multiplication; the native API exposes only the three named NIST curves.

These version comparisons are an assessment of the cited disclosures, not a
claim that no future issue exists. Dependency scans remain enabled. This build
uses the non-FIPS AWS-LC package and makes no FIPS-validation claim.

The explicit SHA1 signing option is the documented legacy Transit wire
contract. It is not used for password storage, default signatures, RSA-OAEP or
new credential proofs. The default signature digest and RSA-OAEP/MGF1 digest
are SHA256. See the [public Transit API](https://openbao.org/docs/api/secret/transit/).

Qualification requires the strict `transit_asymmetric_live.py` 2.7.0 comparison
on fresh candidate and checksum-pinned official processes. Positive signatures
are independently verified with Python cryptography; OAEP is exercised in both
directions across that library and each service. Source, lock, runner, oracle
and binary identities are bound in the comparison receipt. Native unit success
alone does not qualify replacement support.
