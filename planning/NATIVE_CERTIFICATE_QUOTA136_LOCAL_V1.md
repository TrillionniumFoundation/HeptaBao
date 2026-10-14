# Native certificate quota schema 136
Schema 136 is assigned to persistent certificate quota reader authority. Schema 135
is independently assigned to database lease precision and is not implemented by
this B9-based leaf. Combined readers may recognize 135 only with its actual source.

This extension supports root namespace native AppRole and exact-leaf certificate
mount and login rules. Definitions persist as encrypted Auth owner data. Rate-limit
buckets remain per-node observed transport-IP RAM. Global, namespace inheritance,
HA ingress, quota audit-device and optional header profiles remain unsupported.

Role selection shares the existing readonly certificate resolver with login:
observed TLS chain, strict DER and original request-time certificate validity,
enrolled leaf fingerprint and existing certificate constraints. It never mints
a token or lease. Missing or invalid role identity produces an empty quota role;
exact-path and mount rules still apply. Caller body, headers and requested role
names never establish certificate or transport-IP identity.

The new marker is sticky after rule deletion. Downgraded or erased native Auth
owners and readers below 136 must reject the certificate quota state.

Fixed OpenBao 2.7.1 primary sources:
- internal/builtin/credential/cert/path_login.go blob
  582351412733c1e6ea8903b2db1e0a05a85f667a, SHA256
  7945be5f2b28cb4ad3f357918ee615b2fbf7cc386e516c5289e12504b1822cda:
  ResolveRole verifies credentials and returns matched Entry.Name without issuance.
- internal/http/util.go blob dcae672588649b62be651e5fe36296155153a3a9,
  SHA256 33d4af7e2d39583da9635340b7280a8fb7b21e166aa32d972ec426cddf3dc140:
  role-resolution failure retains an empty role; client IP is RemoteAddr.
Both blobs verified against fixed v2.7.1 tree a5db72cef75c24b920ade02065b18dd8eb666bac.

Qualification is limited to local real-DER resolver and Service/durable-state
regressions. No certificate-login network probe, production custody, or full
OpenBao replacement claim is admitted by this source leaf.

Native auth catalogs reject overlapping mount paths. The initial local r01 test
incorrectly assumed a parent cert mount and its child could coexist; those two
cases failed at the existing 400 catalog guard. r02 preserves that guard and
tests distinct legal mounts (cert and cert-child/deep), exact path-segment
boundaries, cross-leaf rejection and independent role/fallback buckets. Generic
auth and plugin routing are unchanged from B9.
