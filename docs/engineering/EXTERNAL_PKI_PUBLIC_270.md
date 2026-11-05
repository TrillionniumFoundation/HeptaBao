# Bounded public external PKI projections

The public capability selects an existing namespace, mount and issuer. It does
not create a principal. For an external Ed25519 issuer it exposes seventeen
public route forms: issued certificates in JSON/DER/PEM, CA JSON/DER/PEM,
CA chain JSON/PEM, full and delta CRL JSON/DER/PEM, issuer LIST and GET-list,
and the default issuer JSON projection. Certificates bind the original public
DER; CRLs are the original signed cache and cannot be rebuilt by a public read.
Issuer identifiers and key identifiers are copied from the stored issuer.

The top-level Service performs its existing HA/read-index, unseal, namespace,
mandatory audit and durable lease-owner maintenance before this capability is
selected. Bearer authentication, finite-use consumption and wrapping-token
consumption are bypassed for these public reads, including invalid/expired
bearers. Explicit creation of a response wrapper retains separate admission.
Issue, revoke, rotation, role and configuration operations require their
original authorization. A missing mount or different namespace gains no public
capability from another mount's issuer.

Public projection handling makes no business mutation and enters no external
provider Sign. Safety maintenance may persist a monotonically advancing lease
clock, expired/revoked owners and the resulting cache invalidation. Root-only
external issuers participate even without an active leaf lease. An observed
expired CRL remains unavailable across clock rollback and encrypted restart.
Necessary maintenance is not a no-commit claim. The existing `writer_schema()`
continues to select schema 66 when safe convergent Transit state or the store's
irreversible schema floor requires it; public maintenance cannot downgrade it.
Internal local CRL rendering can use the existing local signing primitive and
is not counted as an external provider operation.

The fresh public profile predeclares 317 native-comparison cases. It includes
17 routes times 6 bearer states on each side (204 reads), 34 reads after the two
encrypted restarts, five denied sensitive operations per side, exact root/leaf/
revoke provider Sign counts, cryptographic binding, private-field absence and
one request/response audit pair per read. The separate official-only QA contract
predeclares 308 cases and excludes all nine native owner-revocation safety
checks. An official-only preflight never qualifies candidate code. No result
can pass with a shortened prefix, reordered cases, missing metadata, different
MIME types, ambiguous crypto acknowledgement or missing actual readback.

Every qualification requires its own immutable build source/tree, outside
custody binary digest and before/after identity/cleanup evidence. Current
frozen production qualification does not transfer to this increment. All whole
OpenBao compatibility, production, migration and independent qualification
flags remain false. The legacy KMS CSR reference behavior, non-Ed external PKI,
response wrapping, full issuer management and full PKI surface remain separate
work; the bounded public routes do not resolve those differences. The original
failed public/CSR/profile records are preserved.
