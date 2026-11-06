# JWT ACL oracle: shared local syntax and 23 raw-status cells

This is a SOURCE-only follow-on to R2 commit e3afc157447d35c861f275a761b29da3e42aff8e,
not an execution request. Both candidate compilation and all 23 actual cells
are unobserved. The current qualified 4e808 binary is not substituted for this
new native JWT candidate. No original R1 regression or comparison69 result is
changed or normalized.

## Shared parser contract

Official v2.7.1 path_config.go ffbf35fb32bc41f0c1c617e29fb1e1ae5cfdf027
declares bound_issuer, jwt_validation_pubkeys and jwt_supported_algs. It
requires exactly one local/remote source and parses each public PEM. The
candidate auth.rs and unchanged auth_jwt_pem.rs accept the same three fields.
Use one SPKI RSA2048 public key with exponent65537 and an RS256 allowlist.
The public key's exact bytes/hash remain an explicit unbound slot; do not
substitute a malformed PEM or skip setup admission. No remote JWKS/OIDC or
private key is supplied to either product config. The parent fixture's fixed
owned key-generation/public-export method must be reviewed before execution.

The shared minimum role is role_type=jwt, user_claim=sub and one
bound_audiences string. Both parsers accept these fields; the official role
requires a user claim and at least one bound constraint, both supplied here.
No issuer-specific aliases, metadata, OIDC defaults, claim templates or extra
legacy-only fields are sent. JWT login is not necessary to test role/config
ACLs: actor credentials are REAL product-issued nonroot service tokens.

## Owned setup and actor proof

Run pinned official OpenBao2.7.1 and the actually compiled candidate as two
new owned TLS fixtures with fresh data roots. Candidate uses the real native
File V6 activation and root JWT mount; failed setup is a precondition failure,
not an ACL result. Bind actual binary/config/TLS identities and common fields
before any cell. An old passed source/binary is not a substitute.

Administrative credentials are used only for setup, real actor issuance and
independent before/after state observation. For each cell create an actual
ACL policy on only that exact path, issue its nonroot service token with no
default policy, and independently confirm nonroot/no inherited-policy state.
A no-capability cell still uses a valid real token. Tokens, private keys and
auth headers remain private fixture values, never public evidence. Fixture
input identities and every child/FD/stream must be explicitly owned by the
later reviewed controller. This plan does not introduce a new live wrapper.

Seed distinct existing roles for deletion/update and distinct confirmed-absent
names for creation. Collection tests use a known nonempty inventory. All
writes use valid shared bodies with unique public audience/issuer markers.
Observe the complete relevant common role/config projection before and after,
not only a success code or count. Error cases must not mutate that projection.

## Why POST must be split

Official role path has ExistenceCheck plus BOTH CreateOperation and
UpdateOperation (path_role.go212/219/225). The handler refuses an Update of a
missing role. Therefore testing a fresh name with update-only can yield an
ACL denial even when sudo is irrelevant. Existing-role update and fresh-role
creation have separate rows. Current R2 legacy path requires update+sudo in
both cases. This difference is not silently removed from R2.

## Matrix interpretation

MATRIX.public.json contains five DELETE cells, nine collection cells, three
existing-role POST cells, three fresh-role POST cells and three config POST
cells, 23 in total. The official predictions follow pinned backend/HTTP/ACL
source; the R2 predictions expose known differences. Those are hypotheses
for an actual gate, not reported observations. Every actual raw status is
currently null.

Official bare GET maps to Read while collection only has List; read-only
therefore reaches unsupported operation, predicted405. LIST and GET?list=true
map to List. The candidate's unchanged HTTP parser also maps list=true to
LIST, but its JWT collection handler additionally treats bare GET as list.
DELETE requires official delete; current legacy handler requires update+sudo.
Official config uses Update and no backend Root path; current config requires
update+sudo. The config operation has no role-style ExistenceCheck.

Capture the raw HTTP status, public error class, response length/hash, exact
route/method and independently observed common state. Never normalize403,
404 or405 into an accepted category. Parity requires raw equality plus the
same required state transition; acknowledging an expected R2 divergence is
not PASS. An unexpected official result must be retained and investigated
against the pinned actual setup, not hidden by changing expectations.

## Budget and readiness

The original15-second request clock remains the per-request boundary. No
outer controller or child cap is enlarged here; exact existing custody and
its reviewed outer budget must be bound in a later source request. On an
unknown mutation, preserve the original job/state and stop automatic replay.
This source template is unbound and has no Runtime permission. Product
compile, actual binaries, TLS roots, public key, host and controller/request
identities remain null. Formatting changes require a new source tree before
build; ACL semantic changes require an explicit successor and test diff.
