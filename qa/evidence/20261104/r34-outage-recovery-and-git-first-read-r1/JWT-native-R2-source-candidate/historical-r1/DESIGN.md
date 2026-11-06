# Root native JWT: isolated source proposal

## Status and baseline

This is an unformatted, uncompiled SOURCE proposal based on commit
`4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`, tree
`eba5e650bd080b8ad41ea52a2bc68867f541d255`. It modifies seven existing Rust
files and adds two files. It does not modify the qualified source, evidence
branch, active binaries, host fixtures or production configuration. There are
zero Runtime calls and zero Rust test executions in this proposal. The frozen
R1 is an intermediate proposal with the two functional blockers recorded in
`CROSS-REVIEW.md`; it is not ready for compilation admission or deployment.

The existing JWT verifier, native claim handling, local key formats, issuing
role, Identity projection, token renewal and token revocation already exist.
The missing production integration is the root native V6 profile, route owner
and retained delivery custody. Removing the profile guard alone would not
supply those contracts.

## Deliberately bounded implementation

The new route owner admits only root-namespace JWT mounts with local key
configuration and service-token roles. It admits the existing mount/tune,
config, role/list, login and relevant Token API operations. Remote JWKS and
discovery configurations, OIDC, child JWT namespaces, JWT batch issuance and
JWT response wrapping remain outside this slice. Existing MFA/SDK/external
provider guards remain unchanged.

The metadata eligibility predicate is not authentication. Real requests still
pass through the original JWT handler. No credential, role, key, policy, entity
or signed assertion is reconstructed from a test fixture or receipt.

For role management the owner preserves the **current legacy implementation**:
named DELETE uses `update + sudo`, and collection GET uses `list`. These facts
come from the pinned `jwt_role_route` and `jwt_route` bodies. They are not an
independent OpenBao 2.7.1 compatibility result. A later ACL oracle comparison
must observe these two operations on both pinned implementations; the new
regression only prevents this integration from silently changing the existing
implementation's contract.

## One verifier invocation and a private lifetime witness

`NativeJwtLifetime` is a crate-private, non-serialized, non-cloneable value with
private fields. The original verifier body still calls `verified_claims` once.
It retains the exact original NumericDate parsing, optional-date inference,
legacy strict-expiry branch, clock skew, maximum lifetime, namespace, issuer,
audience and bound-claim predicates. The time predicate is moved without
changing its arithmetic into `NativeJwtLifetime::check_at`.

The ordinary verifier wrapper continues to return only its original identity.
The ordinary Auth and Service wrappers pass no lifetime slot. Only the native
JWT login path creates a fresh local `None` slot and selects the private
identity-plus-lifetime verifier return. It invokes one branch, not both.

The Auth handler fills its output only after its actual verified login and
Auth candidate updates succeed. Service uses a second request-local `None`
slot and exports it only after the actual Identity finalization and candidate
installation have succeeded. An Identity error returns without exporting it.
No lifetime is stored in AuthState, Service, AuthResponse, LoginIdentity or any
durable schema. Both receiving entry points reject a pre-filled slot. The
native caller consumes the value once; missing or unexpected leftovers fail
closed. A later request cannot reuse a previous request's value.

`NativeJwtOwner::bind_successful_login` binds that value to the original source
mount and role, the new service token's stored JWT provenance, root namespace,
fresh token digest, accessor and real Identity entity. It does not verify the
assertion again. Source custody retains the complete original Auth image and
request body through the existing `NativeAuthDelivery` machinery.

## Persistence, Identity and lease ownership

| Concern | Existing owner and added binding |
|---|---|
| JWT trust and role | Original Auth JWT parser/handler; complete source Auth digest remains pinned. |
| Signed assertion time | One private verifier-produced lifetime, checked using the continuing original request clock. |
| Token and renewal | Original Auth token registry and JWT provenance/TTL implementation; no external issuer request on renewal. |
| Identity | Original `finish_identity_response_observed`, root Identity Engine delta, and native identity-only Engine guard. |
| Durable publication | Original `commit_native_root_plan`, exact source/CAS conditions and complete root publication. |
| Final response | Exact status/body digest, real local or HA proof, original terminal checkpoint, mandatory response audit, current credential/ACL checks. |
| Unknown outcome | Existing native writer failure/recovery handling; no retry, fresh key or synthetic successful receipt. |

No new durable fields, schema numbers, provider capsule, lease subsystem,
network operation or subprocess are introduced. The existing Auth/Identity
projection is committed as one native root. `auth_only_root_change` and the
original Engine Identity delta guards remain in force. JWT operations gain the
same retained local proof and terminal-checkpoint requirements already used by
the typed native owners. They never acquire a replacement proof after audit.

Renewal deliberately does not revalidate the original assertion or its later
trust keys. The original `auth_jwt_renewal.rs` is byte-identical: it uses the
issued token, current issuing role and original TTL/provenance rules. This
slice grants no separate provider lease; service-token lifetime belongs to
Auth. Mount disable and revocation use the existing token retirement path.

## Correct failure atomicity

The original native transaction is preserved; audit is not moved ahead of
publication. An earlier planning statement that *every audit failure implies
no committed delta* was incorrect and is expressly superseded here.

1. **Known rejection before root publication.** Verification, Identity,
   original-time or owner-capacity rejection must not select a new token,
   Identity or JWT metadata root. The request-local candidate and lifetime
   witness are discarded, and no credential is returned. This claim concerns
   logical selected state; it does not assert that every lower-level failure
   removes previously staged immutable objects or diagnostic records.
2. **Publication outcome unknown.** An I/O or durable/HA outcome with unknown
   authority retains the existing writer's failure notice, recovery state and
   no-replay semantics. This proposal neither reports zero writes nor guesses
   which root became durable. The writer is unmodified.
3. **Known complete publication, then audit/delivery rejection.** The whole
   committed root remains. A failed mandatory audit withholds the credential
   and preserves recovery/UNKNOWN semantics. Expired original assertion,
   altered response, stale proof or intervening real revocation also vetoes
   delivery without rolling back a durable commit. No automatic re-login is
   attempted.

All added checks use the original `NativeDeadline` and original `RequestClock`.
There is no new production timeout, retry loop, clock reset or grace interval.

## New regression source, independently counted

The ten new tests use configured File V6, the real public activation endpoint,
actual local JWT signing/verification, actual Identity, native publication and
ordinary audit/delivery. The baseline cannot pass the setup's real JWT mount.
No token, actor, publication receipt or verification witness is forged.

| New test | Required observation |
|---|---|
| Local service token / renewal / cold reopen | Reusable assertion creates distinct tokens for one entity; retained value, expired-assertion/key-rotation renewal, revoke and mount disable survive cold reopen. |
| Remote/batch/bad signature rejection | Known closed profiles and invalid signature return no credential; complete relevant Auth and Identity projections stay unchanged. |
| Legacy role ACL contract | Collection GET needs list; named DELETE works with update+sudo; absent sudo rejects without delta. Oracle parity remains separate. |
| Identity failure / next fresh login | Disabled entity rejects after actual verification without exporting witness/token; a later request succeeds with its own fresh witness. |
| Assertion expiry before publication | One test-only pause after actual JWT+Identity crosses expiry; no logical candidate delta, no pending delivery, cold state unchanged. |
| Native owner capacity veto | Original root fits; new token/Identity exceeds the existing writer capacity. A zero-delay observation confirms real authentication was reached; the original writer rejects publication with 507. |
| Assertion expiry after commit | Real complete root is present; expiration during audit suppresses delivery and leaves that root intact. |
| Post-commit mandatory audit failure | Existing audit-capacity injection causes actual audit failure; credential withheld, complete root retained, recovery required. |
| Audited response / original deadline | Altered status and elapsed original deadline cannot be rebound into a successful delivery. |
| Post-audit real revocation | Preserve the actual affine owner/proof, perform one separately authorized real revocation, then reject delivery through the stale original proof; cold token remains revoked. |

The existing Userpass unsupported-provider test changes only its `jwt` example
to `oidc`, which remains unsupported by the native profile. Its name and every
assertion remain. This necessary expectation update is not counted as a new
JWT test and does not silently alter the existing qualified 60/61, LAN 98+12,
full34 or comparison69 denominators.

## Costs, validation and next gate

The existing verifier is invoked once, with no second authentication pass.
Its unchanged PEM-keyset branch may try the cryptographic primitive against
multiple matching keys before finding a valid key. This proposal does not
claim one cryptographic primitive invocation for every key format. The native path additionally
checks a small private time value and the closed JWT metadata profile, while
using the pre-existing full-source serialization, proof and complete-root
publication. Profile validation traverses stored roles/tokens; its cost has
not been measured and is subject to the original request deadlines. No budget
is increased to accommodate the integration.

`verify_source.py` performs byte pins, canonical Git tree membership, lexical
function/declaration preservation, explicit integration-order checks and exact
candidate splice reconstruction. It is explicitly not a Rust parser, compiler,
formatter, cryptographic test or product execution. Its earlier checker-only
mistakes/performance limitation are retained separately from the candidate.

The next required gates are independent source review, the real pinned
formatter, Rust compile/strict lint, the ten new regressions, the existing JWT
verifier/renewal and native Auth/Identity regressions, and exact source-bound
qualification of any successor binary. Faults at lower durable/HA publication
boundaries still require their existing fault/reconciliation harness; the
capacity regression does not claim that it simulates an I/O/unknown outcome.
Current 4e808 qualifications remain attached to their existing artifacts.

The two R1 Token API blockers discovered during the requested owner-priority
cross-review are not covered by the ten new regression sources. The next
SOURCE revision must close them and add independent tests while preserving
these ten tests. The deadline scan remains cooperative at enclosing custody
gates, not preemptible inside each metadata iteration; see `CROSS-REVIEW.md`.
