# Native root JWT R2 source freeze

Source commit e3afc157447d35c861f275a761b29da3e42aff8e has sole parent
4e808d0ecb1bcded22870a7ec960dfb2491cf6ec and tree
5497775d9d473541e13e1603be8c893a3e27681b. It modifies seven files and adds
two. No ref, qualified binary, evidence branch or active fixture was changed.
No Rust formatter/compiler/test or Runtime action was performed.

## Concrete R2 fixes

R1 wrongly rejected a real Token API service child because it retained the
JWT auth_mount but correctly had TokenApi provenance and a parent. R2 requires
the real closed origin: root/enabled JWT mount; known origin; no root policy,
wrapping or certificate origin; direct Jwt is parentless, while TokenApi needs
its issued-creation TTL and validated public creation path. Existing
validate_token_api_creation_ttl and validate_public_origin_state remain
authoritative. A mount string alone is insufficient.

The parent graph resolves actual stored tokens and refuses missing parents,
cycles, namespace/mount mismatch and backwards created_at SECONDS. It does
not claim new subsecond ordering validation. Memoization prevents repeated
whole-ancestry traversal. Existing precise token clocks, issuer ancestry and
native source/CAS custody still own authorization. Original revoke-orphan can
leave a parentless TokenApi with the same valid own origin/TTL/path; a profile
predicate alone is not historical authorization proof.

The second repair admits only non-login Jwt owners to the EXISTING
BatchIssuerOwner selection. Its TokenApi source already captures real parent,
digest, role, orphan and CIDR state without rejecting JWT service parents by
provenance enumeration. bind_batch_reply opens the actual sealed grant and
checks parent, namespace, public origin, precise issuance/TTL and actual
lease_issuer_by_digest_observed. Existing paired lifecycle and check_current
retain actual parent ancestry, original clock and exact reply/proof. No new
provider, receipt, batch format or issuer is introduced. Direct JWT batch
LOGIN remains rejected.

Mixed Userpass/JWT operations keep the existing Userpass actor/target priority.
Shared native delivery still owns complete source, Identity, token clock,
target, ACL, exact response and original publication proof. New regressions
exercise both real cross-target directions; they are not yet executed.

## Preserved R1 safety and actual failure order

The existing verified_claims invocation is selected once. Its existing PEM
keyset may try several keys; this is not one primitive cryptographic attempt.
Each native request begins with fresh local None lifetime slots. Only its real
verification fills one; actual Identity finalization must succeed before the
second exports it. Ordinary wrappers pass None. No durable/public schema or
later-request witness reuse is added.

Known prepublication rejection selects no new logical token/Identity root.
Unknown durable/HA outcome retains original UNKNOWN/recovery/no replay and
cannot be described as zero writes. After known complete publication, audit
or delivery veto withholds credentials but retains the whole durable root.
Mandatory audit failure keeps recovery required. No rollback, re-login,
deadline reset or audit-order rewrite is added.

Profile scanning remains cooperative, not preemptive. The original request
clock and before/after source/planning/publication/delivery checks remain;
there is no new timeout or grace interval. The new parent comparison is only
second-granularity. Actual cost under the original deadline remains unmeasured.

## Regressions and limits

The whole 23,058-byte R1 regression file is an identical R2 prefix. All ten
original test definitions and assertions remain. Five independently named
sources add real service descendants, batch grants, revoke-orphan/mount
retirement, mixed Userpass targeting, and detached invalid-origin/parent
probes. REGRESSIONS.public.json maps all fifteen names. The negative detached
values are never installed into the real fixture.

No old 60/61, LAN98+12, full34 or comparison69 denominator changes. Qualified
4e808 binary results do not qualify this candidate. These new fixtures use
actual File V6, public service calls and cold reopen; they do not alone prove
network HA or production deployment. Remote/JWKS/discovery/OIDC, child JWT
namespaces, JWT batch login and wrapping remain outside this slice.

## Official ACL difference is outstanding

Legacy named-role DELETE currently uses update+sudo; collection bare GET uses
list. The unchanged R1 regression records the legacy implementation only.
Root's official v2.7.1 primary source bundle
bbebf79f4e89b5c40621316bb8965a96785435a5 / report
295980f0394775b8dcccdfd90ce0d389ee369f62 identifies a real difference:
role collection ListOperation, named DeleteOperation, no backend Root path;
HTTP GET=Read except list=true, LIST=List, DELETE=Delete; policy ACL maps those
operations to the corresponding capability. This is source evidence, not an
actual oracle PASS. A separate shared-config/raw-status ACL gate must lead to
an explicit compatibility correction, not silently edit the original tests.

## Validation and recovery provenance

The original local R2 byte/lexical checker returned exit0 / 237 checks. Its
two actual executor responses are retained here; the detailed local result
and checker file were not yet Git-archived when the executor became
unavailable, so this packet does not pretend they are accessible. R1's full
historical packet is attached unchanged. The new pure-V8 freeze verifier
independently checks exact bytes, splices, test-prefix/name mapping and source
trees without executing any Rust module.

A later local-first pending intent write failed after 644 seconds before any
Git mutation. The same exact intent was then written through the permitted
Git-only path, whole-read back, and the source commit was created once and
whole-read back. The original failure is retained. Original source-tree
readback native objects are reserialized as DERIVED entries, not mislabeled
as original missing SDK bytes. Environment-dependent formatter/build gates
remain frozen until reliable durable execution journaling is restored.
