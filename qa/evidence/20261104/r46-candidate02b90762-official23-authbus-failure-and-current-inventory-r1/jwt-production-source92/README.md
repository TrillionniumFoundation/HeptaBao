# JWT-local role policy and ACL correction — SOURCE only

This packet contains twelve complete proposed Rust leaves, their exact current before versions, strict forward/reverse diffs, and an independent pure-V8 source verifier. It creates no commit or Runtime request. All Rust compilation and runtime qualifications remain pending.

## Application

Use `SOURCE-MAP.public.json` as the exact leaf mapping. Ten files change and two are new. The `auth.rs` chain includes actual root-provisional `c407b407…` → prior draft2 `c6a15172…` → proposed `c755af14…`; the direct actual-to-final diff is also present. The Service before is the actual formatted snapshot49 `6574a4d5…`, and the Native test before is Identity2 `57dd3760…`. Do not replace either with an older checkout.

The role API and token issuance are separate stages. Roles save their configured policy list without injecting default. Login computes issued policies from the stored role flag. A writer with the proper role route capability need not already own the future login policies. Root configuration remains writable; the preexisting login check rejects root before issuance. Shared ACL helpers and renewal source are preserved.

The internal optional marker distinguishes historical absent metadata from new false semantics. Both Some(false) and Some(true) raise schema147; old None is byte-compatible. State format, publication, namespace scanning, sticky writer floors and snapshot downgrade checks are included. The historical test factory only constructs an unpublished old-format role and commits it once through the real publication checks.

## Verification

Evaluate `pure-helper.original.js`, `strict-diff-helper.original.js`, `source-lexical.js` and `source-verifier.js` in a pure JS environment; invoke `verifyJwtPolicyCandidate(texts, {meta: gitBlobMeta, apply: snapshotApply})` with a flat path-to-text map of this packet. It never evaluates the Rust candidates or calls a tool. The stored result is 272 source checks, including all twelve byte identities and strict diffs, 611 unchanged function bodies, fourteen exact retained Native JWT tests, and the exact test inventory delta. Lexical balancing is not a Rust AST or compiler check.

The old four groups contain149 unique tests/166 profile entries. The proposal contains158/180. Applying the same exact change to root's complete237/254 inventory gives246/268, with all later88 full rows and fourteen groups retained, including source evidence. Every family stays600seconds. The runner adaptation is a separate unbound SOURCE successor; this data alone authorizes no build.

## Evidence limits

`PRIMARY-DOMAIN.public.json` records the official code path, weak-boolean HTTP domain and separately inspected official23 summary. The official live cases only wrote roles with role_type/user_claim/bound_audiences. They observed stored token_policies=[], but did not test explicit empty input, root issuance, or role no-default issuance.

Native JWT batch remains unsupported501. The new batch regressions use real legacy Service issuance; they do not change that Native boundary. No formatted/compiled/live parity or full-replacement claim is made. The old missing-create negative is unchanged and is not used as evidence of policy-subset rejection.
