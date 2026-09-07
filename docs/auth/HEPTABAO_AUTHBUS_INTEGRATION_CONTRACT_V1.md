# HeptaBao Authbus Integration Contract V1

## Trust boundary

Authbus establishes an external subject. HeptaBao remains the only writer and evaluator for policy, internal identity linkage, token, lease, namespace, audit, seal and authorization state.

## Assertion fields

A V1 assertion contains version, issuer, audience, subject, key ID, issue/expiry Unix seconds, request digest, 128-bit nonce and signature. Identity strings are bounded ASCII without controls, whitespace or backslash. Signature and assertion sizes are bounded.

This Rust crate currently models the verified assertion object and provider traits. It does not yet define a production wire codec, algorithm negotiation field, trust-root distribution format or release key.

Assertion and verified-identity `Debug` output redacts the subject and cryptographic fields. Replay-cache `Debug` does not expose issuer/nonce entries. Assertion and verified-identity objects do not provide implicit `Clone`; deliberate downstream identity copies remain explicit at the verification boundary. These are diagnostic/copy-surface controls, not a claim that the underlying public assertion object is secret.

## Request identity and binding

The signed request digest covers a length-prefixed canonical encoding of:

1. domain separator;
2. HeptaBao request ID;
3. method;
4. canonical request target;
5. exact Host value;
6. body bytes.

This prevents method/path/body/Host confusion and assertion reuse across requests.

A production Authbus-capable client must create an unpredictable request ID before assertion issuance, present that same ID in `X-HeptaBao-Request-Id`, and send the exact request bytes represented by the canonical binding. A server-generated post-receive P0 attempt ID cannot be retroactively signed by Authbus. The complete acquisition, retry and HA forwarding sequence is normative in `HEPTABAO_AUTHBUS_REQUEST_ID_LIFECYCLE_V1.md`.

`RequestBinding` safe `Debug` reports only the request ID, method and field byte counts; it does not render the target, Host or body. The target parser verifies that the supplied text already equals its canonical form without constructing another target string. The temporary canonical request byte vector is overwritten immediately after the digest provider returns, before digest errors are propagated. The temporary unsigned assertion payload, which contains the subject and binding digest, is likewise overwritten immediately after the signature verifier returns and before verifier errors are propagated. Providers must not retain either borrowed preimage after returning.

## Time model

The wire format uses Unix seconds because process-local monotonic instants have no cross-process meaning. Maximum assertion TTL is 30 seconds and future issue time skew is bounded to 5 seconds. Expired, zero/negative lifetime, overlong lifetime, overflow and excessive future issue time fail closed.

HeptaBao's internal request deadline uses process-local monotonic nanoseconds and is a separate control. Neither clock representation may be substituted for the other.

## Verification ordering

```text
policy validation
→ assertion shape/version
→ issuer/audience/key allowlist
→ lifetime and current time
→ canonical target equality without duplicate target allocation
→ canonical request digest
→ overwrite canonical digest preimage
→ signature verification
→ overwrite unsigned signature payload
→ atomic replay-authority claim
→ internal authenticated identity input
```

Recording the nonce/request identity occurs only after signature and request binding verify. A replay-store failure, saturation, stale authority epoch, conflicting digest or ambiguous claim result is an authentication failure.

## Authorization effect

The only representable value is `AuthorizationEffect::None`. A verified assertion cannot directly grant a capability or token. Downstream HeptaBao identity and policy packages must independently authorize the operation.

## Provider and replay boundary

The crate defines digest, signature-verifier and replay-cache traits. Test providers are non-cryptographic and may never be used outside tests. Production algorithms, key distribution, rotation, revocation, HA replay-store consistency and signer custody require separate candidate selection and qualification.

The in-memory replay cache is bounded to at most 4096 live entries, prunes expired entries and fails closed when saturated. Custom smaller capacities are permitted only inside the same bound. It is process-local test/development machinery: restart loses the cache, and no production or HA claim follows from it.

A production replay authority must atomically bind issuer, nonce, request ID, canonical request digest and authority epoch across all accepting/forwarding nodes. It must retain live entries through assertion expiry plus skew, reject rather than evict on saturation, recover without resurrecting consumed assertions and expose evidence for failover and partition tests.

## Memory and provider constraints

Best-effort overwrite of owned target/query strings and local digest/signature preimages does not prove that a digest/signature provider, compiler, allocator, process dump, swap device or kernel buffer retained no copy. Production providers must document ownership, copying, hardware boundaries, cancellation and memory-clearing behavior and must pass independent implementation and side-channel review.

## Required qualification cases

- request ID, method, target, body and Host mismatch;
- canonical-target comparison and cross-language byte equivalence without hidden normalization;
- issuer, audience and key confusion;
- expiry, future skew and clock rollback;
- nonce/request-ID replay and concurrent duplicate races;
- replay-store outage, saturation, failover, restart and epoch fencing;
- signature malleability and malformed length fields;
- HA forwarding and exact canonical-byte preservation;
- retry after rejected, committed and unknown outcomes;
- parser fuzzing and cross-language canonical-byte conformance;
- diagnostic redaction, no-implicit-clone and canonical/signature-preimage lifetime tests;
- red-team review proving no authorization authority crosses the adapter.

`qualification=false`, `compatibility_claim=false`, `authorization_effect=NONE`, `authority_effect=NONE`.
