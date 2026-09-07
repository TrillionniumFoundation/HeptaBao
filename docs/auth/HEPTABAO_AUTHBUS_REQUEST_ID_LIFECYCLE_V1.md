# HeptaBao Authbus Request-ID Lifecycle V1

## 1. Scope

This contract closes the request-identity ordering ambiguity between an Authbus assertion and the HeptaBao ingress request. It defines identity ownership and retry behavior; it does not select a production wire codec, signing algorithm, trust root or HA replay store.

## 2. Identity modes

### 2.1 Development-generated mode

When a P0 request does not carry `X-HeptaBao-Request-Id`, the ingress allocates a request-attempt ID before reading or parsing the request. The identifier combines a process-start discriminator with a monotonically increasing process-local sequence. Its purpose is audit correlation for the disposable P0 profile.

This mode cannot be used as an Authbus signed identity because the client and Authbus do not know the identifier before request transmission.

### 2.2 Client-proposed Authbus mode

An Authbus-capable client generates at least 128 bits of unpredictable request identity before asking Authbus to issue an assertion. The same canonical ASCII value is carried in `X-HeptaBao-Request-Id` and in the assertion request binding.

The ingress performs only bounded syntax validation before assertion verification. A production implementation must not permanently poison the replay store with an unauthenticated identifier. After issuer, audience, key, lifetime, request digest and signature verification, one atomic operation claims the tuple:

```text
(issuer, assertion nonce, request ID, canonical request digest, authority epoch)
```

A duplicate, conflicting digest, expired epoch, unavailable replay store or ambiguous claim outcome fails authentication.

The P0 registry is deliberately weaker: it is an in-process, bounded, single-use duplicate guard used to exercise request-ID behavior. It is not the Authbus replay authority and is lost on restart.

## 3. Canonical syntax

The request ID is 8–128 ASCII bytes containing only:

```text
ALPHA / DIGIT / "-" / "_"
```

Header-name comparison is case-insensitive, but the request-ID value is byte-exact and case-sensitive. Duplicate request-ID headers are rejected by the strict HTTP parser before Authbus evaluation.

## 4. Message sequence

```text
client creates unpredictable request ID
→ client canonicalizes method/target/Host/body
→ client asks Authbus to authenticate and sign that binding
→ client sends request-ID header plus assertion and the exact bound request
→ HeptaBao parses and canonicalizes the request
→ HeptaBao verifies assertion shape, issuer, audience, key, time, digest and signature
→ HeptaBao atomically claims nonce/request-ID/digest/epoch in the replay authority
→ verified subject becomes authentication input only
→ HeptaBao policy independently authorizes or denies
```

Authbus never grants a HeptaBao capability, token, lease, namespace, seal operation or audit exemption.

## 5. Retry and outcome rules

- A request rejected before mutation may be retried only with a new request ID and a new assertion.
- A timeout or connection loss after dispatch is an unknown outcome; Blind replay of the same ID is rejected.
- The client must query a future outcome/reconciliation endpoint using the recovery reference or submit a new idempotency operation defined by that endpoint.
- A committed response whose delivery fails retains the original request ID in audit evidence.
- Retrying with the same request ID but a different method, target, Host or body is a binding conflict and fails closed.

## 6. HA requirements

Production Authbus integration requires:

- a quorum or single-writer replay authority shared by all accepting nodes;
- epoch fencing across leadership and membership changes;
- bounded retention at least through assertion expiry plus accepted clock skew;
- saturation behavior that denies authentication rather than evicting live claims;
- crash recovery that cannot resurrect a consumed assertion;
- forwarding that preserves the exact request ID and canonical request bytes;
- signed key-rotation and revocation state bound to the same authority epoch.

## 7. Required evidence

Qualification requires cross-language golden vectors, concurrent duplicate races, restart and failover tests, replay-store outage and saturation tests, retry/outcome tests, key-rotation tests and independent red-team review. P0 execution does not satisfy these production requirements.

`qualification=false`, `compatibility_claim=false`, `authorization_effect=NONE`, `authority_effect=NONE`.
