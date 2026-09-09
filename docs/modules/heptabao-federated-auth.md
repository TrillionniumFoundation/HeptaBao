# heptabao-federated-auth

Package: `heptabao-federated-auth`

Source: `crates/heptabao-federated-auth`

## Purpose and boundaries

Verifies bounded signed external identity assertions and channel-bound MFA proofs, recording replay state durably before releasing a principal. Provider discovery, LDAP binds and Kubernetes TokenReview transports remain adapters outside this package.

## Public API and ownership

`JwtVerifier`, `TrustPolicy`, `VerificationKey`, `PersistentReplayLedger`, `MfaProof` and `MfaVerifier` form the owned API.

## State and data model

Trust policy binds issuer, audiences, namespace, clock skew and lifetime. Replay records bind sequence, fingerprint, expiry, previous tag and HMAC.

## Invariants and authorization

Only configured algorithms and key IDs are accepted. Duplicate JSON members, wrong issuer/audience/namespace, invalid time windows and replay are denied.

## Failure, retry and reconciliation

A replay-ledger write failure is outcome-unknown and authentication is not released. Torn tails are repaired only after the authenticated prefix validates.

## Concurrency model

A create-new owner-private writer lock serializes replay admission. Verification itself is immutable and may be shared.

## Security considerations

Verification keys and MFA/replay secrets are redacted from Debug. MFA is bound to an explicit channel digest. Replay secrets are overwritten on drop.

## Persistence and compatibility

The `HBRL1` ledger is versioned and HMAC chained. It is not an OpenBao storage-format compatibility claim.

## Observability

Typed errors distinguish malformed input, duplicate JSON, algorithm/key denial, signature failure, claim/time denial, replay, tampering and outcome uncertainty.

## Operations

Operators pin issuer, audience, namespace, algorithms and keys; rotate ledger keys through an explicit migration; and resolve stale locks through audited recovery.

## Tests and evidence

Tests cover Ed25519 verification, claim constraints, duplicate-key rejection, persistent replay, MFA channel binding and ledger tampering.

## Evolution and open boundaries

Production OIDC discovery/JWKS rotation, Kubernetes, LDAP, TLS certificate and cloud-IAM adapters; WebAuthn; server routing; and independent provider qualification remain separate gates.

The verifier uses a strict JOSE header allowlist, rejects trailing JSON, and binds durable replay identity to issuer, subject, namespace and `jti` rather than signature bytes.
