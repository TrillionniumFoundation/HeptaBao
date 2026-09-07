# HeptaBao Anchored Recovery Contract V1

## Contract status

This document defines a development-only, provider-neutral recovery boundary. It is not an operating procedure, production provider selection, disaster-recovery certification, or authority receipt.

## Trust separation

Three independent facts are required:

1. the durable state/journal/key observation;
2. an externally stored checkpoint authenticated by the checkpoint authenticator;
3. a recovery archive authenticated by the archive authenticator.

The archive authenticator and checkpoint authenticator have separately bound identities. Verifying one does not imply verification of the other.

## Capture contract

Capture reads the current opaque sealed-state snapshot and the complete durable journal replay. It builds one observation from the exact domains, state generation and digest, journal tail, and active key epoch. The supplied checkpoint must contain the identical observation.

The archive stores opaque sealed state and journal payloads. It must never open secrets, infer plaintext semantics, or print state/payload bytes in `Debug` output.

## Checkpoint contract

A checkpoint is valid only when its authenticator identity matches the verifier and its digest authenticates the canonical checkpoint preimage. Revision one has no previous digest; every later revision has exactly one previous digest. The provider is responsible for externally durable compare-and-swap and rollback resistance.

`VerifiedRecoveryCheckpoint` can be created only after the coordinator authenticates the checkpoint and proves that it equals the provider's current externally stored value. A historical but authentic checkpoint cannot authorize restore. Restore APIs accept this wrapper rather than an unauthenticated checkpoint.

## Archive contract

The archive codec is versioned, closed, bounded, and deterministic. Every length and count is checked before allocation or accumulation. Record sequence starts at one, remains contiguous, and preserves the exact previous-tag chain. The final record must equal the observation tail.

The archive preimage binds both authenticator identities, checkpoint revision chain, checkpoint digest, observation, sealed state, and every journal record. Trailing data is forbidden.

## Restore contract

The target must be empty. A verified archive is staged before publication. Publication returns either:

- a receipt that exactly matches the archive;
- a definitely-not-published provider error;
- an outcome-unknown provider error requiring reconciliation.

Blind retry after outcome-unknown is forbidden.

## Explicit non-claims

The source does not provide KMS/HSM integration, remote anchor durability, backup custody, encryption algorithm selection, multi-process fencing, anti-TOCTOU filesystem handles, replicated recovery, online upgrade, legal retention policy, or production authorization.
