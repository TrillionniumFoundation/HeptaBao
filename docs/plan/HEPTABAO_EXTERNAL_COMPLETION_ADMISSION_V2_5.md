# HeptaBao external completion admission V2.5

## Status

This document defines a repository-owned **verification mechanism** for external
completion evidence. It does not assert that external evidence exists and it
does not grant qualification, compatibility, migration, release or production
authority.

The executable verifier is:

```text
scripts/verify_external_completion_v2_5.py
```

The hostile and positive regressions are:

```text
tests/repository/test_verify_external_completion_v2_5.py
```

## Purpose

Several final HeptaBao gates depend on facts that cannot be manufactured by the
source author or by repository administrator access: independent review, legal
disposition, incident readiness, isolated signing custody, independently
controlled OpenBao Oracle observations, destructive platform qualification and
clean-room reproduction. V2.5 gives those facts one fail-closed admission path.

A successful invocation proves only that the supplied evidence packet:

1. is bound to one exact repository, commit, tree and compatibility profile;
2. contains the complete closed case denominator for every required gate;
3. references exactly the declared regular-file artifacts;
4. matches the observed artifact byte lengths and SHA-256 digests;
5. is signed by the complete role denominator with distinct trusted keys;
6. uses keys that were active, unrevoked and present in an independently
   supplied trust store whose digest was pinned out of band; and
7. has valid strict Ed25519 signatures over the canonical gate envelope.

It does **not** prove that a dishonest independent actor performed a competent
review. Accountability, contracts, organizational controls and the external
execution environment remain outside repository control.

## Required gates and cases

### `HB-BLK-CTRL-001` — enforced repository controls

Required cases:

- direct push by an ordinary member is denied;
- direct push by an administrator is denied;
- a merge with a missing required check is denied;
- a merge with insufficient approvals is denied;
- an unresolved conversation blocks merge;
- force push is denied; and
- deletion of `main` is denied.

Required signers: one repository administrator and one separately accountable
control auditor.

### `HB-BLK-EXT-001` — independent product review

Required cases cover program, security and storage review, plus zero unresolved
Critical and High findings. Required signers are distinct program, security and
storage reviewers.

### `HB-BLK-EXT-002` — legal disposition

Required cases cover license, trademark, patent and export disposition.
Required signers are legal counsel and license counsel.

### `HB-BLK-EXT-003` — incident operation

Required cases cover an operating private disclosure channel, verified on-call
coverage, an incident drill and a revocation drill. Required signers are the
incident commander and security operations owner.

### `HB-BLK-EXT-004` — signing and HSM custody

Required cases cover HSM key generation, separated signer custody, rotation,
emergency revocation and publication of a transparency checkpoint. Required
signers are the release custodian and HSM custodian.

### `HB-BLK-EXT-005` — OpenBao Oracle transfer

Required cases cover complete Oracle capture, complete sanitized fixtures,
side-effect coverage, CLI/client coverage and signed transfer. Required signers
are the Oracle custodian and compatibility reviewer.

### `HB-BLK-EXT-006` — destructive qualification

Required cases cover Linux amd64, Linux arm64, Windows amd64, macOS arm64,
power-cut, fsync-loss, corruption recovery, rolling upgrade and disaster
recovery. Required signers are the platform and storage qualifiers.

### `HB-BLK-EXT-007` — independent reproduction

Required cases cover two clean-room builds, artifact digest equality and test
reproduction. Two distinct independent reproducer signatures are mandatory.

## Trust-store boundary

The evidence packet is forbidden from defining its own trust root. The verifier
requires a separate trust-store file and a SHA-256 digest supplied through a
separate control path:

```console
python scripts/verify_external_completion_v2_5.py \
  --evidence /evidence/completion.json \
  --trust-store /custody/heptabao-trust-store.json \
  --artifact-root /evidence/artifacts \
  --expected-repository TrillionniumFoundation/HeptaBao \
  --expected-commit <40-lowercase-hex> \
  --expected-tree <40-lowercase-hex> \
  --expected-profile HB-OPENBAO-REPLACEMENT-V2.5 \
  --expected-trust-store-sha256 <64-lowercase-hex>
```

Trust entries bind:

```text
key_id + actor + role + Ed25519 public key + validity interval + revoked state
```

Duplicate key IDs, duplicate key material, revoked keys, stale keys, future
keys, actor/role substitution and arbitrary evidence-provided keys are rejected.

## Artifact boundary

Every case must cite at least one artifact. The complete set of cited artifacts
must equal the complete declared artifact set. This rejects both unsupported
cases and unreferenced material smuggled into an evidence packet.

Artifact paths must be bounded POSIX relative paths. Absolute paths, `..`,
dot-components, backslashes, symbolic-link parents, symbolic-link leaves,
non-regular files, size drift, digest drift and changes during streaming read
are rejected. The verifier hashes files in bounded memory.

## Signature envelope

Each signature covers a canonical JSON object containing:

```text
unsigned complete evidence packet
+ gate_id
+ key_id
+ actor
+ role
```

This prevents moving a valid signature to another gate, actor, role or key.
The strict verifier rejects non-canonical points, the identity point,
non-prime-order points and `S >= L`.

## Admission output

A passing verifier returns a machine object with:

```text
admitted=true
authority_effect=NONE_UNTIL_SEPARATE_GRANT
```

The second field is normative. Completion evidence and an authority grant are
separate objects. An admitted technical/legal/operational packet is necessary
but is not by itself permission to migrate data, release binaries or protect
real secrets.

## Failure policy

Any parse, duplicate-member, source-binding, denominator, artifact, trust,
validity, revocation or signature error returns nonzero and `admitted=false`.
There is no warning-only mode and no administrator override in the verifier.

## Required independent review

Before this verifier can protect a production admission decision, an independent
cryptographic reviewer must inspect the Ed25519 implementation and vectors, and
an independent security reviewer must inspect canonicalization, filesystem
handling, denominator completeness and trust-store custody. Repository tests are
development evidence only.

## Authority state

```text
qualification=false
compatibility_claim=false
migration_authority=false
release_authority=false
production_authority=false
authority_effect=NONE
```
