# HeptaBao V2.5 external evidence admission

## Status and authority boundary

This document defines a machine-checkable envelope for evidence produced outside
the implementation control root. It does not grant qualification, compatibility,
migration, release or production authority. A repository administrator cannot
close an independent gate by changing a state field, approving their own work or
uploading an artifact under another role name.

The structural validation core is
`scripts/validate_external_evidence_v2_5.py`; the authoritative repository-side
wrapper is `scripts/admit_external_evidence_v2_5.py`. The wrapper additionally
uses `scripts/heptabao_external_evidence_io_v2_5.py` to rehash bounded artifact
bytes and `scripts/heptabao_ed25519_v2_5.py` for strict Ed25519 verification.
The closed schemas are
`schemas/heptabao-external-evidence-v2.5.schema.json` and
`schemas/heptabao-external-trust-store-v2.5.schema.json`. Hostile regressions
are in `tests/repository/test_external_evidence_v2_5.py`,
`tests/repository/test_external_evidence_io_v2_5.py`, and
`tests/repository/test_external_evidence_role_denominator_v2_5.py`.

## Exact-source binding

Every evidence package binds all of the following:

- repository identity;
- exact lowercase 40-character commit object ID;
- exact lowercase 40-character tree object ID;
- evidence profile;
- bounded validity interval;
- canonical unsigned-payload SHA-256;
- artifact path, byte count, media type and SHA-256.

A result produced for a predecessor, prospective merge, rebuilt tree or mutable
branch name is rejected for the requested exact head.

## Separation of duties

The package declares four distinct roots:

1. implementation control;
2. evidence control;
3. runner control;
4. signing control.

The roots must be pairwise distinct. The issuer and every signer must be absent
from the declared source-author set. The issuer cannot countersign its own
package. Signer identities and signing keys must be unique.

The structural core checks the declared separation and canonical signature
bindings. The authoritative wrapper additionally requires an externally supplied
trust store whose exact bytes are bound by an out-of-band SHA-256 pin. Every
signer actor, role, key identifier, validity interval and revocation state must
match that trust store, and every signature must pass strict Ed25519 verification.
The repository does not generate, enroll or custody those external keys.

## Closed denominators

The validator admits only a complete, exact case set for the requested gate.
Missing cases, extra repository-invented cases, `FAIL`, `UNKNOWN`, duplicate case
IDs and references to unbound artifacts are rejected. Declared artifact digests
must exactly equal the set referenced by the closed case denominator.

The authoritative path also enforces an exact signer-role count for every gate.
A duplicate eligible role cannot replace a missing required role. The independent
reproduction gate requires two distinct independent-reproducer actors and keys.

### `HB-BLK-CTRL-001` — repository controls

- main ruleset enforced;
- required checks enforced;
- non-admin bypass denied;
- force push denied;
- branch deletion denied.

Required signing roles: repository administrator and control auditor.

### `HB-BLK-EXT-001` — independent review

- program review;
- product-security review;
- storage/distributed-systems review;
- reviewer independence;
- current-head binding.

Required signing roles: program reviewer, security reviewer and storage reviewer.

### `HB-BLK-EXT-002` — legal disposition

- license disposition;
- trademark disposition;
- patent disposition;
- export-control disposition;
- clean-room disposition.

Required signing roles: legal counsel and license counsel.

### `HB-BLK-EXT-003` — incident operations

- private disclosure channel;
- 24x7 roster;
- incident drill;
- credential-revocation drill;
- forensic-retention drill.

Required signing roles: incident commander and security operations.

### `HB-BLK-EXT-004` — production signing and custody

- isolated release signer;
- KMS/HSM custody;
- key-rotation ceremony;
- emergency revocation;
- transparency checkpoint.

Required signing roles: release custodian and HSM custodian.

### `HB-BLK-EXT-005` — OpenBao oracle

- restricted Oracle capture;
- deterministic sanitization;
- role-separated transfer;
- Oracle artifact rehash;
- candidate artifact rehash;
- complete-surface differential result.

Required signing roles: Oracle custodian and compatibility reviewer.

### `HB-BLK-EXT-006` — destructive platform qualification

- power-cut campaign;
- torn-write campaign;
- fsync-loss campaign;
- disk-stall campaign;
- filesystem-corruption campaign;
- multi-platform destructive campaign.

Required signing roles: platform qualifier and storage qualifier.

### `HB-BLK-EXT-007` — independent reproduction

- independent source acquisition;
- independent toolchain;
- independent runner;
- independent cache root;
- independent signing root;
- exact output reproduction.

Required signing roles: two distinct independent reproducers.

## Invocation

The structural command validates the envelope without claiming cryptographic
admission:

```bash
python scripts/validate_external_evidence_v2_5.py \
  --evidence evidence/HB-BLK-EXT-005.json \
  --expected-repository TrillionniumFoundation/HeptaBao \
  --expected-commit "$EXACT_COMMIT" \
  --expected-tree "$EXACT_TREE" \
  --expected-gate HB-BLK-EXT-005
```

The authoritative repository-side wrapper additionally requires actual artifact
bytes, a trust store, and the independently delivered digest of that trust store:

```bash
python scripts/admit_external_evidence_v2_5.py \
  --evidence evidence/HB-BLK-EXT-005.json \
  --trust-store /independent/read-only/trust-store.json \
  --expected-trust-store-sha256 "$PINNED_TRUST_STORE_SHA256" \
  --artifact-root /independent/read-only/artifacts \
  --expected-repository TrillionniumFoundation/HeptaBao \
  --expected-commit "$EXACT_COMMIT" \
  --expected-tree "$EXACT_TREE" \
  --expected-gate HB-BLK-EXT-005
```

Successful authoritative validation emits
`ADMISSIBLE_EVIDENCE_NOT_AUTHORITY` and `authority_effect=NONE`. Validator
success alone never changes a blocker or grants release authority.

## Rejection semantics

Validation is fail-closed. It rejects:

- unknown fields, schemas or gates;
- source, tree, profile or gate mismatches;
- self-issued or self-signed evidence;
- reused actor IDs or public-key IDs;
- identical implementation/evidence/runner/signing roots;
- absolute, parent-traversing or backslash artifact paths;
- zero/oversized artifacts and invalid or changed bytes;
- declared artifacts not referenced by the closed cases;
- incomplete or expanded case sets;
- failed or unknown cases;
- stale, future or excessively long evidence validity periods;
- missing, duplicate, substituted or ineligible signer roles;
- untrusted, revoked, expired or identity-mismatched signing keys;
- noncanonical key/signature encodings and invalid Ed25519 signatures;
- signatures over a payload other than the canonical unsigned envelope;
- a trust store whose bytes do not match the out-of-band digest;
- any self-asserted qualification or authority flag.

## Remaining external work

This mechanism closes the repository-side parsing, byte verification,
cryptographic verification and fail-closed admission contract. It does not
produce evidence or keys. Legal counsel, independent reviewers, Oracle
custodians, platform qualification operators, production custodians and
independent reproducers must still perform and sign their own work on the
current exact source.
