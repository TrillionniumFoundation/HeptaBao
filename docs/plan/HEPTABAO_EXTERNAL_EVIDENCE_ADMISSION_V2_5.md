# HeptaBao V2.5 external evidence admission

## Status and authority boundary

This document defines a machine-checkable envelope for evidence produced outside
the implementation control root. It does not grant qualification, compatibility,
migration, release or production authority. A repository administrator cannot
close an independent gate by changing a state field, approving their own work or
uploading an artifact under another role name.

The executable validator is
`scripts/validate_external_evidence_v2_5.py`; its structural schema is
`schemas/heptabao-external-evidence-v2.5.schema.json`; hostile regressions are in
`tests/repository/test_external_evidence_v2_5.py`.

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

This is a structural check, not proof that an asserted actor or key is genuine.
Key enrollment, organizational identity and signature cryptographic verification
remain responsibilities of the independently controlled admission service.

## Closed denominators

The validator admits only a complete, exact case set for the requested gate.
Missing cases, extra repository-invented cases, `FAIL`, `UNKNOWN`, duplicate case
IDs and references to unbound artifacts are rejected.

### `HB-BLK-CTRL-001` — repository controls

- main ruleset enforced;
- required checks enforced;
- non-admin bypass denied;
- force push denied;
- branch deletion denied.

### `HB-BLK-EXT-001` — independent review

- program review;
- product-security review;
- storage/distributed-systems review;
- reviewer independence;
- current-head binding.

The signature set must include program, security and storage reviewer roles.

### `HB-BLK-EXT-002` — legal disposition

- license disposition;
- trademark disposition;
- patent disposition;
- export-control disposition;
- clean-room disposition.

### `HB-BLK-EXT-003` — incident operations

- private disclosure channel;
- 24x7 roster;
- incident drill;
- credential-revocation drill;
- forensic-retention drill.

### `HB-BLK-EXT-004` — production signing and custody

- isolated release signer;
- KMS/HSM custody;
- key-rotation ceremony;
- emergency revocation;
- transparency checkpoint.

### `HB-BLK-EXT-005` — OpenBao oracle

- restricted Oracle capture;
- deterministic sanitization;
- role-separated transfer;
- Oracle artifact rehash;
- candidate artifact rehash;
- complete-surface differential result.

### `HB-BLK-EXT-006` — destructive platform qualification

- power-cut campaign;
- torn-write campaign;
- fsync-loss campaign;
- disk-stall campaign;
- filesystem-corruption campaign;
- multi-platform destructive campaign.

### `HB-BLK-EXT-007` — independent reproduction

- independent source acquisition;
- independent toolchain;
- independent runner;
- independent cache root;
- independent signing root;
- exact output reproduction.

## Invocation

```bash
python scripts/validate_external_evidence_v2_5.py \
  --evidence evidence/HB-BLK-EXT-005.json \
  --expected-repository TrillionniumFoundation/HeptaBao \
  --expected-commit "$EXACT_COMMIT" \
  --expected-tree "$EXACT_TREE" \
  --expected-gate HB-BLK-EXT-005
```

Successful validation emits
`ADMISSIBLE_EVIDENCE_NOT_AUTHORITY` and `authority_effect=NONE`. The separately
controlled governance/admission process must verify the signatures against its
own enrolled trust roots and decide whether the corresponding gate can change
state.

## Rejection semantics

Validation is fail-closed. It rejects:

- unknown fields or schema IDs;
- unknown gates or ineligible roles;
- self-issued or self-signed evidence;
- reused actor IDs or public-key IDs;
- identical implementation/evidence/runner/signing roots;
- absolute, parent-traversing or backslash artifact paths;
- zero/oversized artifacts and invalid digests;
- incomplete or expanded case sets;
- failed or unknown cases;
- cases referring to unbound artifacts;
- stale, future or excessively long validity periods;
- unsupported signature algorithms or malformed signature encodings;
- signatures over a payload other than the canonical unsigned envelope;
- any self-asserted qualification or authority flag.

## Remaining external work

This mechanism closes the repository-side evidence parsing and fail-closed
admission contract. It does not produce the evidence. Legal counsel, independent
reviewers, Oracle custodians, platform qualification operators, production
custodians and independent reproducers must still perform and sign their own
work on the current exact source.
