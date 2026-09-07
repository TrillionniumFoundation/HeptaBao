# HeptaBao External Completion Admission Protocol V1

## Purpose

This protocol turns the factual control and external blockers into strict machine-admission inputs without pretending that repository automation can perform the external work.

## Envelope

Every candidate completion object uses `heptabao.external-completion-evidence.v1` and binds:

- repository ID and full name;
- exact source commit/tree and prospective merge commit/tree;
- plan and normative-manifest digests;
- explicit scope;
- stable actor identities, roles, organizations, independence and conflicts;
- required control-separation roots;
- complete case inventory with PASS/FAIL/BLOCKED/UNKNOWN/UNEXECUTED status;
- raw or sanitized artifact digests and custody references;
- findings and dispositions;
- current, unrevoked signatures;
- an immutable `authority_effect: NONE` boundary.

## Fail-closed admission

Closure admission rejects a document when any required case is not PASS, any exact identity or digest drifts, a required role is missing, independent roles share identity, separation evidence is absent, a Critical/High/Unclassified finding remains open, a signature is stale or revoked, an artifact lacks custody, or any authority flag is raised.

Templates under `qualifications/external/templates/` are intentionally `UNEXECUTED`; they can be schema-shaped planning aids but can never pass `--require-closure`.

## Blocker-specific roles

- `HB-BLK-CTRL-001`: repository administrator plus independent control reviewer.
- `HB-BLK-EXT-001`: program, security and storage reviewers as distinct accountable identities.
- `HB-BLK-EXT-002`: accountable legal signer plus independent program reviewer.
- `HB-BLK-EXT-003`: security operations, backup incident commander and independent observer.
- `HB-BLK-EXT-004`: root-key custodian, cryptography reviewer and independent observer.
- `HB-BLK-EXT-005`: Oracle operator, sanitization operator, transfer custodian and compatibility reviewer.
- `HB-BLK-EXT-006`: independently controlled storage-lab operator and storage reviewer.
- `HB-BLK-EXT-007`: independent reproduction operator and separate reproduction reviewer.

## Invocation

```text
python scripts/validate_external_completion_evidence_v1.py candidate.json
python scripts/validate_external_completion_evidence_v1.py   --require-closure   --expected-commit <40-hex>   --expected-tree <40-hex>   --expected-merge-commit <40-hex>   --expected-merge-tree <40-hex>   candidate.json
```

The first command validates planning shape. Only the second performs closure admission, and only against caller-supplied immutable source identities.
