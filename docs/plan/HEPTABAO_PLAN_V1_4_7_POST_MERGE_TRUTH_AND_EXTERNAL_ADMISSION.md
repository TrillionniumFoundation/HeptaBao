# HeptaBao Plan V1.4.7 — Post-Merge Truth and External Admission

## 1. Baseline

This tranche starts from the signed GitHub merge `54d524214df443752a2ecaeff6d4a05625bf52c7`, tree `c22288f561fdd711e908ce8a70c0116601d519e5`, on `integration/v1.4.4-technical-candidate`. It does not reconstruct or supersede that merge with an unreviewed same-tree commit.

## 2. Objectives

1. canonicalize the completed V1.4.6 repository-controlled result after merge;
2. close `HB-BLK-REPO-049` through `HB-BLK-REPO-058` only in repository scope, without closing role, legal, operational, custody, laboratory or reproduction blockers;
3. replace title-only module-documentation validation with exact source, API, dependency, test and digest binding for every current crate;
4. make stale hand-written Public API tables detectable and regenerate them from candidate source;
5. provide one strict, blocker-specific external completion envelope and fail-closed admission tool;
6. ensure templates, owner assertions, same-identity reviews, stale signatures, incomplete cases and authority elevation cannot close a blocker;
7. bind all changes to distinct exact-head and prospective-merge pull-request checks.

## 3. V1.4.6 post-merge closure

The V1.4.6 head `837668cb879683bc60808584d2ebdedd42a397aa` and prospective merge `54d524214df443752a2ecaeff6d4a05625bf52c7` passed the V1.4.6, inherited V1.4.5 and V1.4.4 gates. A current GitHub review approved the exact head, and GitHub created a valid signed two-parent merge with tree `c22288f561fdd711e908ce8a70c0116601d519e5`. The post-merge receipt records those immutable facts and closes only the ten repository blockers. `HB-BLK-EXT-001` remains open because a GitHub approval does not establish the complete accountable role registry or signed role receipts.

## 4. Module source truth

The V2 renderer derives the workspace package set, Cargo manifest hashes, Rust source hashes, workspace-internal dependency declarations, public lexical declarations and discovered test functions. It rewrites the Public API section of each guide and adds a generated facts block. Check mode recomputes every fact and rejects source/documentation drift.

The parser is intentionally bounded and lexical. It does not claim Rust name resolution or semantic compatibility. That limitation is part of the normative output rather than an implicit weakness.

## 5. External completion admission

`HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007` each receive an `UNEXECUTED` template. The validator can inspect planning shape without closure, but closure mode requires exact source identities, complete PASS-only cases, distinct accountable roles, blocker-specific separation, artifact custody, no unresolved Critical/High/Unclassified finding, fresh valid signatures and unchanged authority flags.

Repository automation cannot populate real identities, legal authority, operating coverage, HSM custody, restricted raw Oracle evidence, independent power-cut control or separately controlled reproduction. Those facts remain open until external operators submit authentic evidence.

## 6. New repository blockers

- `HB-BLK-REPO-059`: V1.4.6 post-merge repository closure was not canonicalized.
- `HB-BLK-REPO-060`: module guides were structurally present but not source/API/dependency/test bound.
- `HB-BLK-REPO-061`: external completion inputs lacked one strict fail-closed admission envelope.
- `HB-BLK-REPO-062`: current documentation still selected the pre-merge V1.4.6 status.

All four are implemented in source by this candidate and remain review-required until exact-head and prospective-merge CI pass and an independent reviewer accepts the final candidate.

## 7. Required gates

```text
python scripts/render_plan_v1_4_7.py --check
python scripts/validate_plan_v1_4_7.py
python -m unittest discover -s tests/plan -p 'test_*v1_4_7.py' -v
python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v
python scripts/validate_plan_v1_4_6.py
python scripts/validate_plan_v1_4_5.py
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

## 8. Carried product work

The production composition root, policy, identity, token, lease, namespace, system and plugin domains, production KMS/HSM, remote rollback provider, qualified recovery target, non-Linux qualification, backup/restore operations, Raft HA, migration, complete OpenBao compatibility and CLI/Agent/Proxy remain product work. This tranche makes their evidence boundaries harder to overclaim; it does not label unimplemented products complete.

## 9. Completion rule

`HB-BLK-REPO-059..062` close only after final source and prospective merge pass the V1.4.7 and inherited gates and receive a current independent review. `HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007` remain open until authentic completion envelopes pass strict admission. Qualification, compatibility, provider selection and all production/migration/release authority remain false.
