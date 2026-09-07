# HeptaBao

HeptaBao is an independent clean-room Rust reimplementation program for an OpenBao-compatible secrets-management server.

## Current truth

- Current plan: **V1.4.6 authoritative recovery closure**.
- Exact security-kernel baseline: **V1.4.5 security invariant closure** (`936cb5599d206cea895de2ae04a1289a0b3a0326`).
- Documentation predecessor: **V1.4.4 module documentation closure** (`489a104450ff48c49e7fb61e167e566ea5e0e6c7`).
- Current implemented foundation: strict P0 protocol, Authbus contracts, durable generation store, authenticated journal, fail-stop operation/key ledgers, authoritative interrupted-commit recovery, atomic empty-target admission, rollback-anchor publication fencing, phase-aware post-entry fence uncertainty, exact receipt validation, owner-only Unix store files and Linux descriptor-rooted ancestor walking/writer fencing.
- Current Cargo workspace documentation: **19 / 19** crates have developer guides under `docs/modules/`.
- Qualification: **false**.
- Compatibility claim: **false**.
- Dependency selections: **none with production authority**.
- Production, migration, release and mixed-cluster authority: **false**.
- Supported production versions: **none**.

The repository is **not production-deployable**. Do not use it to protect real secrets and do not place real tokens, unseal shares, recovery keys, private keys or production snapshots in source, tests or CI.

## Current normative entry points

1. `docs/CURRENT_DOCUMENTATION.md`
2. `docs/plan/HEPTABAO_PLAN_V1_4_6_AUTHORITATIVE_RECOVERY_CLOSURE.md`
3. `planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml`
4. `planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml`
5. `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_6.yaml`
6. `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md`
7. `docs/security/HEPTABAO_SECURITY_INVARIANT_CLOSURE_V1.md`
8. `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`
9. `docs/modules/README.md`
10. `docs/modules/MODULE_DOCUMENTATION_STANDARD_V1.md`
11. `.github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml`
12. `.github/workflows/plan-v1.4.5-security-invariant-closure.yml`

## Architecture boundary

The current code is a set of safety-oriented kernel components and a loopback-only P0 memory server. A production composition root, policy, identity, token, lease, namespace, plugin host, secrets engines, Raft/HA, CLI, Agent, Proxy and full OpenBao compatibility remain future product work. Target-architecture documents do not imply that these modules exist.

## Recovery safety boundary

Recovery target admission is atomic through `stage_if_empty`, and target publication executes while the rollback provider holds the exact-current checkpoint fence. Fence outcomes are phase-aware:

- `CheckpointNotCurrent` and `ProviderBeforeEntry` prove the publication closure was not entered;
- `OutcomeUnknownAfterEntry` means the closure ran but clean fence completion cannot be proved;
- `AnchorFenceOutcomeUnknown` requires authoritative readback of both the external anchor and target before any retry.

A successful inner target receipt does not override outer post-entry fence uncertainty. No provider, operator or caller may relabel that state as a safe stale-checkpoint failure.

## Evidence and authority boundary

Technical source, tests, CI, qualification, compatibility and operational authority are distinct. Repository-controlled gates cannot manufacture external repository controls, independently accountable reviews, legal disposition, incident operation, isolated signing, restricted Oracle transfer, power-cut/filesystem laboratory evidence or independent reproduction. Those blockers close only through their declared real completion objects.

## Development

Read the guide for the crate you are changing under `docs/modules/`, update it in the same change, and run the current and inherited gates:

```text
python scripts/validate_plan_v1_4_6.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_6.py' -v
python scripts/validate_plan_v1_4_5.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_5.py' -v
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/plan -p 'test_module_documentation_v1_4_4.py' -v
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

The V1.4.5 security invariant closure remains an inherited regression baseline, and V1.4.4 remains the inherited **19 / 19** module-documentation coverage revision. Exact current source and prospective-merge identities are taken from the active pull request and its read-only workflows, not inferred from this README.
