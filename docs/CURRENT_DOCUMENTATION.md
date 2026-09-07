# HeptaBao Current Documentation

This page is the single current-entry portal. A newer row supersedes an older
row only for the named subject; historical documents remain evidence and are
not silently rewritten.

## Current normative set

| Subject | Current document |
|---|---|
| active plan | `docs/plan/HEPTABAO_PLAN_V1_4_6_AUTHORITATIVE_RECOVERY_CLOSURE.md` |
| current status | `planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml` |
| blocker register | `planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml` |
| normative manifest | `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_6.yaml` |
| authoritative recovery contract | `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md` |
| inherited security invariant contract | `docs/security/HEPTABAO_SECURITY_INVARIANT_CLOSURE_V1.md` |
| module documentation standard | `docs/modules/MODULE_DOCUMENTATION_STANDARD_V1.md` |
| module index | `docs/modules/README.md` |
| exact module coverage | `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml` |
| filesystem contract | `docs/storage/HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md` |
| current exact-head gate | `.github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml` |
| inherited V1.4.5 regression gate | `.github/workflows/plan-v1.4.5-security-invariant-closure.yml` |

## Supersession chain

```text
V1.4.2 anchored recovery foundation
  → V1.4.3 descriptor anchoring/writer fencing
  → V1.4.4 complete current-crate documentation
  → V1.4.5 security invariant closure
  → V1.4.6 authoritative recovery closure
```

V1.4.5 changes security-kernel implementation and its documentation. It does
not supersede the 19/19 crate-coverage measurement from V1.4.4; that coverage is
inherited and revalidated.

## Reading rule

Target-architecture and roadmap documents describe intended future modules.
Only Cargo workspace members and the current as-built module index describe
implemented crates. Status words such as source implemented or test pass never
imply compatibility, qualification, provider selection or production authority.

Exact source identity is the immutable pull-request head checked by the current
workflow. Exact merge identity is GitHub's two-parent prospective merge checked
by the separate merge matrix entry. A historical source preflight is supporting
evidence and never replaces those final identities.

## V1.4.6 reading note

V1.4.6 supersedes V1.4.5 for interrupted commit recovery, rollback-anchor
publication fencing, atomic recovery-target admission, file-store permissions,
phase-aware outer-fence failure classification and current CI provenance.

The public fence contract distinguishes failures before the publication closure
is invoked from uncertainty after invocation. `CheckpointNotCurrent` and
`ProviderBeforeEntry` mean the closure was not entered.
`OutcomeUnknownAfterEntry` means target publication and fence completion may
have occurred; the recovery API exposes `AnchorFenceOutcomeUnknown` and requires
both anchor and target reconciliation before retry.

V1.4.5 remains the historical security-invariant closure baseline, V1.4.4
remains the 19/19 module-coverage measurement, and the current V1.4.6 validator
must re-run both inherited gates on the exact head and prospective merge.

## Open authority boundary

Repository source and CI may remediate repository-controlled defects, but they
cannot create independent reviewer identities, legal disposition, 24x7 incident
operation, isolated signing custody, restricted Oracle transfer, destructive
storage-laboratory evidence or independently operated reproduction. The control
and external blockers remain open until their real completion objects verify.
