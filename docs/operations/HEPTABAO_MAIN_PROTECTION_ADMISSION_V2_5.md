# HeptaBao V2.5 `main` protection admission

## Purpose

This runbook defines the repository-control portion of
`HB-BLK-CTRL-001`. It does not claim that the live GitHub setting is currently
active. It defines how an independently captured branch/protection API snapshot
is validated and how hostile enforcement cases are attached to the signed
external-evidence package.

The executable validator is
`scripts/validate_github_main_protection_v2_5.py`; hostile regressions are in
`tests/repository/test_github_main_protection_v2_5.py`.

## Required live policy

The `main` branch must satisfy all of the following at the same observation:

- GitHub reports `protected=true` for `main`;
- required status checks are strict and contain the exact approved context set;
- administrators are subject to the protection policy;
- at least two approving reviews are required;
- stale approvals are dismissed;
- Code Owner review is required;
- the last pusher cannot supply the required post-push approval;
- no user, team or app has a pull-request or review-dismissal bypass allowance;
- review conversations must be resolved;
- linear history is required;
- force pushes are disabled;
- branch deletion is disabled;
- the branch is not permanently locked.

The approved required-context set must be captured separately by repository
control governance. The validator never invents or infers a context from a
historical successful run.

## Snapshot capture

Capture both endpoints under an independently controlled GitHub credential:

```text
GET /repos/TrillionniumFoundation/HeptaBao/branches/main
GET /repos/TrillionniumFoundation/HeptaBao/branches/main/protection
```

Preserve raw response bytes, request time, GitHub request identifiers and
SHA-256 digests. Put the responses under the artifact root declared by the
`HB-BLK-CTRL-001` evidence package.

Validate the captured responses:

```bash
python scripts/validate_github_main_protection_v2_5.py \
  --branch-snapshot evidence/main-branch.json \
  --protection-snapshot evidence/main-protection.json \
  --expected-repository-url \
    https://api.github.com/repos/TrillionniumFoundation/HeptaBao \
  --required-status-context heptabao-required-exact-head \
  --required-status-context heptabao-required-prospective-main
```

The concrete context names above are examples only until the repository control
board approves and records the actual stable names. An empty set, a generic
`build`/`test` guess or a predecessor context is not acceptable.

## Hostile enforcement cases

Static configuration is necessary but not sufficient. The external evidence
package must also contain independent, bounded attempts proving:

1. a non-admin direct push to `main` is denied;
2. an administrator direct push without a pull request is denied;
3. a pull request with a missing required check cannot merge;
4. a pull request with fewer than the required approvals cannot merge;
5. the last pusher cannot self-satisfy the post-push approval;
6. an unresolved review conversation prevents merge;
7. a force push is denied;
8. branch deletion is denied.

Use synthetic branches and non-sensitive commits. Do not weaken or remove
protection to run the test. Record API status, response digest and resulting ref
state for each attempt.

## Evidence admission

The validated snapshot and hostile results are then admitted through
`scripts/admit_external_evidence_v2_5.py` under gate
`HB-BLK-CTRL-001`. Success remains
`ADMISSIBLE_EVIDENCE_NOT_AUTHORITY`; a separately controlled governance decision
must close the gate.

## Failure semantics

Any missing field, stale snapshot, mismatched repository URL, non-strict check,
missing context, administrator exemption, insufficient review count, bypass
actor, enabled force push/deletion, unresolved-conversation exemption or
nonlinear history causes rejection. A repository file asserting that protection
is enabled is not evidence of live GitHub enforcement.
