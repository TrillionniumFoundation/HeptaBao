# HeptaBao Plan V1.4.5 — Security Invariant Closure

## 1. Baseline and authority boundary

This tranche extends exact source commit
`489a104450ff48c49e7fb61e167e566ea5e0e6c7`, tree
`a567e8feb90077de5e3a8e540f07a89192264338`. It inherits V1.4.4 module
coverage and every earlier non-authority boundary. Source, tests and CI evidence
do not select providers, qualify a platform, authorize migration or grant
production/release authority.

## 2. Objective

Close the repository-controlled security gaps found by independent review and
full documentation audit without expanding product scope:

1. make journal append ambiguity a provider-neutral fail-stop state;
2. prevent barrier/storage and state/ledger capability decomposition;
3. require exact authoritative storage evidence for durable-intent recovery;
4. make recovery publication depend on a live external-anchor reread and an
   unforgeable single-use capability;
5. classify a wrong post-publication receipt as outcome unknown;
6. require exact rollback-anchor CAS receipts;
7. reject symlinks in every guarded filesystem ancestor;
8. retire historical exact-ratifier CI outside its own version lane; and
9. mechanically bind these claims to source, tests and module documentation.

## 3. Append ambiguity and fail-stop ledgers

`DurableJournal` gains an explicit append-failure disposition. The conservative
default is `OutcomeUnknown`. A ledger receiving that disposition enters
`ReplayRequired`, rejects every later write before provider access, and can
recover only by consuming itself and reopening through authenticated replay.
This rule applies to both operation and key-lifecycle ledgers.

A provider may return `DefinitelyNotAppended` only when it has affirmative,
provider-specific proof that neither record bytes nor authoritative tail were
published. Error names, I/O categories and optimistic in-memory state are not
such proof.

## 4. Durable mutation capability topology

The durable engine no longer exposes a mutable store or raw provider parts.
The journaled composition no longer exposes independently writable state and
ledger objects. A durable mutation at `IntentCommitted` cannot use generic
`Reconciled`; it must reread authoritative storage and match the exact committed
generation and digest before recording `StateCommitted`.

## 5. Rollback anchor and recovery publication

Archive authentication proves only archive integrity. It does not authorize
publication. Restore admission uses this sequence:

```text
verify archive authentication
→ reread and authenticate exact current rollback anchor
→ verify target reports empty
→ reread and authenticate the same current anchor again
→ mint private AuthorizedRecoveryImage(anchor_revision)
→ stage and publish once
→ compare the complete receipt
```

`VerifiedRecoveryCheckpoint` is non-cloneable and cannot be downgraded. The
coordinator does not expose its raw anchor or signing provider. The anchor CAS
receipt must equal the exact requested checkpoint, including observation and
digest. Only `AuthorizedRecoveryImage`, which has no public constructor, can
release sealed state and records to a target.

A target-reported receipt mismatch after `publish` is a publication-unknown
terminal condition. It requires authoritative target readback/reconciliation;
it is never a safe retry.

## 6. Filesystem ancestor provenance

Linux acquisition starts from an opened `/` descriptor and walks every normal
path component through the preceding `/proc/self/fd/<fd>` capability. Each
component uses `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and pre/open/post
identity equality. Intermediate symlinks, parent traversal and non-directory
components fail closed.

This does not claim protection from a compromised kernel, privileged mount
namespace manipulation, unqualified network filesystems or the stronger atomic
semantics of `openat2(RESOLVE_*)`.

## 7. Versioned CI and documentation semantics

The V1.3.1 exact owner-ratification workflow is scoped to its historical base
branch so later implementation commits cannot be rejected for not having a
V1.3.1 commit subject. V1.4.5 has a permanent read-only exact-head/PR workflow.
The validator rejects reintroduced raw capabilities, missing fail-stop states,
missing hostile tests, unscoped historical gates, temporary source generators,
missing documentation addenda and authority drift.

## 8. Required evidence

The immutable candidate must pass:

```text
python scripts/validate_plan_v1_4_5.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_5.py' -v
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/plan -p 'test_module_documentation_v1_4_4.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

Independent reviewers must bind their review to the exact source SHA and the
current two-parent merge candidate. Administrator privilege is not a substitute
for independent review.

## 9. Explicitly carried work

This tranche does not implement the production composition root, policy,
identity, token, lease, namespace, plugin host, secrets engines, Raft/HA, CLI,
Agent, Proxy, production KMS/HSM custody, remote rollback provider, backup
ceremony, storage-controller power-cut qualification, online migration or full
OpenBao compatibility. Those are roadmap/product or external-control items,
not silently closed by this security-kernel change.

## 10. Completion rule

HB-BLK-REPO-041 through HB-BLK-REPO-048 close only when ordinary source (with no
bootstrap/source-writer residue) passes the permanent read-only exact-head and
merge-candidate gates and receives independent review. All external/control
blockers and every authority claim remain fail-closed until their real completion
objects exist.
