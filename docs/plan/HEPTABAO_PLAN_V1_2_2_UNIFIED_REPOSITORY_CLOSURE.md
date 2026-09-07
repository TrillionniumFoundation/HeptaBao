# HeptaBao Plan V1.2.2 Unified Repository Closure

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`
**Revision:** `1.2.2`
**Status:** `NORMATIVE_REMEDIATION_ADDENDUM / LOCAL_PATCH_CANDIDATE / NOT_QUALIFIED / AUTHORITY_EFFECT_NONE`

## 1. Exact composition inputs

This package reconciles two sibling development lines without representing either as merged:

- PR #40 exact matrix/evidence head: `cedb6c95a5323f7004551087d75e2f57a1ec484a`, tree `e0032b54bad2048802cd61f6bbc7d6d1f9ce4003`;
- PR #41 lifecycle transition head: `c2a7967df4a3f1e66d021423fbb561c2491d2843`, tree `ca0f61cf147a7db59f52ed160b6eb3c81c21a0fc`.

At initial V1.2.2 package construction, PR #41 had only moved the one-shot materializer between runner pools and the materializer was queued. It later executed successfully as run `33276128606` / job `99163068708` and published lifecycle head `cd56d815f03c0a62ecb3572fb0ba635e9c5f6b93`. This closes only the lifecycle materialization step: the bot-triggered follow-up checks are `action_required`, and PR #41 still does not contain PR #40's final evidence hardening or the V1.2.2/V1.3 unified source.

PR #40 hardens exact source binding, result taxonomy, timeout process-group handling and a complete 24-entry matrix. PR #41 carries a deterministic transition script for an explicit durable lifecycle. The V1.2.2 package materializes the non-overlapping lifecycle changes directly into the PR #40 reconciliation candidate and removes any dependency on a write-capable materializer for the final source.

## 2. Repository-controlled implementation closure

The resulting source provides:

- `create-new`, `reopen-existing`, and `adopt-legacy` as distinct caller-selected operations;
- versioned, domain-bound initialization markers;
- fail-closed handling for missing initialized generations and deleted initialized directories;
- validation-before-retirement of one stale `.previous` generation;
- no silent rollback from a corrupt current generation;
- ambiguous multiple previous generations rejected;
- real-directory, regular-file and symlink guards;
- atomic state/snapshot bundle generation;
- guarded hostile-snapshot semantics and strict-lint repairs;
- read-only exact-SHA CI with source, tree, manifest, lock, command and output digest binding.

Cluster bootstrap routes to `CreateNew`; logical restart routes to `ReopenExisting`. Recovery and corruption copies are opened through `open_existing`, never through an implicit initializer.

## 3. Technical evidence still required

Repository-controlled remediation is implemented locally, but closure still requires one remote exact head to produce all of the following:

1. every V1.1/V1.2/V1.2.1/V1.2.2 validator and Python suite passes;
2. root workspace Rust 1.98 fmt/test/Clippy passes;
3. OpenRaft Rust 1.88 and 1.98 fmt/test/Clippy passes on the committed lock graph;
4. all 24 exact-head application entries pass with no failed, blocked, unknown, unexecuted, duplicate, missing or unexpected entry;
5. all raw artifacts and source/manifest/lock/command digests re-verify;
6. independent storage/distributed-systems review and a current signed closure receipt exist.

Until then, technical state is `IMPLEMENTED_LOCAL / EXACT_HEAD_UNEXECUTED`, not `CLOSED`.

## 4. External action boundary

Repository code cannot fabricate enforceable rulesets, independent reviewer identities, legal and clean-room dispositions, private disclosure/on-call operation, isolated signing and transparency, restricted Oracle transfers, kernel/VM power-cut laboratories or independently operated reproduction. These remain `EXTERNAL_ACTION_REQUIRED`.

## 5. Authority boundary

```text
qualification=false
compatibility_claim=false
selected_candidates=[]
selection_effect=NONE
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```
