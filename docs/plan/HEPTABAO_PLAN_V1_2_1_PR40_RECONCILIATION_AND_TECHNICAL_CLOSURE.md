# HeptaBao Plan V1.2.1 PR40 Reconciliation and Technical Closure

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`
**Revision:** `1.2.1-pr40-r1`
**Status:** `NORMATIVE_REMEDIATION_ADDENDUM / PATCH_CANDIDATE / NOT_QUALIFIED / AUTHORITY_EFFECT_NONE`
**Exact input:** `ProfHepta/HeptaBao@cedb6c95a5323f7004551087d75e2f57a1ec484a`
**Exact input tree:** `e0032b54bad2048802cd61f6bbc7d6d1f9ce4003`

## 1. Purpose

PR #40 closes important evidence-runner defects on top of PR #38, but it does not contain the sibling PR #39 initialized-generation guard or the strict-lint/source-binding corrections first exposed on the executable PR #37 ARM lane. This addendum reconciles those non-overlapping changes onto the PR #40 exact head without changing candidate selection, qualification, compatibility or authority.

The package is deliberately small. It does not replace the V1.2/V1.2.1 plan, the exact-head matrix specification, or the external-action catalog. It closes only repository-controlled implementation gaps that can be proven by source, tests and exact-head execution.

## 2. Reconciled implementation

### 2.1 Initialized durable generation guard

Both durable domains persist a versioned, domain-bound initialization marker only after the first authoritative generation is durable. Opening a store now distinguishes:

1. a never-initialized directory;
2. a valid legacy generation requiring validation and marker adoption;
3. an initialized store whose authoritative generation is present;
4. an initialized store whose authoritative generation is missing or non-regular, which fails closed.

Interrupted replacement recovery runs before classification. Marker format, domain and authoritative filename are validated. Symlinked roots, markers and authoritative generations are rejected. Deleting `raft-log.bin` or `state-bundle.bin` after initialization can no longer silently create an empty store.

The marker cannot prove loss of the complete directory. A separately persisted rollback anchor or signed external inventory remains required for production qualification.

### 2.2 Strict lint and source binding

The OpenRaft probe now uses Rust inline format capture, the obsolete unguarded stale-snapshot helper is removed rather than lint-suppressed, and the durable fault path uses a direct async block. The active fault-lab validator binds `hostile_snapshot_guard.rs` and rejects a missing or semantically stripped guard implementation.

### 2.3 Exact-head execution

The inherited PR #40 runner remains authoritative for repository-controlled execution evidence. It self-binds to the actual checkout, executes all 24 toolchain/seed/probe entries, preserves process and application classifications, kills timed-out process groups, verifies duplicate/missing/unexpected entries and rechecks source cleanliness after execution.

This reconciliation adds source/unit checks to that same read-only ARM64 workflow. It does not add a write-capable transition workflow and never commits or pushes from CI.

## 3. Required technical closure

Repository-controlled technical closure requires all of the following on one resulting exact head:

- V1.1/V1.2/V1.2.1 and PR40 reconciliation validators pass;
- all Oracle/platform/plan Python tests pass;
- root Rust 1.98 `fmt`, `test`, and `clippy -D warnings` pass;
- OpenRaft Rust 1.88 and 1.98 `fmt`, `test`, and `clippy -D warnings` pass on the committed graph;
- initialization-marker, missing-generation, legacy-adoption, symlink and interrupted-replacement Rust tests pass;
- all 24 exact-head application entries pass with zero failed, blocked, unknown, unexecuted, duplicate, missing or unexpected entries;
- raw outputs and command/source/manifest/lock digests re-verify;
- the authority sentinel remains closed.

A technical pass leaves repository blockers at `REMEDIATION_IMPLEMENTED` until required independent review and a current signed closure receipt exist.

## 4. External gaps preserved

This repository package cannot create or self-close:

- enforceable GitHub rulesets and negative controls;
- independent accountable reviewer identities;
- legal, clean-room, outbound-license, trademark, patent or export disposition;
- private disclosure, 24×7 incident response or revocation drill evidence;
- isolated signing custody, trust roots, transparency and emergency revocation;
- restricted Oracle captures and signed sanitized transfers;
- independently operated kernel/VM power-cut and filesystem crash-consistency evidence;
- independently operated reproduction with a distinct credential root and artifact custody.

These remain `EXTERNAL_ACTION_REQUIRED` and cannot be represented as code-complete.

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
