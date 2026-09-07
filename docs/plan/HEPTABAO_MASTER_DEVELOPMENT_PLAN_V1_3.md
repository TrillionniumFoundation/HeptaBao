# HeptaBao Master Development Plan V1.3

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`
**Revision:** `1.3`
**Status:** `NORMATIVE_FOUNDATION_AND_P0_EXECUTION_INPUT`
**Authority effect:** `NONE`

## 1. Purpose

V1.3 turns the V1.2/V1.2.1 governance, Oracle, dependency and evidence foundation into the first executable HeptaBao server slice without weakening any qualification or authority boundary. It also reconciles two new H02 runtime defects found after V1.2.2 composition and defines the Authbus integration boundary as an authentication-only assertion protocol.

V1.3 does **not** claim OpenBao compatibility, production readiness, migration safety, dependency selection, release authority or protection of real secrets. A code merge or green CI run remains engineering evidence only.

## 2. Canonical truth

The current state is resolved from one exact repository commit and tree plus the following normative inputs:

1. `planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1_3.yaml`;
2. `planning/HEPTABAO_PLAN_V1_3_STATUS_V1.yaml`;
3. `planning/HEPTABAO_BLOCKER_REGISTER_V1_3.yaml`;
4. `planning/HEPTABAO_H01_ORACLE_EVIDENCE_RECONCILIATION_V1.yaml`;
5. `planning/HEPTABAO_WORK_PACKAGE_EXTENSION_V1_3.yaml`;
6. `planning/HEPTABAO_P0_WORK_PACKAGE_CONTRACTS_V1.yaml`;
7. the inherited V1.2 normative manifest and V1.3 manifest extension.

Historical status files are evidence of what was once asserted. They cannot override a later current-state object.

The upstream PR #41 lifecycle transition has now materialized remotely at `cd56d815f03c0a62ecb3572fb0ba635e9c5f6b93` through successful run `33276128606`. That result is input evidence only: its follow-up checks are `action_required`, it is not the PR #40/V1.2.2 unified source, and it provides no V1.3 exact-head execution, qualification or authority.

## 3. Current implementation boundary

V1.3 adds three workspace crates:

- `heptabao-protocol`: strict HTTP/1.1 parsing, target canonicalization, operation registry, request deadline, audit and secret-value contracts;
- `heptabao-authbus-contracts`: request-bound, replay-protected, short-lived Authbus assertion verification interfaces with no authorization authority and no embedded cryptographic implementation;
- `heptabao-p0-server`: loopback-only, in-memory, development server exercising init, seal status, seal, unseal, KV v1 and audit ordering.

The P0 server is intentionally non-durable and non-compatible. Credentials are supplied at process start through the environment, are not returned by init, and must never be used for real secrets.

## 4. P0 vertical slice

The first executable slice is `HB-P0-DEV-MEMORY`:

```text
bounded socket read
→ strict HTTP parse and canonical target
→ exact operation registry
→ deadline validation
→ sealed/initialized guard
→ local development authentication
→ request audit
→ in-memory mutation/read
→ response audit
→ response or post-commit recovery reference
```

Required properties:

- listener binds only a loopback address;
- Host exactly matches the actual bound listener address;
- no `Transfer-Encoding`, duplicate headers, ambiguous path, encoded slash, bare LF or non-canonical Content-Length;
- request audit failure prevents dispatch;
- rejection audit failure becomes 503 rather than a silent bypass;
- response audit failure before commit becomes 503 with no mutation;
- response audit failure after commit returns `committed=true` and a recovery reference;
- secret-bearing types redact Debug output and zero their owned byte storage on drop;
- no production or compatibility claim is emitted.

## 5. Authbus boundary

Authbus is an external authenticator, not an authorization or secrets authority.

```text
Authbus authenticates external subject
→ signs short-lived request-bound assertion
→ HeptaBao verifies issuer/audience/key/lifetime/request digest/signature/replay
→ HeptaBao creates an internal identity input
→ HeptaBao alone evaluates policy and issues tokens/leases/audit records
```

The assertion binds request ID, method, canonical target, exact Host and body. Wall-clock validity uses explicit Unix seconds and bounded future skew; process-local monotonic ticks are never serialized across the Authbus boundary. The current crate supplies interfaces only: no key, trust root or production crypto provider is selected.

## 6. H02 runtime closure

Two additional repository-controlled defects are recorded and remediated at source level:

- automatic `LogsSinceLast(3)` snapshots could purge the log before the in-memory restart test intentionally attached a fresh state machine, causing a replay request from index zero after the retained log began later;
- the OS suspend/resume case assumed node 1 remained leader after SIGSTOP/SIGCONT, even though a legal majority re-election may select another node.

The development probe now disables automatic snapshotting for that test topology and retains explicit manual snapshot cases. Post-resume writes and ReadIndex operations dynamically discover one consensus leader with a bounded timeout. These changes still require exact-head Rust and 24-entry matrix execution.

## 7. Oracle reconciliation

A project issue reports four local Oracle vectors, but the repository currently contains no verifiable signed transfer of those raw/sanitized artifacts and the known Oracle branch still contains synthetic fixtures only. V1.3 therefore records both facts:

- `claimed_local_vectors = 4`;
- `repository_verifiable_transferred_vectors = 0`.

Neither value may silently overwrite the other. H01 qualification remains blocked until exact artifacts, provenance, independent sanitization review and a signed transfer are available.

## 8. Work Package extension

V1.3 inherits 301 V1.2 Work Packages and adds five Authbus packages, making the effective catalog count 306:

- `H03-WP11` assertion protocol and request binding;
- `H07-WP11` request-pipeline adapter and failure semantics;
- `H16-WP11` Authbus authentication method and operator API;
- `H21-WP12` HA forwarding, replay-cache and fencing behavior;
- `H25-WP13` replay/confusion/forgery/fuzz/red-team qualification.

The first P0 slice consumes existing H03/H04/H06/H07/H08/H10/H12/H16/H17/H22 packages under the bounded contracts in `HEPTABAO_P0_WORK_PACKAGE_CONTRACTS_V1.yaml`.

## 9. Execution gates

### Gate A — static and semantic

- all YAML/JSON parse;
- all Draft 2020-12 schemas meta-validate;
- V1.1, V1.2, V1.2.1, V1.2.2 and V1.3 validators pass;
- all Python regression suites pass;
- workflow mutation scan finds zero write-capable CI paths;
- authority and candidate-selection sentinels remain closed.

### Gate B — root Rust

On exact Rust 1.98 and one immutable lock graph:

- `cargo fmt --all -- --check`;
- `cargo test --locked --workspace --all-targets`;
- `cargo clippy --locked --workspace --all-targets -- -D warnings`.

### Gate C — P0 socket behavior

Start the exact P0 binary on an ephemeral loopback port and prove bounded health, init, unseal, authenticated KV write/read, Host mismatch rejection and audit artifact creation. The test uses development-only credentials and destroys its temporary state.

### Gate D — H02 exact-head matrix

Run Rust 1.88 and 1.98 over the complete 24-entry in-memory/hostile/blocker/durable matrix with all process and application outcomes retained. Every entry must pass; missing, blocked, unknown, timed-out or malformed output fails the aggregate.

### Gate E — independent and external closure

No repository automation may self-close branch rules, independent reviewer identities, legal conclusions, incident operations, signing custody, restricted Oracle transfer, power-cut laboratory evidence or independently operated reproduction.

## 10. Promotion rules

- `IMPLEMENTED_LOCAL` is not `EXECUTED_REMOTE`.
- `EXECUTED_PASS` is not `INDEPENDENTLY_REPRODUCED`.
- `INDEPENDENTLY_REPRODUCED` is not `QUALIFIED`.
- `QUALIFIED` is not a compatibility claim.
- a compatibility claim is not production authority.
- only a separately verified, scoped, expiring and revocable authority grant can authorize an operation.

Every V1.3 object fixes `qualification=false`, `compatibility_claim=false`, `selected_candidates=[]`, `selection_effect=NONE` and `authority_effect=NONE`.

## 11. Closure definition

Repository-controlled V1.3 implementation is complete only when Gates A–D pass on one exact remote commit/tree and independent reviewers issue current closure receipts. Program-wide gap closure additionally requires every external action package to produce real evidence. Until then the correct stop state is `REPOSITORY_REMEDIATION_IMPLEMENTED_LOCAL / REMOTE_EXECUTION_REQUIRED / EXTERNAL_ACTION_REQUIRED`.
