# HeptaBao Master Development Plan V1.4

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`  
**Revision:** `1.4`  
**Status:** `NORMATIVE_DURABLE_SINGLE_NODE_FOUNDATION_INPUT`  
**Authority effect:** `NONE`

## 1. Purpose

V1.4 begins the first product-kernel step after the V1.3.1 repository-controlled
technical closure. It converts the target storage/barrier architecture into
provider-neutral Rust contracts and one fail-closed single-process durable
implementation. The bounded profile is:

```text
HB-P1-DEV-DURABLE-SINGLE-PROCESS
```

This revision does not select a production cryptographic provider, does not
claim OpenBao compatibility, and grants no qualification, production,
migration, release or mixed-cluster authority.

The frozen V1.3.1 baseline is
`a5b9739e46f4bed54dbb3edd0e32400481b3b12f`, tree
`1727b9498258883b2504c53ac501c415a07218e2`. Runtime execution and review
results for V1.4 are resolved from the exact Git commit and GitHub event; they
are never inferred from this static document.

## 2. Scope

V1.4 adds four workspace crates:

1. `heptabao-storage-api` — provider-neutral durable generation, lifecycle,
   integrity and compare-and-swap contracts;
2. `heptabao-barrier-api` — versioned sealed-envelope and associated-data
   contracts with no cryptographic implementation or embedded key;
3. `heptabao-single-node-store` — absolute-path, single-process generation
   store with explicit create/reopen/adopt lifecycle;
4. `heptabao-durable-core` — a minimal composition that seals plaintext before
   storage commit and verifies exact generation receipts.

The exact files, status object and blocker extension are indexed by
`planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4.yaml`.

## 3. Authoritative ordering

The mutation path is:

```text
validate expected generation
→ derive next non-zero generation with checked arithmetic
→ resolve active barrier key epoch
→ build canonical domain/generation/epoch/purpose associated data
→ seal plaintext through the configured BarrierProvider
→ encode one strict versioned envelope
→ persist immutable candidate generation bytes
→ fsync candidate file
→ atomically publish CURRENT
→ fsync the storage directory
→ publish the initialized-store marker after the first durable generation
→ reread and verify generation/digest/current binding
→ update in-memory current generation
→ return commit receipt
```

Plaintext must not cross the `DurableGenerationStore` boundary. A stale
expected generation is rejected before barrier-provider work. A commit path
that may have changed `CURRENT` but cannot prove durable completion returns the
explicit `CommitOutcomeUnknown` error and forbids blind mutation retry.

## 4. Lifecycle

The caller must choose exactly one lifecycle operation:

- `create_new`: absolute existing empty directory; no implicit defaults are
  published;
- `reopen_existing`: valid marker, `CURRENT`, immutable bundle and integrity
  binding are all required;
- `adopt_legacy`: marker must be absent, unresolved temporary artifacts are
  forbidden, and the complete existing generation is verified before marker
  publication.

Missing initialized state, non-regular files, symlinks, truncation, trailing
bytes, invalid versions, domain/algorithm drift, digest mismatch and generation
conflict fail closed. Corrupt current state never silently falls back to an
older bundle and never initializes an empty store.

## 5. Binary and integrity boundary

The development store owns three strict formats:

```text
heptabao.marker
CURRENT
generation-<20-digit-generation>.hbs
```

Every decoder rejects truncation and trailing data. `CURRENT` binds generation
and digest. Each immutable bundle binds generation, storage domain, integrity
algorithm identity, digest and opaque state bytes. The integrity algorithm is
injected through `IntegrityProvider`; this plan does not claim that an
unkeyed digest alone protects against a storage attacker.

The sealed envelope separately binds version, key epoch, nonce, ciphertext and
authentication tag. Its canonical associated data includes domain, generation,
key epoch, purpose and caller data using length-prefixed fields.

## 6. Secret handling

`OpaqueState`, `SecretState`, `SealedEnvelope` and barrier context caller data
are non-`Clone`, redact safe `Debug` output and overwrite owned user-space
buffers on controlled drop paths. These controls are best effort. They do not
prove compiler-proof zeroization, allocator-page scrubbing, swap exclusion,
core-dump prevention, locked memory or side-channel resistance.

The only barrier implementation in this revision is a `cfg(test)` mock used to
prove composition and associated-data rejection. It is intentionally not
cryptography and must never be exported as a production provider.

## 7. Repository-controlled blockers

V1.4 introduces and addresses at source level:

- `HB-BLK-REPO-018`: no provider-neutral durable generation API;
- `HB-BLK-REPO-019`: no versioned barrier envelope/associated-data boundary;
- `HB-BLK-REPO-020`: no fail-closed single-node generation implementation;
- `HB-BLK-REPO-021`: no executable barrier-before-storage composition;
- `HB-BLK-REPO-022`: no exact-head V1.4 plan/Rust gate.

Source presence is not execution. These blockers reach technical closure only
after the V1.4 exact-head workflow passes and a final designated-ratifier head
runs the inherited V1.3.1 source/merge matrix without changing any authority
claim.

## 8. Exact execution gates

### Gate A — version-aware plan and regression execution

Historical V1.3/V1.3.1 validators intentionally describe a closed world with
seven workspace crates and one canonical V1.3.1 pull-request workflow. V1.4
does not weaken or reinterpret those rules against an expanded tree. Instead,
the exact V1.4 workflow must:

- verify that the current branch is a descendant of the frozen V1.3.1 baseline;
- compare the complete Git name/status delta against the closed V1.4 extension
  allowlist and reject any inherited-file modification;
- create a detached temporary worktree at the exact V1.3.1 baseline and rerun
  its complete plan, platform and Oracle Python suites there;
- validate the V1.4 manifest against its Draft 2020-12 schema;
- run the V1.4 closed-world source and mutation tests on the current head;
- run current platform and Oracle regressions against the expanded workspace;
- keep every qualification and authority field false/NONE.

This preserves the old proof on the old exact source while proving that V1.4 is
an additive extension rather than silently relaxing the historical contract.

### Gate B — Rust 1.98 workspace

On the exact V1.4 head and committed lock graph:

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

### Gate C — inherited exact-source technical controls

After implementation source stops moving, the designated `ProfHepta` ratifier
must publish the required one-parent, no-tree-change ratification commit. The
V1.3.1 canonical head/merge workflow must then execute on that exact head and
its distinct GitHub synthetic merge. It must retain source/merge identity, P0
typed evidence, OpenRaft dual-toolchain checks, H02 24/24 and lane arbitration
without changing any qualification or authority field. No other identity may
be substituted or inferred from repository ownership.

### Gate D — independent review

Current review is required from independently accountable storage and security
roles. Repository automation and the author cannot self-issue those receipts.

## 9. Explicit non-scope and remaining work

V1.4 does not close:

- production AEAD/KMS/HSM selection, key custody, rekey or recovery ceremony;
- descriptor-relative no-follow filesystem operations and multi-process writer
  fencing;
- an authenticated append-only audit ledger and durable request/effect journal;
- external rollback anchor, anti-rollback inventory and storage-controller
  persistence proof;
- production database backend, backup/restore, online upgrade or schema
  migration;
- Raft/HA integration, membership, snapshot replication or standby reads;
- policy, token graph, lease, namespace, plugin and full API compatibility;
- restricted Oracle transfer, independent power-cut testing or independently
  operated reproduction;
- any external/control blocker inherited from V1.3.1.

These are maintained as open inputs rather than represented as implicit
success.

## 10. Stop and promotion rules

```text
SOURCE_PRESENT
→ EXACT_HEAD_COMPILES
→ EXECUTED_PASS
→ INDEPENDENTLY_REVIEWED
→ QUALIFIED
→ COMPATIBILITY_CLAIM
→ SCOPED_AUTHORITY_GRANT
```

No transition is implicit. The truthful V1.4 source state remains
`SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED` until
its exact gates and independent receipts exist. Even after technical closure:

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
