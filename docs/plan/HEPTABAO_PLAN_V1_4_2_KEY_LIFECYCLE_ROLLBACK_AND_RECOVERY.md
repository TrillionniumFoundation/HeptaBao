# HeptaBao Development Plan V1.4.2 — Key Lifecycle, Rollback Anchor, and Recovery

## 1. Authority and source binding

This plan is an additive repository-controlled extension of the exact V1.4.1 head:

```text
repository_id = 1349115072
repository    = TrillionniumFoundation/HeptaBao
base_commit   = 6b2c11d46c65603f1a1e8ded742335990b61a79b
base_tree     = a83b78d1f2312f495ed82c2af1071342676380f2
```

The extension is technical evidence only. It does not select a KMS, HSM, archive authenticator, remote rollback service, filesystem adapter, production recovery target, or operational custodian. It grants no qualification, compatibility, migration, production, release, or other authority.

## 2. Objective

Close the next repository-controlled durability blockers after the authenticated journal and operation ledger:

1. record a strict provider-neutral key-epoch lifecycle without storing key material;
2. bind durable state, journal position, key epoch, checkpoint chain, and authenticator identity into an external rollback checkpoint contract;
3. capture state and the complete authenticated journal into one bounded recovery archive;
4. require exact external-checkpoint verification before restore;
5. make restore staging, empty-target enforcement, receipt verification, and publication uncertainty explicit.

## 3. Bounded profile

```text
profile                         = HB-P1-DEV-ANCHORED-RECOVERY-SINGLE-PROCESS
operating_system                = linux
production_supported            = false
replicated                      = false
multi_process_supported         = false
external_anchor_provider        = unselected
archive_authenticator_provider  = unselected
compatibility_supported         = false
```

## 4. Key lifecycle invariants

The key lifecycle journal contains no key bytes, wrapped keys, provider credentials, or production provider selection.

The state machine enforces:

- one initial active epoch after bootstrap;
- staged epochs are unique and strictly monotonic;
- rotation is one durable event that demotes the exact old active epoch to decrypt-only and promotes one staged epoch;
- only the active epoch may seal and open;
- decrypt-only epochs may open but never seal;
- staged, retired, revoked, and unknown epochs are denied;
- active revocation is forbidden; rotation must precede revocation;
- live append and restart replay execute the same invariant checks.

A lifecycle event proves only that HeptaBao recorded the transition. It does not prove that an external custody provider created, activated, destroyed, or revoked a key.

## 5. Rollback checkpoint invariants

A checkpoint authenticates a canonical preimage containing:

- checkpoint revision and previous checkpoint digest;
- checkpoint authenticator identity;
- state store domain, generation, and state digest;
- journal domain, tail sequence, and tail tag;
- active key epoch.

The coordinator must:

- authenticate every checkpoint read from the provider before using it;
- permit recovery only from a checkpoint equal to the provider's current value;
- reread the provider after compare-and-swap and reject a receipt that was not published;
- reject authenticator identity drift;
- reject store or journal domain drift;
- reject state-generation, journal-position, or key-epoch regression;
- reject same-position state, journal-tag, or key-epoch divergence;
- use provider compare-and-swap and verify the returned receipt;
- distinguish unanchored, exact, and advance-required observations.

Local memory and local disk are not treated as rollback-resistant anchors.

## 6. Recovery archive invariants

The recovery archive binds:

- archive version, archive identity, and archive authenticator identity;
- the exact checkpoint, including checkpoint authenticator identity and digest;
- state domain, generation, digest, active key epoch, and sealed state bytes;
- journal domain and every sequence, previous tag, tag, and payload;
- the exact observed journal tail.

The decoder is strict and bounded. It rejects unknown versions, zero tags, malformed lengths, excessive records, payload budget overflow, non-contiguous sequence numbers, broken tag chains, tail mismatch, invalid checkpoint shape, authentication mismatch, truncation, and trailing bytes.

The archive authenticator does not replace checkpoint verification. Restore requires an externally verified checkpoint wrapper produced by the rollback-anchor coordinator, and the archive checkpoint must equal it exactly.

## 7. Restore invariants

Restore is allowed only when:

1. the archive authenticator identity matches the selected verifier;
2. the archive tag authenticates the exact archive preimage;
3. the embedded checkpoint equals the externally verified checkpoint;
4. the target reports that it is empty;
5. the target stages the complete verified image before publication;
6. the publication receipt exactly matches archive identity, observation, and checkpoint digest.

A target publication error must distinguish definitely-not-published from outcome-unknown. Outcome-unknown is never converted into safe retry.

## 8. Work packages

### V142-WP01 — Key lifecycle ledger

Deliver `heptabao-key-lifecycle`, replay tests, illegal-transition tests, and active-revocation rejection.

### V142-WP02 — External rollback checkpoint

Deliver `heptabao-rollback-anchor`, canonical checkpoint authentication, provider identity binding, comparison classification, compare-and-swap receipt verification, and verified-checkpoint wrappers.

### V142-WP03 — Authenticated recovery archive

Deliver `heptabao-recovery-core` capture, strict codec, archive authenticator binding, exact state/journal/checkpoint validation, and bounded decoding.

### V142-WP04 — Staged restore and uncertainty

Deliver empty-target enforcement, exact externally verified checkpoint requirement, staged publication, receipt verification, and explicit publication-outcome uncertainty.

### V142-WP05 — Exact-head qualification gate

Deliver a closed additive 18-path delta, hostile mutation tests, frozen V1.4.1 replay, Rust 1.98 formatting/tests/strict Clippy, and non-authority sentinels.

## 9. Repository blocker mapping

```text
HB-BLK-REPO-028 -> V142-WP01
HB-BLK-REPO-029 -> V142-WP02
HB-BLK-REPO-030 -> V142-WP03
HB-BLK-REPO-031 -> V142-WP04
HB-BLK-REPO-032 -> V142-WP05
```

## 10. Remaining product boundaries after this extension

This plan does not close:

- real key generation, custody, wrapping, rotation ceremonies, or emergency revocation;
- a production remote/append-only rollback-anchor service;
- descriptor-relative filesystem operations and multi-process writer fencing;
- retention, archive compaction, and garbage collection;
- replicated audit and HA recovery;
- production backup scheduling, off-site custody, restore drills, or online upgrade;
- policy, identity, token, lease, namespace, and plugin domains;
- Raft membership, snapshot replication, standby reads, or compatibility behavior;
- any inherited external or repository-control blocker.

## 11. Required exact execution

The final candidate must pass:

```text
python scripts/validate_plan_v1_4_2.py
python scripts/validate_v1_4_2_inherited_surface.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_2.py' -v
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

The workflow must also replay the frozen V1.4.1 Python and Rust gates from commit `6b2c11d46c65603f1a1e8ded742335990b61a79b` in a detached clean worktree.
