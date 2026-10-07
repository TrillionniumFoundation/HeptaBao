# ACL policy migration

Status: bounded logical migration adapter for OpenBao 2.6.2 to the current HeptaBao candidate. This document does **not** grant full migration, cutover, rollback, compatibility, production, or release authority.

## Scope

`qa/openbao-acceptance/migrate_policies.py` inventories the user-defined ACL policies visible in one namespace, reads each source policy exactly, binds the inventory to the source and target cluster identities, and optionally writes those policies to an otherwise unowned target namespace. The adapter is intentionally logical: it does not import OpenBao barrier, Raft, snapshot, token, or storage bytes.

The built-in `root` and `default` policies are observed but never transferred. Root-token authority is never recreated by this adapter. Namespace remapping is rejected. Apply mode requires all of the following:

- a private durable checkpoint;
- an operator attestation that source ACL policy writers remain frozen;
- exclusive control of the selected target policy names;
- distinct source and target clusters;
- an OpenBao **2.6.2** source.

The source is read-only after the synthetic/live fixture setup. The tool does not delete, disable, seal, fence, or cut over the source.

## Crash and retry contract

For each target policy, the checkpoint records `write_inflight` **before** the remote write. Automatic write retry is forbidden because a transport failure can follow a committed effect.

On resume:

1. if the exact policy is present on the target, the checkpoint is advanced to `complete`;
2. if the target policy is absent, the outcome remains ambiguous and the tool fails closed for authoritative reconciliation;
3. if different policy text is present, the tool reports a conflict and does not overwrite it;
4. a completed checkpoint is reusable only when the exact target policy still matches.

An existing target policy without an owned checkpoint is never silently adopted, even when its text happens to match.

## Inventory consistency

The adapter bounds policy count, per-policy bytes, and aggregate bytes. It lists the source before and after reading every policy and then re-reads every selected policy. Any inventory or policy-content change aborts the transfer. After each target copy, the live source policy is read again before the tool proceeds.

The checkpoint binding contains the frozen inventory digest plus source/target cluster IDs, versions, and namespace. Rebinding a checkpoint to a different inventory or cluster fails closed.

## Evidence

Repository-controlled evidence consists of:

- `qa/openbao-acceptance/tests/test_policy_migration.py` for committed-but-unacknowledged writes, no blind retry, checkpoint rebinding, source mutation, reserved-policy exclusion, and unowned-target conflicts;
- `qa/openbao-acceptance/policy_migration_live.py` for an actual checksum-pinned OpenBao 2.6.2 source, an actual HeptaBao TLS target, exact readback, restart, and idempotent resume;
- `.github/workflows/policy-migration-live.yml` for exact-head execution.

The latest recorded exact-head live receipt was produced from source `e7e5a0f` and is [`qa/openbao-acceptance/evidence/policy-migration-e7e5a0f.json`](../../qa/openbao-acceptance/evidence/policy-migration-e7e5a0f.json). It records 19/19 checks against a pinned OpenBao 2.6.2 arm64 oracle and the candidate binary digest `9ee7481825c1f01a1200faeb601bfe8d154e814445460c3e35b6f4e9f0178847`; it deliberately records `full_asset_migration`, cutover and rollback authority as false.

This closes only the bounded adapter portion of the `policies_acl` asset class. Full asset migration still requires namespace-complete inventory, an explicit treatment of built-in policy semantics, token/revocation cutover ordering, rollback behavior, and independent admission on the unchanged release candidate.
