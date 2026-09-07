# HeptaBao OpenBao Oracle Lane

Status: `H01 WORK STARTED / SANITIZED PUBLIC FOUNDATION ONLY / NOT QUALIFIED`

This directory contains implementation-independent, sanitized inputs for behavioral compatibility research. It is **not** an OpenBao source mirror, an implementation crate, a compatibility claim or permission to process real secrets.

## Lane boundaries

- Raw source research, raw black-box captures and restricted upstream-derived notes belong in the separately controlled Oracle/specification storage defined by `planning/HEPTABAO_CLEAN_ROOM_ACCESS_POLICY_V1.yaml`.
- This repository may contain only approved public facts, sanitized inventories, normalization policies, schemas and secret-free fixtures with provenance records.
- The independent Rust implementation lane may consume a sanitized artifact only after a valid `heptabao.source-provenance-record.v1` authorizes the exact transfer.
- Raw OpenBao/Vault source files, copied tests, mechanical/model translations, live tokens, unseal shares, root/recovery keys, plugin private keys and production snapshots are forbidden here.

## Frozen baseline

The deterministic Oracle train is pinned in `oracle/baselines/openbao-v2.6.2.yaml`:

- release: OpenBao `v2.6.2`;
- commit: `dd9c19c37a878cf4a81b18efb8d6f0599c7da923`;
- source tree: `308de7e6da19d8b994c5710ffd715ce4cedde448`;
- release date: 2026-08-18;
- license: MPL-2.0.

A later upstream release never mutates this baseline in place. It receives a new manifest, inventory namespace, fixture set and claim scope. Current security releases are tracked independently through `planning/HEPTABAO_UPSTREAM_COMPATIBILITY_TRAINS_V1.yaml`.

## Artifact classes

```text
baseline manifest
→ surface inventory
→ endpoint/config/CLI inventory
→ raw restricted capture outside implementation lane
→ sanitized fixture + normalization report
→ signed source-provenance record
→ requirement/test/evidence graph
→ qualification receipt
→ compatibility claim
```

Qualification and compatibility still have `authority_effect: NONE`; operational use requires a separate scoped grant.

## Normalization

`oracle/normalization/HEPTABAO_ORACLE_NORMALIZATION_POLICY_V1.yaml` is explicit and versioned. The normalizer:

- preserves unknown fields by default;
- replaces only registered correlation/time/runtime values;
- converts registered secret-bearing values into typed digest/length placeholders;
- rejects suspicious secret fields not covered by a rule;
- never silently drops a security-relevant field;
- emits canonical JSON and input/policy/output digests.

Normalized equality is not sufficient by itself. Tests also compare observable storage, token, lease, audit, plugin, cluster and external-system side effects.

## Current implementation status

This H01 foundation implements baseline provenance, inventory/fixture schemas, a seeded surface catalog, a deterministic secret-redacting normalizer, negative validation and CI. It does not yet claim a complete endpoint/config/CLI inventory and has captured no real Oracle fixture in this repository.
