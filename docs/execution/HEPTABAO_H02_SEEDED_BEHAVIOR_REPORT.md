# HeptaBao H02 Seeded Behavioral Harness Execution Report

**Plan:** `HEPTABAO-PLAN-2026-08-28` revision `1.1`  
**Branch:** `codex/h02-seeded-behavior-harnesses`  
**Implementation source:** `dc5f18bea2e039e2897cd89a3e502e96c4580b8d` / tree `52cd4c67cda5984183bef11bae31e230512cd35a`  
**Status:** `REFERENCE MODELS IMPLEMENTED / LOCAL UNATTESTED PASS / NOT QUALIFIED / AUTHORITY NONE`

## Delivered

- A deterministic `SplitMix64` seed/replay contract.
- Runtime, TLS and Raft reference models with six fail-closed cases each.
- Canonical JSON trace and final-state SHA-256 evidence.
- An evidence schema that separates reference-model and candidate-adapter execution.
- An independent-reproduction merger requiring two distinct attested environments and runners.
- A reproduction bundle that remains `PENDING`, unqualified and authority-free.
- Twelve semantic and negative tests.
- A GitHub matrix covering three domains and three fixed seeds.

## Local execution

The exact implementation commit/tree above was run in a local Python 3.13.5 container with seed `0x5eed20260828cafe`.

| Domain | Cases | Trace SHA-256 | Result |
|---|---:|---|---|
| Runtime | 6/6 | `fdcbe302910b97884f56ded87d094dde938e364b12a5e6ae281fe7832967b16a` | PASS |
| TLS | 6/6 | `0705b82e40a550216693067c2fd3c77d26b6cae99a5fd9c9f327d1b8d775b9c0` | PASS |
| Raft | 6/6 | `3e5adfbef64b94200120a60664696b0796cd77b6c987d306f14eb0c6548c7179` | PASS |

All three evidence objects passed JSON Schema validation and exact replay. The plan validator passed, and all 12 semantic/negative tests passed.

This evidence is intentionally marked `attested=false`. It cannot qualify H02, select a dependency, or grant Runtime/TLS/Raft implementation authority.

## Behavioral boundary

The reference models prove that the HeptaBao-owned harness, invariant set, trace format and replay mechanism are executable. They do **not** prove Tokio, rustls or OpenRaft behavior.

Candidate-specific evidence remains pending for:

- Tokio 1.53.1 cancellation, panic isolation, bounded blocking and leak behavior;
- rustls 0.23.43 ring and aws-lc profiles, including malformed tickets, mTLS and atomic reload;
- OpenRaft 0.10.0-alpha.33 deterministic apply, snapshot conflict, membership, partition and quorum-loss behavior.

## Remote execution

GitHub run `33163071844`, job `98821929468`, was observed as:

```text
status=queued
runner_id=null
runner_name=null
steps=[]
```

It is classified `INFRASTRUCTURE_UNEXECUTED`, not pass and not code failure.

## Authority

```text
H02 qualification                 false
candidate selection               0
prototype selection authority     false
production dependency authority   false
crypto implementation authority   false
Raft implementation authority     false
compatibility / production /
migration / release authority     false
authority_effect                  NONE
```

## Next execution

1. Execute all nine reference-model matrix entries on an attested runner.
2. Reproduce identical source/profile/seed evidence in a second attested environment.
3. Add exact candidate adapters without allowing candidate types into HeptaBao domain contracts.
4. Run candidate behavior together with the existing byte, graph, SBOM, advisory, license, unsafe/native and MSRV evidence.
5. Obtain independent specialist review before any bounded prototype-selection receipt.
