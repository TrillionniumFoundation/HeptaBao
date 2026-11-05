# Section-six implementation and acceptance map

Subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`. This is an execution increment for
the 2026-09-15 review, not a replacement master plan. Implementation baseline:
`0ddbb3a3abae30f14d9267fa56c6dd67d8de08f5` / tree
`c07f35ef3791c1bf8270c5335067eeda79ff4265`. Existing candidate ancestry and all
original authority/qualification requirements are retained.

## One inventory, differentiated states

`planning/HEPTABAO_SURFACE_WORK_V1.json` retains each of the 60 original surface
IDs, categories and fixed case bindings. Each row names its current real source
owner (or explicitly no implemented owner), six technical work dimensions and
available bounded executable profiles. A source/script path proves existence,
not correct implementation, completed execution or external acceptance. In
particular `not_implemented` rows are explicit development contracts, not APIs
advertised by the product. Broad future features require detailed endpoint and
parameter design against the pinned upstream reference before implementation.

```text
python scripts/surface_work.py
python scripts/surface_work.py --surface HB-SURFACE-SECRET-TRANSIT
```

The validator checks the original corpus content digest, exact surface/category/
case set, source paths, profile existence and required contract/evidence fields.
It does not execute shell text or grant compatibility. Modifying the corpus
requires deliberate corresponding review, never shortening the denominator.
Use `runtime_partial`, `tooling_partial` and `not_implemented` separately from
`not_executed`, `failed`, `passed_scoped` and `independently_admitted` evidence.
The fixed-corpus status is unchanged by new separately executed profiles.

## Workstream disposition in this increment

| Workstream | Actual change | Still open |
|---|---|---|
| Current truth | Correct obsolete PostgreSQL execution statement, static/remote JWT wording, duplicated remaining-fixture count, audit wording; preserve frozen historical generated tables | Semantic review remains human work; a validator cannot certify all prose |
| Sixty surfaces | Source-bound per-surface technical/evidence contracts and linked existing executable profiles, with negative validator tests | Implement and independently validate each remaining product behavior |
| Storage/compatibility | Audited capacity API, pre-entry retained-ID check, automatic journal-only checkpoint with replay-preserving retry/fences; native and real TLS refusal/restart tests | 768 KiB aggregate State, 32,000 retained IDs, whole-state HA, indexed/streaming transactional store, bounded lifetime/GC protocol |
| Actual migration | Source-decrypt/destination-encrypt/readback Transit tool, durable private per-record checkpoints, real official-binary CLI restart/lost-ack fixture | Raw-key import, arbitrary SQL provider semantics, full assets, snapshots, application-side atomic cutover |
| Integration/qualification | Both new real profiles added to existing exact-head/prospective-merge read-only CI; existing gates remain | Independent security/custody/physical-host qualification, production SLOs and Hepta consumer requalification |

## Development order and acceptance exits

The native storage boundary must evolve before a general capacity claim. Follow
`docs/storage/HEPTABAO_CAPACITY_AND_GROWTH.md`: per-record encrypted ownership,
deterministic transactional Raft batches, authenticated commit root, safe replay
expiry frontier, streamed snapshot installation and a deliberate schema migration
must work as one system. Do not raise unrelated constants or erase operation IDs
to make a stress test pass. Current refusal is deliberately tested and visible.

Transit's intentional AEAD domain binding is retained. The implemented conversion
path is documented in `docs/migration/HEPTABAO_TRANSIT_REENCRYPTION.md`; successful
conversion is not unchanged ciphertext compatibility. PostgreSQL's provider-side
sequence/tombstone SQL remains its actual contract, not OpenBao's arbitrary SQL
plugin contract. Supporting arbitrary statements requires parameter/quoting and
privilege design, negative injection tests, real role/login/revoke/root-rotation
behavior, and crash/readback reconciliation. Do not silently discard unsupported
statements, disable revocation, or report a simulated wire server as real SQL.

Each remaining auth/engine/plugin/KMS/client feature must enter through a real
product caller, the actual Service authorization/audit boundary, durable state,
HA when applicable and a genuine provider. Existing independently tested Rust
models are useful references but are not substitutes for this integration. The
manifest names those still-unimplemented surfaces without manufacturing modules.
Full migration additionally needs all-asset inventory, per-class adapters, one
writer, verified readback, revoked-effect preservation and recovery/cutover tests.

## Hepta consumer boundary

`hepta-private-ci` remains a separate source, build and authority boundary. Its
recorded real consumer uses `BaoClient::consume_kv_v2`, the kernel's independently
signed `FinalUseAuthority`, durable single-use nonce/revocation state, and the
separate `hepta-final-use-signer`. A Python replacement is not that consumer.

Before advancing `external/HeptaBao/README.md` in that repository, build or obtain
source-and-digest-bound actual `consume_secret` and signer executables from its
reviewed checkout. Execute its existing
`codex-rs/hepta-bao-adapter/qa/real_service_smoke.py` against this new Bao server,
then the normal Hepta workspace checks. Bind source commit/tree and all three
binary digests, verify signed operation/digest/version, invalid trust/signature,
nonce replay across consumer restart, provider denial, revocation and service
restart. The bounded integration still must not publish secrets into model/log
context. This increment does **not** advance that pin or claim those tests ran.

## Evidence and production boundary

Current source and each run's exact head/tree take precedence over copied status
prose. Historical PR #95 CI is evidence only for its original source. The new
candidate requires its own terminal tests; failed attempts are preserved, and
missing prerequisites are failures/blocked states rather than successful skips.
Only safe metadata receipts/logs may be retained: never archive synthetic runtime
credentials, TLS private keys, secret-bearing temporary directories or migration
plaintext. Local repeatability is not independently controlled qualification.
Independent review, signer/KMS/HSM custody, license disposition, physical fault
campaigns, vulnerability response and operational readiness must be genuine.

`qualification=false`, `compatibility_claim=false`, `production_authority=false`,
`migration_authority=false`, `release_authority=false` remain unchanged. This map
makes remaining implementation work explicit; it does not say all gaps are closed.
