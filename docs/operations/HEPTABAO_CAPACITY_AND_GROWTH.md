# Capacity observation, admission and growth

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This is a concrete runtime contract
and unresolved scalability exit, not a new plan or a production-capacity claim.

## Real owner and interface

The running Service owns one serialized encrypted application record. Auth,
Identity, KV, Transit, PKI, SSH, wrappers, local leases, PostgreSQL intents and
Raft-admin state share that record. The current limit is **768 KiB aggregate**,
not 768 KiB per secret. The server retains **32,000 operation identities**. Each
underlying durable file/journal is bounded to **64 MiB**; values are bounded to
1 MiB. Request parsing limits do not override this smaller aggregate limit.

`GET /v1/sys/internal/capacity` accepts an empty request object and reports:

| Field | Meaning |
|---|---|
| `state_bytes`, `state_limit_bytes`, `state_remaining_bytes` | Current aggregate committed application payload and hard bound. |
| `retained_operations`, `operation_limit`, `operations_remaining` | Non-evicted local durable replay identities and hard bound. |
| `journal_bytes`, `journal_limit_bytes` | Current local replay journal and configured hard bound. |
| `generation` | Durable committed local generation, not a cluster-wide capacity reservation. |
| `admission_reserved` | Always false: sizes, ciphertext overhead, concurrent activity or I/O may invalidate headroom. |
| `compaction_reclaims_operation_identities` | Always false. Compaction is not ledger garbage collection. |

Only a root token in the root namespace may enter this diagnostic. A non-root
policy with read/sudo is not sufficient. Normal request and result audit remain;
sealed state and recovery fencing reject observation. HA forwarding returns the
serving leader's local counters, not a sum or a promise about all replicas.
No token, key, path, resource name, request identity or credential is returned.
This is a HeptaBao extension, not an OpenBao compatibility surface closure.

## Before-entry capacity handling

`DurableService::preflight_new_identity` rejects a known full replay ledger before
`Service::persist` proposes a fresh HA operation. This preflight is not a future
I/O guarantee. Exact duplicates still use their existing retained record.

The server uses `put_with_compaction`: attempt once, and only on the specific
`JournalCapacityExhausted` result (before an intent was appended), create one
existing authenticated checkpoint and attempt that exact envelope once more.
There is no retry loop. `OutcomeUnknown`, corruption, I/O failure, binding conflict
and full retained-identity capacity never trigger retry. A checkpoint publication
failure fences the Service when it fences its durable owner. The old strict
`put` API retains its original behavior for callers that do not opt in.

Every committed identity remains in the checkpoint's authenticated ledger.
Before-HA-publication state/identity capacity refusals return HTTP 507. Once Raft
has committed the effect, any local persistence failure (including capacity during
leader publication or follower synchronization) is instead HTTP 503, fences the
Service and preserves any local recovery reference. It cannot be treated as a
failed-before-entry write. Unknown effects remain 503 with
recovery semantics and never release the requested secret. A failed domain
request does not restore a finite token use that already committed at admission.
Deleting journals, lowering schema numbers or resetting identities is unsupported.

## Executable evidence

`crates/heptabao-durable-service/src/capacity_tests.rs` tests repeated real durable
puts across a deliberately small journal budget, exact duplicate preservation,
known ledger saturation, wrong-binding no-retry, unknown-outcome fencing and
reopen counters and actual checkpoint I/O failure fencing. `crates/heptabao-server/src/service_capacity.rs` tests the actual
Service route, authorization, schema/bounds, compaction and reopen.

`capacity_live.py` (below) starts a new synthetic loopback TLS service,
fills the actual aggregate state, verifies 507 without a rejected-key side effect,
checks retained values, compacts and SIGKILL/reopens. Its measurements describe
that bounded fixture only. It cannot test an existing endpoint or mutate live data.
Use the current source/binary-bound output; an older successful run is not inherited.

```bash
python qa/openbao-acceptance/capacity_live.py \
  --binary /absolute/heptabao-server --output /private/new-receipt.json
```

## Scalable-storage exit still required

The current state, snapshot and ledger are still serialized monolithically. Neither
this diagnostic nor automatic checkpointing changes that complexity or removes
permanent operation-count saturation. Do not call this an unlimited store.

The next storage-format implementation must use keyed record deltas and an atomic
authenticated transaction manifest/frontier shared by Auth, engines and external
intents, while preserving the existing authorization/audit/durability order. It
must distinguish the application schema from storage format, preserve the old
source on migration, and reject unsupported binaries. A request-retirement epoch
must reject every old identity even after its detailed record is archived; deleting
records without such a fence would re-enable replay and is not acceptable.

Before admission, execute large object counts and total sizes, long-write histories,
leader/follower catch-up, snapshot/backup/restore, disk-full/torn-write/fsync faults,
mixed-version refusal, restart and measured RPO/RTO. Record peak memory, bytes
written per mutation, throughput and tail latency versus total stored bytes. Do not
raise constants and infer safety or performance from a tiny happy-path fixture.

The same precedence applies after an observed PostgreSQL effect: final local
publication failure preserves the pending lease and returns reconcile-only 503,
not a new-attempt capacity rejection. See the provider completion-publication
contract in `docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md`.
