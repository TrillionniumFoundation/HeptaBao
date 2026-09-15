# Current capacity, maintenance and growth boundary

This contract is subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`. It describes
implemented bounded behavior and explicitly identifies the next storage change;
it does not reclassify the server as production-capable.

## Actual request path

The HTTP/Service dispatcher owns authentication and pre-entry/result audit.
The aggregate serialized `State` remains at most 768 KiB. The local durable owner
retains at most 32,000 operation identities and uses a 64 MiB journal budget.
HA proposals still carry an entire encrypted state and are bounded by their
existing codec/frame limits. These are independent bounds, not interchangeable
configuration parameters. Enlarging just one constant is not a valid growth fix.

`GET /v1/sys/internal/storage/capacity` follows the existing audited dispatch path,
requires a root principal in the root namespace, and returns only metadata:
`scope`, `state_limit_bytes`, `stored_value_bytes`, `generation`, `journal_bytes`,
`journal_limit_bytes`, `retained_requests`, `retained_request_limit`,
`remaining_request_slots`, `recovery_required`, `automatic_journal_checkpoint`,
and `replay_id_eviction`. It accepts GET with no input fields. Unauthorized
requests return 403; other methods return 405; unavailable/sealed/recovery state
remains denied by the existing admission path. It never exposes tenant names,
keys, operation IDs, plaintext, password hashes, tokens or lease identifiers.

The local retained-ID check runs before a new HA proposal. It prevents the known
local full-ledger condition from first creating a replicated effect; it does not
reserve peer capacity or turn a later disk/peer failure into a pre-entry rejection.
An individual follower can remain unable to apply new state when its local
retained-ID budget is full. ReadIndex and recovery fences are not bypassed.

## Safe automatic checkpoint

`DurableService::put_with_maintenance` is explicitly selected by the current
server's local persistence adapter. Its state machine is:

```text
put(same authorized request)
  committed or retained duplicate -> existing result
  explicit JournalCapacityExhausted before entry, no unresolved effect
    -> authenticated compact, retaining generation and every replay record
    -> one put(same authorized request)
  any other error -> no automatic retry
```

A failed checkpoint can return an I/O error while leaving the durable owner
fenced. Therefore the server mirrors `recovery_required()` on **every** error,
not only the mutation-specific OutcomeUnknown variant. It does not serve an old
cached state as healthy after an unresolved local maintenance write. Reopen and
authoritative recovery remain the way to classify uncertain state.

No operation ID, revocation tombstone, state generation or application secret is
removed to free capacity. Checkpointing is not retention expiry. A full replay
ledger still rejects new mutations. This implementation clones a bounded request
for the single permitted retry, and still serializes whole state; it is not a
performance optimization or an indexed storage engine.

## Executable evidence and fault limits

Four native tests in `crates/heptabao-durable-service/src/capacity.rs` exercise
repeated small-budget checkpoints, old duplicate/conflict/reference behavior
through restart, no identity eviction, no retry after unresolved publication and
an actual filesystem checkpoint-publication failure. Two Service tests in
`service_capacity_tests.rs` exercise authorization/audit and pre-entry capacity
rejection without changing admitted state.

`qa/openbao-acceptance/capacity_live.py` starts a fresh synthetic real TLS server,
fills it with bounded objects until 507, verifies the rejected object is absent,
checks the recovery flag, compacts, restarts and reads selected acknowledged
values. Its count is a fixture observation, not an estimate of supported users,
objects, throughput or availability. Run-specific binary digests belong in the
result receipt. Physical power loss, disk/controller behavior, long-duration load
and multi-host capacity campaigns are not established by this fixture.

## Required next storage implementation

The aggregate-state and lifetime-operation bounds remain open implementation
work. The following design constraints must be resolved together before changing
the persisted format or claiming scalable storage:

* Record ownership: separate auth, engine, lease and external-effect records with
  structural namespace/type/key identities and encrypted per-record values. A
  point mutation must not require serializing every unrelated secret.
* Transaction and Raft ownership: replicate deterministic operation batches and
  publish one authenticated commit root after quorum/application. The same root
  must govern reads, recovery and snapshot generation; do not add an independent
  side database whose commit can diverge from Raft.
* Replay lifetime: define a protocol with explicit request expiry/epoch and a
  durable rejection frontier before garbage-collecting IDs. Requests older than
  the frontier must remain rejected, never silently become new operations.
  Revocation/provider tombstones have their own external-effect retention rules.
* Upgrade and snapshot: stream authenticated snapshot chunks from a pinned commit
  root, validate a complete manifest before installation, and stage a deliberate
  old-State-to-record-store migration with rollback fences. Native streaming does
  not imply OpenBao snapshot-byte compatibility.

These are required future implementation constraints, not code claimed by this
increment. Acceptance must cover multi-record authorization changes, concurrent
CAS, reader snapshots, all crash boundaries, disk-full/partial writes, member
catch-up, old-ID rejection after GC, provider-tombstone preservation, and actual
latency/memory/recovery measurements at declared supported data sizes.
