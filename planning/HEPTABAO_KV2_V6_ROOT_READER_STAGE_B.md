# V6 root and closed authenticated reader: stage B

Status: **NOT_ADMITTED**. Stage B builds on detached native KV2 codec commit
`ba07d936` and includes the independently reviewed raw JSON cleanup from
`88ddd4e3` (local cherry-pick `772efc2f`). It does not enable V6 Service reads,
writes, migration, membership admission, namespace custody or replacement.

## Distinct publication identity

`state_record_root_v6.rs` defines a separate canonical V6 manifest and
`StateIdentity::RecordsV6`. The V5 manifest/type/encoding/digest domains remain
unchanged. V6 commits cluster identity, state schema, replay epoch, a required
reader floor, all five ordered protected owner roles, the KV1 root and sorted
scoped native KV2 roots. Owner roles and graph domains derive distinct keyed
object addresses from secret root material; scope-only public hashes are not
used. The V6 root identity uses its own key and digest domains.

The reader floor requires record format 6 and native KV2 cell format 1. The
root's schema must meet its declared minimum. The actual read kernel additionally
checks the supplied local reader profile, supported state-schema table, minimum
previous schema, exact expected typed identity, cluster and replay epoch before
any object is read. `RecordsV5(digest)` cannot substitute for `RecordsV6(digest)`.

## Actual protected owner and graph decoding

`service_records_v6.rs` authenticates and reassembles every role-specific owner
chunk, verifies each canonical owner digest, parses the real NamespaceRegistry,
AuthState, EngineState metadata, DatabaseState and RaftAdminState, and requires
canonical byte equality. The actual State validation remains in this path.

The V6 engines owner has a distinct wrapper containing ordinary engine metadata
and an exact scoped native-mount list. Every KV2 backend in that metadata is a
pristine placeholder, with no opaque data/configuration fallback. Borrowed
preflight checks scope/count/string bounds and rejects nonpristine KV2 bodies
before the ordinary engines decoder allocates payloads. The explicit root
namespace is required; other engine namespaces must belong to the authenticated
namespace catalog. Declared graph scopes and actual mount incarnations must
match exactly.

The kernel opens the real immutable KV1 graph and each actual native KV2 graph,
authenticating every referenced object and complete typed closure. Native views
own the real decoded KV2 model and delegate its existing read API. They remain
separate from the protected metadata State and never become a mutable Service
backend. Sparse native histories are validated by the native codec without
loosening the older opaque/importer's contiguous-history contract.

Objects are requested through an explicit owner/KV1/scoped-KV2 domain. Missing,
wrong-domain, corrupted or incorrectly addressed objects fail closed. Encoded
inspection frames additionally reject duplicate IDs, undeclared scopes and
unreferenced rows. A durable object source may legitimately retain objects from
older pinned roots; such a source is not interpreted as a closed single-root
inspection frame.

## Closed Service and legacy/HA boundaries

`service_records::decode_root` recognizes canonical V6 and explicitly refuses
Service admission pending stage C. It never returns V6 as legacy owner fallback.
Unknown record-root versions also fail closed. Known legacy storage formats and
the exact V5 decoder retain their existing behavior.

All existing exhaustive legacy/V5 local-unseal, immutable-read and received HA
identity paths explicitly reject `RecordsV6`. HBSM5/HBRO5, the existing Raft
`RecordRootBase::RecordsV5`, root publication and snapshot writer paths are not
promoted. No configuration toggle or inspection receipt enables V6.

`v6_read_validation::inspect_v6_records` exposes a privileged in-process,
read-only inspection of caller-provided plaintext root/object bytes under a
supplied expected frontier. Its safe receipt reports counts only and always
sets Service-reader, namespace-custody, membership-fence, writer, migration and
replacement qualification to false. Successful graph authentication is not a
committed membership/custody receipt.

## Bounds and remaining authority work

V5's 16 MiB aggregate opaque owner limit remains unchanged. V6's protected owner
metadata aggregate remains 16 MiB. Root encoding is limited to 64 KiB and 128
native mount references; each native graph still uses the existing stage-A
cell/count limits. The reader accounts unique encoded owner bytes (16 MiB plus
bounded framing), KV1 graph bytes (64 MiB), and aggregate KV2 graph bytes (64 MiB).
Inspection input has a 150,000-object and approximately 144 MiB encoded-byte
preflight limit. These do not establish a production RSS or staged-I/O ceiling.
Declared KV1 payloads are bounded at 64 MiB and 1,048,576 records; KV2 payload
declarations are bounded at 64 MiB and 100,000 records in aggregate. Root decode
enforces those limits before inspection-frame namespace copies or object reads.

This operator inspection kernel has no original request/deadline authority.
Stages C/D must carry the actual original request context and deadline through
root selection, every CPU/I/O boundary, custody, replication and publication.
They must not reset a budget or obtain reader permission from this facade.

The next integration points remain explicit:

- `namespace_custody.rs`, `engine_namespace_assets.rs`,
  `engine_namespace_record_cells.rs` and `namespace_record_graph.rs` must derive
  scoped native addresses from actual independent namespace key owners and
  partition/restore every graph under incarnation and retirement checks.
- `ha_record_codec.rs`, `ha_record_runtime.rs` and the record protocol/state
  machine in `heptabao-raft-runtime` must add a distinct V6 transport and
  committed membership capability. HBSM5/HBRO5 and the existing V5 replay base
  cannot stand in for this capability. Snapshot, catch-up, compaction and pinned
  readers must retain all domain-specific dependencies.
- `service_records.rs::{materialize_committed_ha_records,
  install_received_record_state}` and `service_identity.rs` must accept V6 only
  with those custody/membership owners and the original request deadline. The
  currently closed `decode_root` dispatcher must remain closed until then.
- `engines/kv.rs` and `engines/kv2_native_records.rs` must implement a real
  selected-record KV2 backend before
  `service_records.rs::{prepare_record_plan, commit_record_plan,
  persist_record_plan_local, persist_record_batch}` can stage point mutations or
  atomically migrate an opaque V5 owner. The detached whole-graph read kernel
  does not provide point-write, durability or post-Raft uncertainty semantics.

Stage C must supply actual namespace key ownership and committed membership
reader capability, define V6 object transport/resource/encryption contexts, bind
retirement and independent namespace ownership, and preserve every dependency
through snapshot, catch-up, compaction and pinned readers. Stage D must supply
point mutation, atomic V5-to-V6 migration, mandatory audit/durability ordering and
post-Raft uncertainty handling. This read-only work cannot resolve the current
production counterexample: pinned OpenBao 2.7.1 accepts sixteen 2560 KiB versions
while the unchanged candidate refuses version seven at the opaque-owner ceiling.

## Validation performed for this tranche

On native Mac with pinned Rust 1.98.0 and a dedicated offline target, strict
server all-target Clippy passed. All 12 Stage B reader tests passed. The complete
root fixture authenticates five actual protected owners, a nonempty real KV1
graph and 16 retained KV2 versions with 2560 KiB blobs each. It read 201 unique
domain-bound objects (41,965,208 encoded bytes in the recorded run), compares the
exact KV1 value response and the existing KV2 data/config/metadata/subkeys/list/
scan responses, and keeps every admission flag false.

The 10 Stage A native codec tests, four V5 root tests and eight domain tests
passed, including the existing 10,000-version, sparse-history, precision and
private-tag semantics. The new 2209-byte V5 golden manifest roundtrips exactly
and retains the independently computed pinned keyed identity. All 290
repository unit tests, repository-v2/module-closure/structural replacement
validators, rustfmt and diff checks passed. The structural replacement validator
does not grant replacement authority. Initial compile failures and two baseline
filters that selected no tests are preserved in local evidence and excluded
from test pass counts; corrected filters required the expected denominators.

This branch performed no production TLS, membership, namespace custody,
durability-fault, restart/migration or full-replacement qualification.
