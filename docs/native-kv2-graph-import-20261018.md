# Direct lossless KV2 import into active native V6

This change is a candidate implementation on the exact Rust base
`46cf92e5578c1a566ef0a1d8869c7cbddb6bdc50`. The source overlay contains
eight regression tests. Neither local compilation nor those tests have run in
this editing environment, which has no Rust toolchain.

## Admission and scope

The existing `POST sys/migration/openbao/kv2` JSON contract remains unchanged:
`mount` names an existing pristine KV2 destination and `bundle` uses the
closed `openbao270-kv2-lossless-v1` history schema. An activated, paged V6
single-node Service now selects a dedicated import route. The earlier generic
native route whitelist admits only this exact additional path; ordinary
parameter authorization and control-group admission still precede dispatch.
The route requires the original trusted token Clock and sudo authorization,
an empty root namespace, the configured native candidate, and reader floor 2.

HA imports remain explicitly rejected. A legacy or V5 destination continues
to use the existing aggregate importer, and that importer's native 501 guard
remains intact. A caller cannot acquire graph publication by invoking the
old engine helper directly.

This change preserves the existing JSON decoder, HTTP, CLI, and bundle byte
limits. It does **not** establish full 34-MiB OpenBao history migration or
remove the separately reproduced record/response/bundle transport blockers.
No production credentials, traffic, services, or OpenBao assets are changed.

## Typed preparation

The native helper verifies the current destination's actual paged graph,
scope, incarnation, key and pristine state before importing. It uses the
existing closed lossless decoder for version numbers, retained history,
timestamps with nanoseconds, source deletion timestamps, configuration,
custom metadata, metadata CAS counters, exact JSON numbers, soft deletion
and destruction.

The decoded private owner is encoded immediately as the existing paged
native graph. Payloads become bounded immutable typed blocks, with the same
256-KiB block codec and authenticated per-version descriptors already used
by V6. Before the replacement view can enter an EngineState, all value data
is removed from its metadata owner. Only the native graph cache and
descriptors remain there. NativeReadView still refuses aggregate JSON
serialization.

A separate opaque `NativeKv2GraphImport` owns the newly prepared typed
objects. Its private witness binds the complete target mount scope,
incarnation, projected root, and logical payload byte count. Its objects
can enter the dedicated Service planner only when these values exactly
match the projected candidate graph. The generic live planner receives no
arbitrary extra object map. Discarding this witness leaves a metadata-only
candidate that the existing materializer rejects for missing fresh payloads.

## Publication and recovery

The existing native publisher is unchanged. The import supplies it with
the authenticated candidate and an original-request authority callback.
The callback retains the admitted Auth state, exact request parameters,
sudo check, trusted Clock and original monotonic deadline; an unrelated
admission or later time budget cannot replace those values.

The writer stages immutable ciphertext and authenticates readback under
the actual file/barrier source session. Candidates larger than the existing
96-mutation limit register locators in bounded batches. Every batch keeps
the exact old root, active cursor and retained V5 source as CAS conditions.
The old active V6 graph remains selected until the final two-slot root and
cursor Apply. The writer then rereads the committed root/cursor/source and
authenticates the complete graph from durable objects before installing it.

A lost append acknowledgement fences the live Service. Cold recovery follows
the actual committed root. If only locator registration reached durable
storage, the old empty target remains selected and a new authorized request
can retry. If the final root reached durable storage, cold recovery selects
the complete imported history, and a repeated import receives the existing
non-pristine conflict instead of duplicating or renumbering versions.
Prepared ciphertext and unreachable registered locators are retained;
this change adds no object garbage collection.

## Regression entry points

Run with the real native features and require exactly eight discovered tests:

```sh
cargo test -p heptabao-server \
  --features experimental-native-v6-ha,private-ha-forward-diagnostic \
  native_kv2_graph_import_ -- --test-threads=1
```

The three codec tests verify exact history/number preservation with a
metadata-only owner, reject mismatched scope/root/budget and missing fresh
payloads, and reject replay, non-pristine configuration and incomplete
retained history.

The five Service tests cover:

1. The same bundle imported through the real V5 reference path and through
   an already active V6 Service; all selected API observations must match.
   The generic planner must reject the native candidate when its imported
   object witness is discarded. Cold reopen and later value/metadata CAS
   retain the exact imported counters.
2. Fresh real-Clock credentials without sudo, anonymous requests, malformed
   input, noncanonical mount names, unsupported methods, replay and a
   nonempty destination; the target graph and unrelated mount stay intact.
3. A 112-entry import loses the first real locator Apply acknowledgement
   after append and fsync. The test requires that exact named batch to fire,
   proving the actual object set exceeded one atomic Apply. Cold recovery
   keeps the old graph, and a fresh import completes and reopens correctly.
4. The same multi-batch import loses the real final root Apply
   acknowledgement. Cold recovery selects the complete history once and
   rejects replay.
5. Native snapshot export, a later real mutation, authenticated native
   restore and cold reopen preserve the imported history and unrelated mount.

All payloads, keys, tokens and fault-injection storage in these tests are
synthetic isolated fixtures. Passing these tests would establish the stated
Service boundary; physical Mac/X230/LAN acceptance, complete large-volume
transport migration, HA import provenance, client cutover and old-service
cleanup require their own evidence.
