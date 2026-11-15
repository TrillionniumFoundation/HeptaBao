# Dedicated native KV2 large import profile

This candidate adds a separate, bounded transport into the native graph writer.
The original `sys/migration/openbao/kv2` JSON route and the default raw migration
decoder retain their existing limits. This document describes source behavior;
the new `native_large_kv2_` tests and two-process OpenBao 2.7.1 differential still
require actual execution before this candidate can be admitted.

The preceding `native_kv2_graph_import_` group passed all eight tests on the Mac
at commit `741082dbc8dcdcb3d6dee3e584f0842f311ae86b`. That result establishes the
prior small native writer and its real durable fault/recovery cases. It is not
evidence that the large route or a 34-MiB migration already passed.

## Protocol and separate bounds

Use HTTP/1.1:

```
POST /v1/sys/migration/openbao/kv2/native-large?mount=secret
Content-Type: application/vnd.heptabao.kv2-lossless+json
Content-Length: <exact positive byte count>
X-Vault-Token: <authorized credential>
```

The body is the existing raw `openbao270-kv2-lossless-v1` bundle, without an outer
`mount`/`bundle` JSON envelope. The query must contain exactly one canonical mount
name. Only an unwrapped root-namespace request for an existing pristine paged V6
KV2 mount is admitted. A real sudo-capable Actor and trusted RequestClock are
required. HA publication is refused explicitly; the route does not add a new HA
forwarding or restore contract.

| Boundary | Dedicated native-large profile | Existing default unchanged |
| --- | ---: | ---: |
| Raw source record, client profile | 4 MiB | 1 MiB |
| Raw source aggregate, client profile | 64 MiB | 64 MiB |
| Bundle/HTTP request body | 64 MiB | Existing CLI 16 MiB; ordinary HTTP 2 MiB; Service bundle 8 MiB |
| Per-version raw JSON data, native decoder | 4 MiB | Original lossless decoder remains 16 MiB |
| Source raw HTTP response, client profile | 8 MiB | 2 MiB |
| Isolated helper input, client profile | 96 MiB | Existing helper unchanged |
| Token validation | 1,048,576 nodes, depth 128 | Ordinary domain JSON unchanged |
| Concurrent large uploads | One affine lease per Service instance | No change to other request lanes |
| Journal publication | Existing locator batches of at most 96; final root/cursor CAS | Unchanged |

The client profile is a separately implemented companion change. The Rust delta
does not modify the Python decoder or helper. All retained payloads, including
soft-deleted versions, count against the complete bundle limit. Destroyed
versions require null payloads and remain destroyed.

HTTP/2 returns an explicit 501 before reading DATA for this route. Chunked,
Expect, missing/zero/conflicting lengths, excess lengths, and ambiguous routes
are rejected. There is no silent HTTP/2 fallback. The ordinary JSON ingress does
not acquire the large cap merely because a caller names this path.

## Admission and publication

The listener keeps only its bounded header/prefix buffer while parsing the
request. It defers the remaining body and enters the ordinary audited Service
authentication and control-group boundaries. The dedicated stage checks the
actual native destination, root selection, root namespace, sudo, original Clock,
unseal activation, physical durable ownership, and pristine mount. It then issues
one private non-cloneable upload plan and one live-instance lease.

The plan owns the original Principal, RequestClock, deadline, StateIdentity,
native request-failure binding, and metadata-only admitted State. Upload and graph
preparation run outside the Service writer. Every bounded read and token/graph
phase keeps the original deadline; no phase creates a replacement budget. The
large input has a separate strict token walk that rejects duplicate keys,
excess depth/nodes, excessive records, and closed-schema violations. Each value
uses the existing token-preserving lossless decoder. The ordinary 16-MiB domain
decoder is never enlarged.

Private lossless decoding prepares immutable typed payload blocks and metadata
descriptors. The returned EngineState contains native metadata views only;
NativeReadView continues to refuse aggregate serialization. The 34-MiB history
does not enter a legacy EngineState owner or the 8-MiB owner serializer.

Finalization reacquires the Service writer, restores exactly the original failure
binding, verifies the same live-instance lease and unseal activation, compares
the selected StateIdentity, and reauthorizes the original Actor against current
Auth with the original Clock. Any intervening source or authorization change
refuses publication. The existing native graph materializer then verifies the
complete typed closure, and `commit_native_root_plan` performs its unchanged
immutable ciphertext readback, locator registration, fresh durable source
reopening, and final root/cursor conditional append. Terminal clock/audit work
retains the original deadline. A committed but uncertain result fences the live
cache and requires normal reopen/reconciliation.

Dropping a pending transfer before publication frees only its affine in-flight
lease and publishes nothing. There is no cross-request staging schema, resumable
upload identifier, or new durable session state. A complete import is the unit of
publication and recovery.

## Required executable evidence

The `native_large_kv2_` prefix contains thirteen discoverable tests:

- Three codec cases: duplicate-key/private-number handling; per-record, total,
  depth and original-check limits; explicit-profile acceptance above the still
  enforced legacy/domain byte bound.
- Three HTTP cases: deferred body reading and unchanged JSON limits; forbidden
  and excess framing before any body read; exact length, truncation and the
  original deadline.
- Seven Service cases through actual HTTP parsing or affine Service entry:
  full 34-MiB live history plus deleted history, exact metadata/numbers, native
  snapshot/restore/cold recovery and undelete; unauthorized/nonpristine/replayed
  uploads with zero body reads; expiry through body and finalization; one pending
  upload with cancellation; actual token revocation/source change after transfer;
  real locator append+fsync lost acknowledgement with cold retry; and real root
  append+fsync lost acknowledgement with one cold-selected import.

Run both the previous native eight and this new group under the same explicit
native features. Preserve every failed receipt. The real two-process controller
must separately show official OpenBao 2.7.1 export, dedicated profile transfer,
complete API comparison, restart and rollback before a full34 success is claimed.
These isolated tests do not authorize production cutover or old-service removal.
