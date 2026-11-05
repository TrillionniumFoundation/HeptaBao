# Root native KV2 lossless export

The normal native storage profile exposes a bounded, read-only export at
`GET /v1/sys/migration/openbao/kv2/export?mount=<mount>`.
`HEAD` uses the same authorization and source checks and sends no body.

The request requires the original, current root Actor in the root namespace,
the actual native HTTP download transport, and an explicitly activated paged
V6 storage owner. It accepts exactly one string query field, `mount`.
Wrapping, non-root namespaces, extra fields, non-native mounts and a JSON-only
in-process call do not acquire export authority.

## Content and bounds

The response media type is `application/vnd.heptabao.kv2-lossless+json` and its
schema is the existing `openbao270-kv2-lossless-v1` import schema. It contains
the selected mount configuration, per-key metadata and every retained version.
It reads the actual authenticated paged descriptors and their blocks; it does
not replay the ordinary GET projection. Exact JSON numbers, custom metadata,
metadata CAS, nanosecond timestamps and `source_deletion_time` are retained.
Soft-deleted payloads remain present. Destroyed versions retain their metadata
and have a null payload.

The existing native-large limits apply: a 64 MiB complete bundle, a 4 MiB
individual payload, and the same JSON node and depth limits. Native record
count and metadata bounds are also retained. Ordinary JSON request limits do
not change. The completed private file is checked against the same strict
token profile before delivery, using a bounded buffer that is erased on exit.

Sparse legacy version histories cannot be represented by this schema. They
produce an explicit refusal instead of invented versions or a successful but
unrestorable bundle. An empty custom-metadata map and a destroyed version's
source-deletion timestamp are exported without normalization. A destination
which cannot represent those states must reject them separately.

## Source and delivery ownership

File storage retains the real Shamir/barrier owner, held storage identity,
live seal bytes, original unseal nonce, original root Actor and original
deadline. The single-node delivery consumes only its own terminal-clock
receipt and authenticates that exact successor before releasing the file.

Raft storage retains the actual committed selection and original ReadIndex
proof, and uses the existing HA terminal-successor delivery gate. A logical
export does not grant replica publication, archive restore or membership
authority. No source state is deleted or changed by the export, apart from
the existing request-clock and mandatory audit effects.

The plaintext bundle is held in the existing descriptor-owned, unlinked
snapshot spool and reaches the socket only after successful finalization and
mandatory audit. Any source, Actor, deadline, nonce, seal or audit veto discards
that delivery. It is not retried automatically.

## Qualification boundary

This endpoint supplies an exact logical export. It does not itself establish
official OpenBao 2.7.1 raw-write compatibility, a complete reverse migration,
HA disaster recovery, provider migration, or full OpenBao parity. Those claims
require their own actual target writes, independent readback, cold restart,
CAS and multi-host evidence. Existing qualification denominators are unchanged.
