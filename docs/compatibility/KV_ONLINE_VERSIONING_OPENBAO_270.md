# Bounded KV online versioning

This increment replaces the native 501 for upgrading an existing KV v1 mount.
`heptabao kv enable-versioning PATH` sends the mount tune request through the
shared strict HTTPS client. Existing Python KV commands and legacy CLI entries
remain available. This document describes a bounded increment, not full CLI or
OpenBao replacement qualification.

## Public contract and actual oracle

The public [2.7 command documentation](https://openbao.org/docs/commands/kv/enable-versioning/)
describes enabling versioning on an existing mount. Pinned official 2.7.0 CLI and
HTTP probes observed successful first and repeated execution, preservation of
leaf and nested typed data as version 1, timestamps within the upgrade interval,
CAS 0 refusal after conversion, CAS 1 publishing version 2, and downgrade refusal.
No upstream Go implementation was read.

The HTTP shape probe observed first and empty-mount conversion returning 200
with eight common response fields and a warning. Repeating version 2 returned
204 with an empty body. The native increment preserves those types and lease/null
semantics. Two observable differences remain explicit:

- The official warning says version 1 to version 0 and predicts a brief unavailable
  period. Native conversion is synchronous and returns `KV v1 data was upgraded to KV v2.`
- Native uses the existing empty request-ID convention. This is not an exact
  official UUID contract.

A later live profile must record these differences rather than normalize warning
values or claim exact complete CLI output.

## Publication and failure boundary

Both legacy KV v1 values and authenticated V5 KV v1 records are supported.
The converter reads only the requested namespace, mount and incarnation, validates
all selected canonical objects, and builds KV v2 version-1 entries before changing
the candidate. It preserves typed values, mount incarnation and omitted
configuration, assigns the supplied request clock as the new version's creation
and update time, and increments the mount revision once. Repeating the upgrade
does not publish another revision or version.

The candidate mount and removal of its old KV v1 record scope are included in the
existing Service durable publication. Retained COW snapshots keep the previous
mount and graph. Parameter/CAS errors, corrupt or missing graph, expired read
preparation, and capacity refusal before publication retain the original mapping.
The converter cannot cancel an already submitted durable or Raft write; uncertain
publication outcomes require reconciliation through the owning Service protocol.

KV v2 still uses the existing 16 MiB opaque application/engine-owner capacity.
The converter checks both aggregate source size and complete serialized KV v2
metadata; the Service also checks the full application. An oversized record-backed
KV v1 mount returns 507 and remains KV v1. This does not provide unbounded KV v2
storage or a resumable multi-publication migration.

## Evidence scope

Original Rust regressions cover legacy and record conversion, crossing a 256-key
scan page, retained graph isolation, namespace separation, exact mount CAS,
missing graph/deadline refusal, an actual capacity boundary, empty mount, and CAS
history. Service tests exercise one encrypted publication and restart, plus ACL
and injected publication-capacity veto followed by reopening the original mapping.
Python tests cover the executable command, shared credential permissions,
namespace/environment validation, one mount-only tune request, fixed errors and
absence of retry. Synthetic command stdout and credentials are not exported.

Pinned native/official live comparison, actual old-program read/write proof, and
final integrated-head qualification remain separate required evidence. Unit tests
are not those qualifications. The first Service fixture's raw-query helper error
is retained; its corrected test passes the HTTP parser's decoded version field.
