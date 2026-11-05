# Native snapshot public restore: outer ending candidate

## Status and scope

This is an **uncompiled, unexecuted candidate**, based exactly on
`21a521e3e59af291dd2abc6721e8559e06338657` / tree
`625b0a5d4e2bce62fe0b014edff9c18f96840a3c`.

The independent source candidate is commit
`4f0a732bd934321e5abfc3025a22345a1c42c5ae` / tree
`62b8a0e4c1265192d86605be1766e7f4114e63d1`, on
`work/20261105-snapshot-outer-restore-61ff-r1`. Complete Git readback confirms
exact byte equality for all three candidate files and no other source changes.
See `source-readback.public.json`.

Only three Rust files change. No Mac source, production service, credential
source, ordinary KV transport or AuthBus code is changed. No HeptaBao process,
Rust formatter, Clippy, compiler, product test or HTTP observer was run for this
candidate. Local scripts only reconstructed source, compared bytes and generated
review files.

The original in-memory candidate was lost. The three files were reconstructed
from the fixed baseline and all three reconstructed hashes exactly matched the
previously recorded candidate hashes. The only subsequent source edit expands
one 102-character `matches!` assertion into four lines. See
`reconstruction.public.json`, `format-only.patch` and `manifest.public.json`.

## Concrete change

| File | Change |
| --- | --- |
| `crates/heptabao-server/src/snapshot_archive.rs` | Preserve strict `import`; add `import_public_restore`; share one private parser with a private ending policy. |
| `crates/heptabao-server/src/service_snapshot_transfer.rs` | Inside the already-admitted upload branch, select the public importer only for the exact server-owned `plan.path` values `sys/storage/raft/snapshot` and `sys/storage/raft/snapshot-force`. |
| `crates/heptabao-server/src/service_snapshot_transfer_tests.rs` | Replace the misleading four-variant rejection test with four substantive test functions separating accepted outer grammar from required content/authentication failures. |

The HTTP body is still fully staged before either importer is called. The
compressed body, including ignored suffix bytes, retains its original framing,
`MAX_NATIVE_ARCHIVE` and deadline checks.

The public parser stops only after all four required native tar entries and the
complete 1024 zero-byte terminator were successfully read. It then performs the
existing state-format magic checks and returns `Import` data. It does not perform
the two extra reads that formerly demanded gzip EOF and underlying file EOF.
Every error from a required read still propagates. No checksum or decryption
error is caught and ignored, and no second archive is scanned or selected.

The strict wrapper continues to require the complete first gzip member and
underlying file EOF. It remains the default for direct/offline import callers.
The internal `sys/storage/raft/snapshot-repair` path does not match either public
path and continues to use that strict wrapper. This patch introduces no public
verify endpoint and does not relax an existing verify tool.

## Fixed reference and grammar boundary

The fixed OpenBao 2.7.1 source is commit
`a5db72cef75c24b920ade02065b18dd8eb666bac`.
`WriteToTempFileWithSealer` calls the tar reader, verifies internal hashes
(including sealed hashes when a sealer is present), then returns the state file.
It does not call `concludeGzipRead`; that additional complete-gzip check is in
`Verify`.

- [Official restore/verify implementation](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/physical/raft/snapshot/snapshot.go)
- [Official tar and sealed checksum implementation](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/physical/raft/snapshot/archive.go)
- [Pinned flate2 1.1.8 decoder](https://github.com/rust-lang/flate2-rs/blob/1.1.8/src/gz/bufread.rs)

The existing official node-1 observations of a one-byte footer truncation and
self-concatenation are contextual evidence supplied by the parent task; this
candidate creates no additional oracle run or multi-host qualification.

The ending policy is intentionally broader than a special case for two byte
patterns: after the first complete logical tar, later DEFLATE output, CRC/ISIZE,
additional members and raw suffix bytes are not consumed by the public parser.
Those bytes still count against the complete HTTP input bound. They do not
participate in content authentication and cannot authorize or install anything.

Other native grammar remains unchanged:

- The gzip prefix must still be `1f 8b 08 00`; optional/reserved flags are
  rejected. This is not a requirement that all ten header bytes be identical:
  the old MTIME/XFL/OS treatment remains unchanged.
- The decoder is still single-member `GzDecoder`, not a multi-member decoder.
  A first member that does not yield the complete required tar cannot be rescued
  by a later member.
- Exact native filenames, order, canonical headers, lengths, zero padding and
  the full 1024 zero terminator remain mandatory. Links, PAX/GNU variants,
  duplicate paths and alternative naming are not newly accepted.
- This does not make HBB2/HBV6 native payloads OpenBao state.bin payloads.
  Cross-seal force restore and other source rules remain unchanged.

## Content authentication and actual installation

All source paths and their fixed Git blob SHAs are recorded in
`source-chain.public.json`; that document pins the complete reviewed chain.

### Import is data, not installation authority

The importer requires the metadata format and length to agree with the exact
state bytes, checks metadata/state SHA256 sums and requires nonempty bounded
sealed sums. After tar processing, metadata and HBB2/HBV6PK01/HBV6HA01 magic must
agree. This is not yet a claim that the sealed sums have been authenticated.

An eligible standby can return 307 after container prevalidation. It does not
install the archive. Such a 307 is not proof of sealed authentication or restore.

### V5 / HBB2

The finalizer preserves the original deadline, activation/base, live seal and
Actor/ACL checks. It opens `SHA256SUMS.sealed` with `CHECKSUM_CONTEXT`, requires
the resulting bytes to equal the exact computed sums, checks seal identity, and
prepares the internal backup.

The internal HBB2 parser still requires exact length and EOF, internal hash,
component AEAD, generation agreement, complete journal/checkpoint and ledger
consistency. Application schema/owner/record validation, protected floors and
capacity checks precede the affine prepared restore. The durable instance and
frontier must still match at publication.

### Single-node V6

The same sealed-sums and seal checks precede HBV6PK01 authentication. The pack
keeps exact internal EOF, per-object slot/AAD/AEAD and byte-count checks, and the
sealed `PACK_AAD` transcript footer.

`materialize_for_service` still uses full payload mode. All typed owners and
KV graphs, including paged payloads, remain validated. Actual object reads,
physical pins, live gates and durable publication remain unchanged.

### V6 HA historical/force restore and repair

HBV6HA01 retains exact internal EOF, local/shared hashes, closure checks and the
sealed `ARCHIVE_AAD` transcript. Historical or cold facts remain authenticated
data, not current Raft capabilities. Cluster/epoch/cursor/source constraints and
full local-pack/full-payload materialization remain before publication.

The historical path keeps the original Actor and current source through a new
actual Raft restore epoch/CAS and committed local installation. Existing
post-publication uncertainty fences remain intact. The internal repair route
keeps strict outer EOF and its existing live source/repair proof checks.

No installation path reviewed depends only on the outer gzip CRC.

## Authored tests: expected behavior, not results

All four functions are under `service::snapshot_transfer::tests`.

| Test | Substantive assertions |
| --- | --- |
| `strict_native_archive_import_still_requires_gzip_and_file_eof` | Normal strict import succeeds; footer truncation, A||B and raw suffix fail. Live marker remains B and spool is empty. |
| `public_native_restore_outer_end_variants_install_first_archive_and_reopen` | For both public paths and normal/footer-truncated/A||B inputs, real admission/import/finalizer restores A over a live marker. The seal stays identical, spool is empty, and drop/reopen/unseal still reads A. A and B contain different marker values. |
| `public_native_restore_rejects_required_tar_damage_and_invalid_first_archive` | For both public paths, compressed damage, non-gzip, flagged header, absent state body, truncated/nonzero terminator, changed state hash and badA||goodB fail. Generation, state identity, activation and live marker remain unchanged; spool is empty. |
| `public_native_restore_outer_end_never_bypasses_sealed_checksum_authentication` | Re-export an actual archive with valid outer framing and ordinary hashes but damaged sealed checksum ciphertext. Normal/footer-truncated/badA||goodB inputs must first produce an Upload observation, then the real finalizer must reject checksum authentication. State and spool assertions remain. |

The old test wrongly treated both observed official outer forms as corruption.
The new acceptance tests prove which data is installed and survives reopening.
The malformed-input tests retain the original real public import error mapping
(500 in the fixed source); the sealed authentication test requires its existing
400 rejection and the exact authentication error. These are not passing results.

## Mandatory unexecuted gates

`required-unexecuted-cases.public.json` distinguishes authored-but-unrun tests
from remaining independent gates. These include recomputed plain sums with stale
sealed sums; authenticated but internally invalid HBB2/V6 packs; full graph and
payload negatives; wrong HA lineage/cluster/epoch/cursor; actual repair routing;
framing, total suffix size and deadline limits; and live actor/seal/source
changes. No source review substitutes for those runs.

The candidate is not formatted by cargo fmt, compiled or Clippy-checked. Existing
recovery/HA/34-case observers and physical Mac/ROG/Pocket4 validation were not
executed against it. Runtime failures, if any, must be retained under the
original qualification gates.

## Independent unresolved wire status boundary

This candidate deliberately preserves the existing Service restore success:
status 200 with its current data payload. `http_snapshot::execute` forwards it
as `NativeReply::Json`; the HTTP writer uses `response.status` and does not
generically map 200 plus null to 204. Fixed official restore was observed as
HTTP 204. No HTTP writer or finalizer is changed here.

The new tests therefore assert the current **Service** status 200 plus actual
marker/reopen evidence. They do not prove HTTP status/body parity. The 200/204
difference remains a separate uncorrected wire boundary for an independently
reviewed fix and real HTTP validation.

## Review and provenance

The parent independently read the full three-file local diff and reported no
additional required change before packaging. Automated local checks verify the
fixed baseline blobs, reconstruction hashes, the sole formatting change, one
shared private parser, one production public-import call site, and byte-identical
required parsing, state-magic tail and Service finalizer.

The patch is based on the fixed source. Its manifest pins every before/after
byte count, SHA256 and Git blob. The independent candidate branch must not be
applied to a Mac worktree with active or unconfirmed fixture owners.

**Qualification remains false.**
