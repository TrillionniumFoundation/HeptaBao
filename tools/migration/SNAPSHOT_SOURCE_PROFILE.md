# Complete OpenBao 2.7.0 snapshot source profile

`openbao270_kv2_snapshot_export.py` projects a previously qualified private raw
spool into the existing `openbao270-kv2-lossless-v1` bundle. It performs no HTTP
requests and does not modify or import into any server. It supports the exact
OpenBao 2.7.0 source build named in `kv2_lossless_raw.py`; other source releases
and builds require their own reviewed default-configuration qualification.

## Trust boundary

The backup owner must first establish all of these facts and retain the
underlying evidence:

1. The capture contains one consistent Raft snapshot with a known source
   binary, source mount identity, state digest, index and term.
2. Owned isolated recovery and a second cold recovery produce the same
   complete raw tree and every raw value. All original process owners and
   namespaces are closed, with no unknown mutations remaining.
3. Every metadata protobuf key is authenticated against its actual encrypted
   locator and reproduces the current `GET` locator. The exact mapping
   algorithm has independently passed a fresh official-binary oracle and
   its cold restart.
4. The owner pins the complete spool and a per-mount raw manifest, all
   metadata/history counts, configuration origin and evidence receipt
   digests in a witness. The witness SHA is delivered separately through
   that owner's trusted channel.

The witness is **not self-authenticating**. Its own contents cannot establish
the required SHA. Supplying a digest calculated from an untrusted adjacent
witness file does not qualify that source. The exporter checks the pinned
witness and the supplied raw bytes; it does not repeat the historical Raft
capture, recovery, oracle or cryptographic locator work. Receipt digests
bind the separately retained evidence, rather than replace it.

The witness schema is `heptabao.openbao270-complete-snapshot-source.v1`.
Unknown fields, duplicate JSON keys, unsupported source identities and
nonfinite numbers are refused. The source is currently limited to a root
namespace mount. The complete spool may contain multiple explicitly admitted
mount/backend roots, while each invocation emits exactly one mount.

The spool uses repeated `uint64_be(path_bytes)`, `uint64_be(raw_bytes)`, UTF-8
path and raw value frames. Its complete byte length and SHA are pinned. The
per-mount manifest sorts unique UTF-8 paths, starts SHA-256 with
`HBKV2-SNAPSHOT-RAW1\n`, and appends each path length, path bytes, value length
and binary SHA-256 of the value. Both lengths are unsigned 64-bit big endian.
The exporter checks every global frame and recomputes the selected manifest.

## Configuration provenance

Legacy decoding and the live exporter continue to require a physical
`/config` record. A snapshot witness permits absence only for the exact
reviewed 2.7.0 source and a complete matching raw set. That source's absent
Configuration defaults are `max_versions=0`, `cas_required=false`,
`metadata_cas_required=false` and `delete_version_after="0s"`.

When `/config` exists, its original protobuf digest must match the witness
and the original strict decoder must accept its bytes. A corrupt or
unsupported physical record never falls back to defaults. No synthetic raw
`/config` record is added to the spool. A separate provenance file names the
origin and exact output bundle digest; the existing closed bundle schema
is unchanged.

## Invocation and private custody

```sh
python3 -I -B tools/migration/openbao270_kv2_snapshot_export.py \
  --witness /private/qualified-witness.json \
  --witness-sha256 OWNER_DELIVERED_SHA256 \
  --raw-spool /private/qualified-raw-spool.bin \
  --output /private/new-bundle.json \
  --provenance /private/new-bundle.provenance.json
```

Input files must be canonical absolute, single-link regular files, owned by
the executing UID and mode `0600`. Output parents must be owned by that UID
and mode `0700`. Outputs are created exclusively at new names, synchronized,
read back and checked against their original file identities. The source
descriptors remain open and are fully rehashed before and after projection.
Failure preserves private partial outputs and returns a fixed public error.
A provenance file alone does not establish success: require exit zero and
the successful export receipt, then independently bind the output digests.

The process uses a separately named 300-second offline maintenance budget.
`TERM`, `INT` and the maintenance alarm enter the ordinary failure/descriptor
cleanup path. The caller still owns process supervision for an uninterruptible
kernel operation. This is not a claim that the original live export meets its
five-second request or 360-second total budgets; those remain unchanged.

## Capacity and remaining qualification

| Profile | Raw records | Logical paths | Config + paths + retained versions |
| --- | ---: | ---: | ---: |
| Legacy raw decoder | 10,000 | Original downstream limits | Original downstream limits |
| Explicit native large | 100,000 | 50,000 | 100,000 jointly |

Each raw record remains bounded by 4 MiB in the native profile and total raw
values by 64 MiB. The spool separately bounds aggregate path bytes by 64 MiB.
The emitted bundle is at most 64 MiB. The ordinary payload JSON decoder and
all metadata, retained-history, salt, deleted/destroyed payload and orphan
checks remain in force. The native import API must independently admit the
actual bundle under its own syntax, per-value and record limits.

A successful offline export establishes only the captured source frontier.
It does not establish the current live frontier, target import or cold
restore success, client migration, HA qualification, unrelated auxiliary
policy lifecycle migration or cryptographic verification of the sealed
snapshot checksum. The raw spool and evidence remain available for those
subsequent steps and rollback.
