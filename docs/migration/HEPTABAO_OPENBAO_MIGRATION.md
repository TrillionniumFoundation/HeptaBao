# Controlled OpenBao KV-v2 migration

## Implementation boundary

This guide describes the Python HTTPS transfer tool. The separate Rust `heptabao-migration` crate now offers explicit authenticated v2 migration checkpoints as well as legacy checksum checkpoints; this tool does not invoke that crate. Its live-transfer checkpoint and the Rust protocol journal must not be treated as one implementation or one security receipt. See `docs/modules/heptabao-migration.md` for the Rust profile/key/no-downgrade contracts.

## Implemented transfer boundary

`qa/openbao-acceptance/migrate_kv2.py` copies explicitly selected KV-v2 objects
through real HTTPS APIs. The default is a read-only dry-run. Direct `transfer`
streams one object's history from source to target in process memory and does not
create a plaintext secret export. Optional `export` and `import` support a private
plaintext artifact only under the explicit controls below.

The HTTP behavior follows OpenBao's primary
[KV-v2 API](https://openbao.org/docs/api/secret/kv/kv-v2/). This is an application
data copy for a limited schema, not a conversion of OpenBao's encrypted storage,
Raft snapshots, barrier keys, policies, identity graph or dynamic-secret state.
The tool never modifies, unseals, fences, revokes, deletes, cuts over or switches
the source. Every result reports `source_modified=false`, `source_cutover=false`
and `full_format_migration=false`.

| Data or behavior | Initial implementation |
|---|---|
| KV-v2 JSON values | Exact JSON values, including nested objects, arrays, booleans and numbers, read back after each write |
| Version ordinals | Preserves contiguous readable active history1..N, at most128 versions per object |
| Deleted/destroyed versions | Rejected before copying that object; no fabricated placeholder values or destructive source undelete |
| Pruned/partial history | Rejected; historical gaps are not silently renumbered |
| Custom metadata | Copied and read back |
| `cas_required` | Copied; every data write uses an explicit CAS regardless of policy |
| `max_versions` | At least the larger of the source's explicit setting and copied-history length, so a target default cannot prune the copied history |
| `delete_version_after` | Source automatic-deletion settings are rejected; target auto-delete is explicitly disabled |
| Creation/update/deletion timestamps | Original timestamps are retained only in optional export metadata; target timestamps are newly assigned, never forged |
| Mount defaults, tune settings and ACLs | Not copied; target KV-v2 mount must already exist |
| Tokens, identity/auth methods, leases, Transit/PKI/SSH/database/cloud engines | Outside this tool's scope |
| Global snapshot consistency | Requires an actual operator-managed source write freeze; metadata is additionally rechecked per object |
| Atomic multi-object cutover | Not provided; partial verified target objects may remain after failure |

There is a1000-key explicit allowlist bound and a16 MiB total-history bound per
object. Exports are also bounded below16 MiB; larger transfers should use direct
mode or explicitly partitioned allowlists. Python does not guarantee locked or
zeroized process memory; run on an appropriately controlled migration host.

## Endpoint and key selection

Configure `HB_SOURCE_ADDR`, `HB_SOURCE_CACERT`, `HB_SOURCE_TOKEN_FILE` and their
`HB_TARGET_*` counterparts. An environment token is accepted only instead of a
token file, never in addition to it. Optional `_NAMESPACE` values select existing
namespaces. TLS verification and hostname checks are mandatory; HTTP, URL
credentials, redirects and implicit proxies are rejected. Tokens and unseal or
key material are never accepted in argv.

The source token needs read access to selected data/metadata and read access to
the mount inventory. The target token needs its inventory, selected metadata and
data privileges. Both mounts must be existing KV-v2 mounts. The tool does not
discover all secrets or expand scope from a user-supplied prefix: a private JSON
array explicitly selects relative keys, for example `["app/one", "app/two"]`.
Duplicates, traversal, empty segments, URL query
injection and percent-encoded escape attempts are rejected.

Provision the key allowlist and tokens through an approved credential source.
Files must be regular and effective-user-owned with no group/other access, normally
`0600`; symlinks are rejected. Put checkpoint/export files in an existing private
directory, normally `0700`. Do not put these files or their values in Git or CI.

```sh
export HB_SOURCE_ADDR=https://openbao-source.example:8200
export HB_SOURCE_CACERT=/secure/migration/source-ca.pem
export HB_SOURCE_TOKEN_FILE=/secure/migration/source.token
export HB_TARGET_ADDR=https://heptabao-target.example:8200
export HB_TARGET_CACERT=/secure/migration/target-ca.pem
export HB_TARGET_TOKEN_FILE=/secure/migration/target.token
python qa/openbao-acceptance/migrate_kv2.py transfer \
  --source-mount secret --target-mount secret \
  --keys-file /secure/migration/keys.json
```

This is a dry-run: it reads and validates source histories and reports target
presence counts without mutating either endpoint or creating a checkpoint.
Existing target keys are reported, not certified resumable during dry-run. Apply
refuses an existing target key unless the exact private checkpoint establishes
that this transfer created it.

## Apply and restart-safe checkpoint behavior

First establish and retain a real source write freeze through the deployment's
normal controls, and exclusive control of the selected empty target keys. The
flags below record those operator assertions; they do not perform or prove
fencing. Source and target must have different HTTPS origins and different live
cluster IDs. Recheck the intended identities before applying.

```sh
python qa/openbao-acceptance/migrate_kv2.py transfer \
  --source-mount secret --target-mount secret \
  --keys-file /secure/migration/keys.json \
  --checkpoint /secure/migration/checkpoint.json \
  --apply --source-writes-frozen --target-exclusive
```

The checkpoint binds source endpoint/namespace/mount/cluster, target
endpoint/namespace/mount/cluster, the exact key allowlist and copy profile. It
records hashed object identifiers and source snapshot digests, completed version
numbers and in-flight phases. It contains no plaintext KV values or bearer tokens,
but is still sensitive and must remain owner-only. A separate descriptor lock
rejects concurrent users of the same checkpoint. Each update uses a private
temporary file, file sync, atomic rename and directory sync.

For each object the transfer:

1. Reads all source metadata and active versions; rechecks that metadata did not
   change while reading.
2. Proves the target object is absent, durably records initialization intent,
   initializes bounded retention/metadata, and reads that metadata back.
3. Durably records an in-flight version before sending its CAS write.
4. Reads target metadata and every copied version back, compares exact values and
   ordinals, then advances the checkpoint.
5. Verifies complete target history and selected metadata, marks the object
   complete, and rechecks source metadata in direct mode.

On restart, a previously committed but unacknowledged version is accepted only
after exact target history/value readback. It is not written a second time.
Completed objects are likewise verified and skipped without creating a new
version. Source changes, a changed target, a rebinding attempt, or a missing
unowned checkpoint stop the transfer.

If a timed-out write is still absent at readback, absence alone does not prove
that the old request cannot later commit. The tool stops with
`ambiguous_pending_write_requires_authoritative_reconciliation` and does not
blindly retry. Keep the source frozen, preserve the checkpoint and obtain
authoritative target outcome evidence. Do not edit the checkpoint to turn an
unknown write into a success or a retry. If authoritative reconciliation cannot
be obtained, abandon that target scope under an explicit operator decision and
rehearse into a new empty target with a new checkpoint.

No cross-object rollback or source switch is attempted on failure. Successfully
verified earlier target objects remain identifiable by their checkpoint state.
The source stays authoritative until a separate, explicit operational cutover
decision is made after the required verification and rollback rehearsal.

## Explicit private plaintext export and import

Direct transfer is preferred. For an offline handoff, exporting requires all of
`--apply`, `--source-writes-frozen`, `--allow-plaintext-export` and an explicit
output path. The destination must not already exist. Publication is mode0600 in
an owner-only directory, with descriptor checks and no symlink following.

```sh
python qa/openbao-acceptance/migrate_kv2.py export \
  --source-mount secret --keys-file /secure/migration/keys.json \
  --export-file /secure/migration/kv2-export.json \
  --apply --source-writes-frozen --allow-plaintext-export

python qa/openbao-acceptance/migrate_kv2.py import \
  --target-mount secret --export-file /secure/migration/kv2-export.json

python qa/openbao-acceptance/migrate_kv2.py import \
  --target-mount secret --export-file /secure/migration/kv2-export.json \
  --checkpoint /secure/migration/import-checkpoint.json \
  --apply --target-exclusive
```

The first command creates a **plaintext secret-bearing file**, not an encrypted
backup. The second is import dry-run. The third validates the bounded export
schema and applies the same CAS/checkpoint/readback protocol. Offline import
reports `source_live_revalidated=false`; the source may have changed since export,
so a successful import alone cannot authorize cutover. Protect, transport, retain
and dispose of any plaintext export under the actual environment's secret-data
handling rules. Do not rely on file deletion as proof of physical secure erasure.

## Result and verification requirements

The tool emits only fixed classifications, counts and bounded scope statements.
It never emits values, key paths, bearer tokens, export content or raw server
errors. A request timeout preserves the possibility of a committed effect. A
successful run reports `copied_and_verified` only after live target readback;
this describes the selected readable history, not OpenBao-format equivalence.

The safety unit suite includes committed-but-unacknowledged resume without a
duplicate version, unknown/absent refusal, changed-source rejection, changed
target binding rejection, unowned target refusal and destroyed/pruned-history
refusal. These tests use explicit fault doubles and are not migration evidence.
Archive separate receipts from a real OpenBao2.6.2 source and the actual candidate
target, including source freeze evidence, target identity, dry-run/apply results,
restart rehearsal, independent value verification and operational rollback review.

## Recorded live rehearsal

`qa/openbao-acceptance/evidence/live-migration-20260908.json` records a completed
real HTTPS rehearsal, rather than a transport double. Its OpenBao2.6.2 binary
SHA-256 is `8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00`;
the tested HeptaBao server binary SHA-256 is
`2e91f99bbd729ea4079d5697f844fa7b9e5dcf97ac81ef410f2ea8e5c9477f54`.
Both ran as actual TLS servers in one execution/network context, with different
cluster identities and certificate validation. The final candidate fixture uses a
separate CA certificate (`ca.crt`) signing a non-CA TLS leaf (`tls.crt`); the migration
client trusts only the CA, not the leaf as an improvised CA. The Oracle used its normal server
mode with file storage, not a simulated API or dev-mode response generator.

The18 recorded checks cover two synthetic source objects containing three and
two versions, custom metadata, dry-run non-mutation, direct copy/readback, repeated
invocation without new versions, actual target SIGKILL/restart, private export and
offline import/repeat. For the checkpoint fault, a real HTTPS data write committed
at the target; the harness discarded that successful response before the copier
could acknowledge it in its checkpoint, then SIGKILLed and reopened the target.
Resumption read back the committed first version and completed versions2/3 without
creating an extra version. This specifically tests client acknowledgement loss;
it does not claim to simulate every network or power-loss fault.

The source objects remained unchanged throughout the transfer assertions. The
rehearsal subsequently removed its own synthetic source mount and stopped both
test servers. The receipt contains no secret values or credentials. Retained
private test-state directories and plaintext synthetic export files are outside
the repository; only the sanitized result is included. The record remains scoped
to the exact binary digests above, with production authority and full-format
migration false.

To reproduce against a new binary, supply an independently verified launcher
implementing `start_oracle(port)`/`stop_oracle(handle)` and a fresh private work
directory. The launcher and binary are operator-approved executable inputs:

```sh
python qa/openbao-acceptance/live_migration_rehearsal.py \
  --binary /absolute/path/to/heptabao-server \
  --oracle-launcher /absolute/path/to/verified/oracle_launcher.py \
  --work-dir /secure/rehearsal/new-run \
  --oracle-port 28500
```

Do not run two launcher instances against the same Oracle storage simultaneously.
The rehearsal starts both services in its own process/network context and shuts
them down afterward. Root credentials and unseal material are written only to
owner-only synthetic test files; no secret appears in a subprocess argument.
