# Offline Shamir seed transport

`heptabao-seed` transports the encrypted physical seed of a newly initialized,
stopped ordinary-file server. It does not initialize a service, accept unseal
shares, decrypt application state, activate V6, enroll a peer, or grant HA
qualification. Real startup, Shamir unseal, cluster binding, consensus admission
and authenticated native migration remain separate required operations.

Build the dedicated binary from the same exact source and normal feature set as
the server. `cargo build --locked -p heptabao-server --bin heptabao-seed` uses the
normal `native-v6-storage` feature. The existing package default executable stays
`heptabao-server`; no fixture or fault feature is needed by this helper.

## Produce an actual seed

Use the normal TLS server entry point in a new private directory. Perform real
`sys/init`, Shamir unseal and initialization acknowledgement. Keep shares and the
root credential in the existing protected credential channel. Read and retain
the actual public cluster UUID. If a V5 record root is required, perform a real
ordinary KV mount or mutation and verify its current storage profile; initial
state schema alone is not evidence of V5 activation.

Do this before the first binary snapshot operation, which can create a snapshot
spool directory. Do not activate V6 on the standalone seed before constructing
the new HA cohort. Its native object publication would not yet be committed to
the new Raft cluster.

Stop only the process whose ownership, PID and process-start identity were
recorded by the driver. Verify its terminal exit and the absence of its owned
children. Retain that stop receipt separately. The helper acquires the exact
`ExclusiveDirectory` / `File::try_lock` fence used by the durable file owner; an
active writer is refused. A successful fence acquisition does not replace the
driver's process-ownership and stop proof.

## Export and stage

The only admitted source entries are:

| Leaf | Meaning | Existing bound |
| --- | --- | --- |
| `state.hbs` | Encrypted durable checkpoint | `MAX_BACKEND_ARTIFACT_BYTES` |
| `journal.hbj` | Encrypted journal | `MAX_BACKEND_ARTIFACT_BYTES` |
| `ledger.hbl` | Encrypted replay ledger | `MAX_BACKEND_ARTIFACT_BYTES` |
| `seal.json` | Actual validated Shamir seal envelope | `SEAL_METADATA_LIMIT` |

The helper refuses every other file or directory. This includes native `nv6.*`
objects, initialization recovery, rekey/provider markers, snapshot spools and
unknown owners. It does not delete these entries to make an export pass.
Symlinks, hard links, public permissions, owner changes, missing files, changed
metadata and content drift are also refused. Reads use bounded buffers and the
original opened file descriptors. The real `SealMetadata` validator is reused.

Allocate a private export parent and a new destination name. Source directories,
destination parents and source files must belong to the invoking user with
exact private permissions (0700 directories, 0600 files). No existing destination
is overwritten, including a concurrently created empty directory.

```sh
umask 077
/absolute/heptabao-seed export /absolute/stopped-seed /absolute/new-bundle > /absolute/export-receipt.json
```

Compute and retain the SHA-256 of the exact receipt bytes, including its newline.
Transfer the four-file ciphertext bundle and the receipt through the already
authenticated controlled host channel. Keep the receipt outside the bundle so
the bundle still has exactly four entries. The receiving stage call requires
the independently retained lowercase receipt hash:

```sh
/absolute/heptabao-seed stage /absolute/transferred-bundle /absolute/new-state /absolute/export-receipt.json <receipt-sha256> > /absolute/stage-receipt.json
```

Each destination file is created exclusively with private permissions. Every
actual writer FD is synchronized and its exact identity and bytes are checked
again. The complete staging directory is synchronized before publication. The
locked `rustix` implementation uses Linux `RENAME_NOREPLACE` or Apple
`RENAME_EXCL` through the same `RenameFlags::NOREPLACE` API; an ordinary
overwriting rename is not used. The held parent is synchronized after the
atomic publication, followed by fresh destination and source checks.

Success prints only a JSON receipt containing fixed leaf names, sizes, hashes,
directory identities and the physical synchronization outcome. It contains no
path, share, token, plaintext state or wrapped barrier-key value. Both
`cryptographic_state_admission_performed` and `ha_qualified` remain false. The
stage receipt must match the export's seed manifest and ciphertext commitments.

## Failure and recovery

The original source is never removed or rewritten. A failed copy can leave a
private staging directory. An error after the atomic rename is reported as an
unknown publication outcome, even if the directory now exists. Retain the
source, destination and staging evidence and reconcile their exact identities
and hashes. Do not automatically rerun the operation, replace the target or
discard files after an unknown outcome. A lost stdout receipt is also an
unknown delivery outcome and does not justify repeating publication.

Use independent new Raft directories, audit paths and enrolled TLS identities
for each node. Set the HA cluster UUID to the actual seed UUID; do not relabel
encrypted state. Only actual unseal and consensus synchronization can
authenticate each copy. Verify the real leader's initial V5 application anchor,
then explicitly activate native storage and test each member. Before any
external traffic, retain the stopped source as a separate recovery artifact.
After accepted mutation or credential issuance, that old seed is not a current
rollback target: use the authenticated current backup/restore and per-client
rollback protocol instead of rewinding state.

## Verification

The new `native_seed_` tests use actual Shamir initialization and the real file
writer fence. They cover export/stage/cold unseal, running writer rejection,
unknown and pending owners, missing/linked/public files, changed source identity
and bytes, atomic refusal of a raced destination, pinned receipt and ciphertext
drift, false qualification claims, real initialization recovery, real V6 object
refusal and the original physical size bound. These tests do not replace the
default binary's real TLS and multi-machine cohort qualification.
