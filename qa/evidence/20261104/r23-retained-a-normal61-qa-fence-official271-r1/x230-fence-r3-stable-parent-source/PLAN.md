# X230 original relay fence: shared parent identity correction R3

## Status and boundary

This is a SOURCE-only successor to the exact 21,479-byte R2 controller, blob fa0b8eabe31d1666377d73052ddb5025bff3df21. It is not a dispatch request and grants no host mutation or replay. The original relay 1a1aa57458d-fc05-4156 remains UNKNOWN. Its new exact desktop status and read attempt both failed in private_job_directory; those tool errors are not an original process exit, original stdout, original stderr, or cleanup proof. Full read-only packet: 8b9b9de427fdd4f375c5a396e56197d65fcba751.

The recovered later fence 1a1aac6213e-fc05-4714 is a different job. Its authority is exit 1 with complete durable public output. Its actual packet 36ccdc50549694479d0ee189ed8e606bacbf2d05 shows bind_fixed_directory/fixed_identity_mismatch, seven metadata calls, only / and /home opened and closed, zero body bytes, zero mkdir and zero tombstone attempts. In the actual source, that trace reaches the before-open comparison for /home/qian-qi. The rejected tuple itself was not emitted. Its specific changed field is therefore unproved. The fixed marker's later ENOENT observation does not prove the original relay never executed or that it is safe to replay.

## Evidence comparison, without rounding nanoseconds

The pure verifier parses the saved Python constants and the exact metadata JSON with Python integers. It compares all nine fields, including full st_mode, and keeps original source and metadata bytes.

- Earlier controller abcbde6b6defd3376d0c2cc2c490c45303c78896 expected /home/qian-qi nlink 605 and mtime_ns/ctime_ns 1793857598066648108. The later independent metadata observation 62403647a790e255006068666fb71c95965420ba recorded nlink 607 and both timestamps 1793862453712255117.
- For BASE, the earlier controller expected nlink 194 and both timestamps 1793858713862347110; the later observation recorded nlink 195 and both timestamps 1793863012520353264.
- The other six observed nodes have all nine fields unchanged between that earlier source and the later metadata observation.
- All eight nodes retain the first five fields: device, inode, uid, gid, and full mode.
- The R2 source's expected identities match every one of those later saved metadata fields exactly. Its subsequent failure cannot be attributed to one of the earlier observed differences: the rejected current R2 tuple is unavailable.

The metadata authority is blob 3850cd3c452068e119c38d2749314452d031445d: original positive-control job 1a1aaa6db3e-fc05-45a6, exit 0, complete and durable 5,656-byte stdout. Its SDK snapshot b5cebe61586ff2045c9d742197bc71fa670193b8 contains precisely that authority text. These are separate historical observations, not an atomic observation of today's directories.

## Minimal predicate change

The candidate introduces a fixed four-path allowlist:
1. /
2. /home
3. /home/qian-qi
4. /home/qian-qi/heptabao-ha-closure-20261103-r1

Only when a node is a directory and its exact path is in this allowlist does same_bound_identity compare the first five fields. st_mode includes the object type and all permission/special bits; it is not reduced to a loosely accepted permission class. The source retains the original expected nine-field records unchanged. It also records the actual before-open full tuple and actual final held full tuple; expected_fixed_identity separately exposes the historical baseline.

This predicate applies at the three existing identity boundaries: before opening against the pinned baseline, after opening between held/named observations and the baseline, and later verify_nodes checks. Each path still uses its already-held parent descriptor, follow_symlinks=False and O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC. An inode, device, uid, gid, type, or permission/special-bit change remains a rejection. Both held and named objects must keep that fixed identity. The checks are sequential observations, not an atomic directory-membership snapshot.

nlink, directory size, mtime_ns and ctime_ns remain observed metadata for these four shared ancestors. They do not become authorization to follow a replacement, accept an existing reservation, infer an absent job, skip a source hash, or start/replay a relay. Excluding them from object identity specifically prevents ordinary shared-directory bookkeeping from being conflated with replacement of the pinned parent object.

The dedicated CONTROLS directory is not in the allowlist. Its complete nine-field checks remain. All three source files retain complete nine-field, owner/group, regular-file, single-link and 0600 checks, exact bytes/SHA256/Git-blob verification before and after publication. The newly created reservation and tombstone are not in the allowlist and keep the original complete checks and original narrowly controlled metadata updates.

## Reservation and effect scope remain unchanged

reserve(), publish(), read_source(), close_all(), invocation checks, signal handling, original deadline and resource bounds are byte-identical. The only Fence methods changed are bind(), current_identity(), and verify_nodes(). The top-level report adds the explicit identity policy and schema v2.

The final reservation still requires:
- A no-follow stat of the exact ROOT_NAME relative to the held BASE descriptor.
- Rejection on any existing entry, including directory, regular file and symlink.
- Exactly one os.mkdir(ROOT_NAME, 0700, dir_fd=held_parent). A competing create that wins after an absence observation causes EEXIST to fail; there is no retry, deletion or replacement.
- Parent fsync, held/named verification of the newly created directory, and then O_EXCL tombstone publication with original same-FD byte readback and fsync.
- The same original public-source verification, all registered descriptor closures, pending-signal rejection and final original deadline.

The observation of ENOENT is not itself a reservation. Only the successful exclusive mkdir can claim this exact name was reserved by this fence. Even that does not prove original job termination: the original report and tombstone retain original_execution_state=unknown and the limited future-effect scope.

Bounds remain 15 shared seconds, 128 metadata calls, 10 registered descriptors, 131072 public-read bytes, 8192 tombstone bytes, 32768 output bytes and the original outer configuration. No subprocess, network, provider, J3160, production, credential or data access is added.

## Targeted offline evidence

The exact old and new sources compile without module execution. The harness selects original class methods and uses only fake OS objects and a fake clock. It makes zero actual FD, directory, mkdir, signal, child, network or host operations.

38 recorded checks cover:
- Exact unchanged constants and all unchanged method bytes.
- Lossless comparison of the original source expectations against the existing eight-node metadata observation.
- The actual old before-open method rejecting the separately observed metadata.
- Independent variations in each of the four excluded directory metadata fields while the original fixed object and no-follow bindings remain.
- Rejection of each first-five-field drift; replacement between open and named observation; later named replacement.
- Full-nine enforcement on controls, new reservation, public source and non-directory use of a shared path.
- Existing root directory, regular file and symlink rejection; the ENOENT-then-EEXIST race failing after exactly one attempted mkdir.

The existing full controller is not run; original history and failure reports are not modified. These component results establish the proposed predicate and unchanged create-only behavior, not current host identity or runtime success.

## Next decision

Root and independent peer must review this narrow source change. No exact runtime request is included or authorized. Any eventual execution must use a newly reviewed observation/fence identity; it cannot replay either failed fence or the UNKNOWN original relay. Existing entries must still stop the operation. Any later failure or uncertain closure remains a failure/unknown with no automatic retry.
