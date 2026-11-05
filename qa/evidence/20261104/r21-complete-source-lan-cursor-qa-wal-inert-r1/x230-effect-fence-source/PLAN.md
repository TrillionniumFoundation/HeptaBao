# Fixed original-relay directory reservation — active source for review only

This package does not authorize a host action. The candidate's BINDING_READY is true because its finite metadata inputs are now actual and root reviewed. The request remains unsubmitted and requires a separate exact root GO. The original transport job remains UNKNOWN.

## Fixed identities and provenance

The original job is 1a1aa57458d-fc05-4156, with key heptabao-df026-x230-source-artifacts-relay-r1-732fa7e7 and controller request digest aaec19b4b6de67f3cf58d898ee388396d73f4b3409fbba972df5f2de3f5f2b47. Its exact 324-byte request is blob 125f37cd526d3cdb9b4a5513b6e9c033fec45935. Its launch outcome and subsequent status remain unknown. The four bounded reconciliation reads returned generic tool errors; they did not establish ENOENT. Two healthy host connections and the missing worker job directory do not establish nonexecution, a terminal outcome, or cleanup.

The fixed source is the original relay b076da8a629694e0dc988c57c13e03fa1b2ec548, 21,085 bytes, SHA256 732fa7e74d859c48cd3844967409254e6f7cd44d4ceb148a20d2ea89ed07388f. Sender and receiver pins are also exact; all three are re-read completely before and after any permitted reservation.

The separate metadata job 1a1aa6b1640-fc05-42c8 completed successfully. Its root review is d7eaa68cf63d0d47aad38a1796b9e995f591e9b7; its actual 5,656-byte result has SHA256 da22041ad211aadaedf50655aff25284c3f361020a15416ee4e065c7a9d4a088. It made 42 metadata observations, closed all 8 registered descriptors once, and observed the original ROOT absent twice. These observations are inputs to this source, not an atomic reservation or a reconstruction of the original job's history.

The candidate binds five directories and three source files to every field of those actual nine-element identities: device, inode, UID, GID, full mode, link count, size, mtime_ns and ctime_ns. Python source literals preserve the exact integers. The reference result preserves their original JSON integer tokens. The binding projection uses decimal strings for integers beyond JavaScript's exact range and explicitly does not replace the raw source.

## Exact proposed effect

The only directory this program may create is:

/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-x230-transfer-r1

The only file it may create is that directory's relay-effect-fence.public.json. It creates neither the old control directory nor an old result receipt. No existing file is overwritten; the candidate has no unlink, rename, remove, chmod, chown, process-launch, network, listing, or signal-to-other-process path. It does not inspect X230 or any private input.

The sequence is:
1. Check the exact interpreter/argv/code SHA and the now-complete metadata binding. Hold the fixed ancestor chain with O_DIRECTORY/O_NOFOLLOW and verify named/held identities.
2. Hold the three fixed 0600, UID/GID 1000, single-link source files. Read their full bytes, SHA256 and Git blob identities; verify their named/held nine-field identities.
3. Recheck every held node. Use the held parent to observe ROOT absent. Perform exactly one mkdirat(ROOT_NAME, 0700), with no exist_ok behavior. An existing or racing ROOT causes refusal.
4. Fsync the held parent. Record the parent identity after the program's own directory-entry mutation. Device/inode/owner/mode must remain unchanged. Hold the newly created ROOT by descriptor and check its named identity.
5. Create only the fixed 0600 tombstone using O_CREAT|O_EXCL|O_NOFOLLOW. Write/fsync it, read back the exact bytes from the same descriptor, bind its named identity, then fsync the new directory.
6. Re-read the three source files in full and recheck all ten held/named nodes. Close all registered descriptors once in reverse order. Publish the bounded report.
7. Accept only a new authoritative exit 0 with full/durable stdout, no errors, all descriptor closures, final identity/hash equality and both pre-publication and post-flush checks within the original new 15-second deadline.

The tombstone is written before final closure and therefore never acts as a self-sufficient success receipt. It explicitly requires the separately bound final report and authoritative terminal. A deadline or close error can leave a directory or partial marker; that remains a failed/partial reservation, with no automatic removal, recovery, replay, or new-key retry.

## Source-specific exclusion argument

In the verified original relay, ROOT.mkdir(mode=0o700) at line 260 dominates inspect_config and both transport child starts. CONTROL.mkdir and the intent follow that mkdir. The old program never deletes or replaces ROOT.

| Ordering | Result and permitted claim |
| --- | --- |
| Reservation mkdir wins before the old absence check | The old absence assertion rejects; no transport/config start_child path is reached. |
| Old absence check passes, then reservation mkdir wins | The original mandatory mkdir raises FileExistsError; it cannot reach transport/config start_child. |
| Original mkdir wins first | The reservation refuses. It makes no isolation claim and does not open or modify the existing ROOT. |

This argument assumes the original process is executing the verified source and that the fixed namespace remains in place. Descriptor/name observations before and after are evidence at those observations, not a permanent namespace lock. mkdir does not return a held inode; the subsequent no-follow open and identity checks bind the observed new directory. A separate actor removing or renaming the reservation or its parents could invalidate future exclusion. Such actions are not authorized here.

The original program's finally block can still execute its read-only ps snapshot. Its Python process and worker logs can still exist. This reservation must never be described as killing the old task, proving no child ever ran, establishing original cleanup, or establishing the original job's terminal state. No old receipt is changed.

## Bounds and resources

| Bound | Proposed value and scope |
| --- | --- |
| New soft deadline | 15 seconds shared by all checks, reads, mkdir, fsync, publication and success closure |
| New outer supervisor | 60 seconds; failure cleanup margin only, never late success |
| Registered and peak held descriptors | At most 10 |
| Metadata observations | At most 128; the ordinary success path has 113 |
| Total public bytes read | At most 131072; two complete source scans plus the 8192-byte maximum marker fit at 127886 |
| Marker bytes | At most 8192 |
| Public stdout bytes | At most 32768 |

The old relay's 90/300/360-second budgets and all product deadlines remain unchanged. No late-success budget extension is introduced. Closing after failure remains necessary, but closure cannot convert an expired attempt to success. The signal handler records interruption; it sends no signal to another process.

## Changes and verification scope

The reviewed inactive source f5ba32352b5221d8d4573eacbde32b5876573ecc changes in exactly two one-line hunks: its documentation describes a reviewable proposal, and BINDING_READY changes False to True. All other bytes and AST nodes are identical. No path, identity, deadline, I/O rule, error branch or success predicate changes.

The 21 selected source checks were rerun on the exact active bytes. They compile the complete AST and exercise only the binding function against fixed in-memory values. A separate 17-check verifier strictly reconstructs the two literal edits in both directions, compares every other AST node, and exercises the actual selected invocation guard with the exact request and missing/wrong/extra/code-drift negatives. Candidate main and Fence I/O methods were not executed. No physical host, native descriptor, filesystem write, transport or product action was used by these checks.

The initial inactive 21-check result is retained separately. Its qualification is source-only. These component checks do not simulate a kernel mkdir race or claim to prove runtime FD closure.

## Admission and possible future work

The exact proposed request uses desktop /usr/bin/python3 -I -S -B -c, the full candidate text and its exact SHA argument, fixed cwd, a new fixed idempotency key and outer 60. There are no documentation-only fields inside the executable request. After separate root GO, the intended contract is: persist intent, single submit, retain ACK, reconcile only the same operation/job if the result is unknown, collect authoritative terminal and full output, and verify the new tombstone independently. Never replay the old relay.

A future independent X230 validation still needs its own reviewed source, fresh roots and key, current source/artifact admission, and a resource window whose residual-process uncertainties are explicitly resolved or excluded. A successful directory reservation only addresses future entry through this old relay path. It does not grant new transport or product permission.

LAN live has not been authorized here. Creating sibling fixture roots under the same BASE before the reservation would change the exact parent metadata input and cause refusal. The reservation and any subsequent validation must therefore be coordinated by root without refreshing pins merely to conceal drift.
