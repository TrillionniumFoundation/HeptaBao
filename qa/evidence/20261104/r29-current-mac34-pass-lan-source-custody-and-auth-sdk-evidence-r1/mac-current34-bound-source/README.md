# Current Mac full34: exact system Git reader and create-only publication proposal

This is a SOURCE-only successor to tree bdb1dd296ac147ddcd355655814df099e59c571d. The six current fixed metadata reads are preserved in tree 7335151a16006015891c4fe62655d7907f8fedc1 and independently accepted in root review b137fc849b441e3e70e44a0c29cbf6d8bb3676ca. No Runtime operation is submitted by this packet.

## Known input difference and the narrow change

The successful current /usr/bin/git file_info observed a regular file of 118,640 bytes, SHA256 b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9, uid:gid 0:0, permissions 0755 and link_count 78. Its exact version is 16777233:1152921500312571562:118640:1786589515000000000:1786589515000000000. The prior wrapper rejects it because its generic reader requires one link. That prior rejection and source remain unchanged.

The successor keeps fixed_file byte for byte. It adds fixed_system_git and changes only the Git role's dispatch in readonly_prepare. The dedicated reader accepts only the literal /usr/bin/git path and the complete observed root-owned identity, size, SHA256, version and link count 78. It requires a regular named file, opens with O_NOFOLLOW and O_NONBLOCK through the standard file context manager, compares descriptor identity before and after the read, compares the named identity after close, verifies exact whole bytes/SHA and a separate EOF probe, and checks the original prepare deadline before reads and after close. The body cap is 118,640 bytes plus a separately identified one-byte EOF probe. Short read, extra bytes, wrong digest, changed inode/metadata, close failure and expired deadline cannot return success.

The other five roles still pass through the original single-link reader. No general hardlink acceptance is added. Existing evidence proves the actual /usr/bin/git metadata and prior successful invocations of that path; it does not establish that this binary is a shim, enumerate its aliases or identify an alternative CLT/Xcode singleton executable. No alternate path, alias census, copy, tool execution or new probe is proposed.

## Lossless binding and proposed readiness

The offline assembler consumes the exact root-reviewed six-input projection. Python integer parsing preserves all dev/inode/size/nanosecond tokens; the regular type bits are ORed with the observed permission bits. The unsafe Git and OpenSSL inode values and all version strings round-trip exactly.

The proposed wrapper changes only the INPUT_METADATA literal and readiness literal after the source delta. Its inverse reconstructs the unbound source exactly; every function is identical across this metadata-binding step. The unbound template remains in candidate/. The proposed-bound/ sources contain True only as review artifacts: they have not been published or admitted. A new source review and explicit Runtime GO are required before either exact request may be used. Root's metadata review does not by itself authorize the new system Git reader or publication.

## Create-only inert publisher

The publisher is adapted from the preserved 5,025-byte source-carrier publisher. Eleven exact replacements have a whole-file inverse. sha, ident and sync_dir are unchanged; exact/publish retain their original behavior apart from the current-user ownership predicate and the new temporary basename. No existing source checkout, retained server or normal result is written.

It requires Darwin/arm64 and the configured current user's existing, nonsymlink T5 parent. It creates only:

- /Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-official271-full34-4e808-r1
- that root's control directory

Both are created as 0700 with their parents fsynced. A pre-existing root is rejected. Only one wrapper and one public receipt are published, as 0600. The decoded wrapper is checked against exact length/SHA and compiled without import or execution. Publication retains the original same-directory temporary file, exclusive creation, link-to-destination without replacement, owned temporary unlink, fsync and whole readback. Partially created root/control directories are explicitly recorded and retained on failure; this is not permission to repeat a failed or unknown request.

The proposed inert request has a 60-second external supervisor and the publisher's original 262,144-byte stdin cap. There is no new internal hard-deadline claim, no child process and no product/TLS/Git/Cargo execution in the publisher.

## Exact requests and review order

proposed-bound/INERT.request.REVIEW-ONLY.json contains the exact regular Python path, argv source, cwd, stdin carrier, new stable key and 60-second cap. proposed-bound/PREPARE.request.REVIEW-ONLY.json contains the exact future control path, --prepare-only argv, separate stable key and 90-second outer cap. No live request is generated because no prepared SHA or actual publication identity exists yet.

The admission sequence is:

1. Root reviews the dedicated Git source, lossless binding, strict diffs, publisher and exact inert request.
2. Only a separate inert GO permits the unique external intent and Runtime submission.
3. Original inert authority/streams and independent exact wrapper/receipt metadata plus full bodies must close before prepare GO.
4. The new readonly prepare retains its own 60-second absolute budget inside outer 90. It rechecks the actual files, current normal61 receipts and bounded Git source guards, creates no fixture and starts no product.
5. Only the actual prepared SHA and another explicit GO may authorize the fresh runtime request. That request is absent from this packet.

The original 31-check driver, HTTP 15 seconds, native-large migration 360 seconds, its inner HTTP 5 seconds and runtime outer 1,800 seconds remain unchanged. The original Mac Popen compatibility and failure-cleanup limitations remain; no Linux affine Owner or bounded 5+5 claim is introduced. This remains a single-node full34 migration/restore/cold gate, not HA, H2, CLI Phase B or full OpenBao 2.7.1 replacement.

## Offline verification and preserved mistakes

There are 95 source checks including strict whole application of all four diffs, unchanged-function comparisons, exact carrier/request binding and 14 selected fake-IO components. The components execute only four selected actual definitions against fake Path, FD, stream, clock and digest objects. They test the reader's guard/order/error/once-close behavior; they do not read the actual Git body, run Mac syscalls or qualify real hashing/tool execution. The real whole Git hash comes from the original file_info observation.

The initial offline assembler expected the wrong exact status label in the already frozen projection and stopped before creating output bodies. The one-string selector correction is preserved. Its next invocation encountered an existing empty offline output directory; that refusal, observed empty state and preservation are recorded without attributing an unproved cause. The same corrected assembler then generated the proposed sources in the local scratch workspace. None of these local events invoked Runtime, changed a host source, retried a product or altered the six observed inputs.
