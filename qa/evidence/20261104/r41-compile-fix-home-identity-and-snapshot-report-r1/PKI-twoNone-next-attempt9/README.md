# Two explicit None arguments after actual E0061

This source-only successor is based on commit 33b814c7034ec853151b1ff13e7529c83f65ea70. The actual normal release compiler exited 101 before any regression test began. Its complete original stderr identifies precisely two missing 14th arguments in the native PKI and SSH owner dispatch calls.

Each of the two files receives one `None,` line after the existing `&mut consumption,` argument. The private dispatch definition already accepts `Option<&mut Option<NativeJwtLifetime>>`. PKI and SSH do not produce JWT login lifetime witnesses. The ordinary wrapper already passes None; the real JWT login dispatcher retains its existing request-local slot and conditional witness transfer. No signature, owner, ACL, policy, lease, clock, source proof, failure/commit boundary or test is changed.

Strict forward and reverse application proves that the two added lines are the entire product delta. The before files and three reference files are checked against the full immutable 33b canonical tree. The known-call inventory contains the definition plus three direct calls across five specifically named source files; it is not a claim that the complete repository was text searched.

The expected source tree is 1d8160c9385f8053b9a683cc1834da0f912e2d37: 3916 leaves, 358 Merkle trees, two modified leaves and 3914 untouched leaves. No candidate commit or ref has been created by this packet. Root owns the successor freeze.

No formatter, Cargo compiler, Rust test, SDK module or Runtime was executed while preparing this patch. The two initial pure adapter mistakes (Git contents already decoded; strict diff result is an object with text/hunks) are retained. They changed no candidate or host file.

The next-attempt plan preserves the original failed r1 output directory and uses a fresh r2 control/output directory. It reuses the exact existing nonblocking exclusive lock admission probe on the same target; that descriptor closes before same-PID exec and is not a claim of a lock held throughout Cargo. New actual source-stage/control identities and a new build request remain unbound. Budgets and the 149 unique /166 profile matrix are unchanged, including the legacy ACL test. New compilation and all selected test executions remain required.
