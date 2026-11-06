# H2 stage fixed-target read closure

The two independently observed file_info results and three fixed binary reads are complete. Five original native observers, 20 readonly API calls, and 10 immutable payload pages close exactly. The offline verifier ran once with exit 0 and 411 passing checks. No candidate, SDK module, prepare, live fixture or additional stage was executed during this packet.

Actual receipt: 28,615 bytes / SHA-256 f2bcc9227a235a40afa11c1703595180a925fbd39abd29d4550872ed3a05ae6a. Actual binding: 10,230 bytes / SHA-256 b241c6fc78bbe77ea69fc3b8a707b1747324a81f1da1ade3d9bb15c5cea5b7d8. Both have independently observed versions, 0600 permissions, UID/GID 1000, and one link. Their complete bodies came from the original version-bound binary reads. The receipt shares a content address with the earlier derived expectation; the original chunk provenance is retained and no expectation was substituted for an actual read.

The receipt was written before the stage finally block, so its fd_close_pending=true is retained. The separate original stage final stdout records all_stage_fds_closed=true, no close errors, and completion within the stage deadline. Root already independently reviewed that stage evidence. The current packet closes only the two fixed target documents; it does not assert 22 new independent file_info observations of every staged target.

## Preserved exceptions

An offline full_mode projection mistakenly added permissions twice (33536). The original native permission mode was always 384. The previous helper/journal and the correction to S_IFREG 32768 | 384 = 33152 are retained. Content, UID/GID, link-count, version and dispatch guards did not change.

The third payload page of receipt-body0 returned successfully and was locally fsynced before Git archival failed with ReadTimeout. A same-object Git lookup returned 404; trying to archive the Git error then returned an internal Git tool error. All three original Git errors remain. The exact eight pending public originals were subsequently stored through create_tree content entries and read back whole in tree 98aecf8ce75ab5ff7594d93081b260a1e9a89348. No Runtime page, binary_read, metadata request or business operation was repeated. The local pre-publication index intentionally preserves its earlier external_Git_saved=false observations; the recovery-complete record gives the later successful archive boundary.

A local error-inspection helper initially attempted JSON.parse twice on an already parsed SDK object. This produced only a local SyntaxError; the same existing wrapper was then read correctly. That note is explicitly a reported local error, not a reconstructed Runtime SDK.

The earlier stage status-query delivery UNKNOWN remains historical and is not converted by these new observations. Current A is released to root with zero tool calls and zero native futures in flight. Prepare and live still require separate authorization.
