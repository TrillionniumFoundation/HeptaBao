# df026 desktop standalone source delivery, concrete transport source

This new packet binds the two-file carrier to the completed df026 standalone export. It does not dispatch a host operation. The authoritative export and all 27 command receipts/81 original streams are independently preserved in tree 7c617428645a23e18e6ffb3854708e0b210fc676. The bundle is 23,429,893 bytes / SHA256 2f25963c59ecfd0918f786c98e6babcd7ba35daec02f00d899e987f19c28ad71; the raw export receipt is 38,783 bytes / SHA256 34816ca251e2cf420ed63db97bd56c10e0c1a725e16470f28f9eedf70dd21bb4. Both original ROG versions are pinned exactly, including nanosecond timestamps. No product artifact is included in this transfer.

## Minimal reuse

The sender, receiver, relay and inert publisher derive from the previously executed 3cb two-file carrier, whose complete reference sources are included. This revision changes only candidate identity, fixed fresh paths, schemas, source-file bindings and derived helper/source hashes. The sender's ten definitions, relay's seventeen definitions and inert publisher's five definitions are byte-identical. Nine of the receiver's ten definitions are byte-identical; only the finite export-provenance literals in receive change. Every tracked transformation reverses to the original full source. Full unified diffs are included.

The original 300-second controller, 90-second endpoint/SSH-child, 10-second SSH connect and TERM 5/KILL 5 allowances remain. The external transfer supervisor is 360 seconds, as in the actual predecessor. The inert publisher has an external 60-second supervisor and executes only Python compile/publication, not any target source. Existing strict rog-ts configuration, known-host pins and the prior actual HA launcher pin remain mandatory; observed drift refuses rather than falling back to another route.

The target incoming directory is created exclusively and ends at mode 0500. Each file is created exclusively, transferred by its exact fixed length, checked for SHA and EOF, fsynced, and read back through the same FD. Both public target files are 0400 with the original raw bytes. Source ROG files remain 0600; source and target modes are separate. Remote success requires a complete sender receipt and complete local receiver receipt plus all locally owned child groups empty. Unknown endpoint or cleanup outcome remains failure without a retry.

## Ordered admission

1. Root reviews and authorizes exact dispatch/inert.request.json. It publishes three sources under a new controls directory, returns all file identities, and never starts the relay.
2. After root accepts that actual inert result, root may separately authorize exact dispatch/transfer.request.json. The relay creates only the new source-carrier root and incoming files.
3. The complete standalone importer is provided now under candidate/importer.py, with its full reference and diff. Actual export values and the exact candidate carrier program pins are already filled. It deliberately retains five unresolved transport observations: two received-file versions and the transfer receipt's bytes/SHA/version. ACTUAL_INPUTS_READY remains false. The import request template is not admissible. After the real transfer, a narrow successor may fill only those five values and the readiness flag, then be separately reviewed and authorized.

The importer keeps all original behavior: held and named directory/regular-file guards, source-only no-network Git environment, fresh independent source with no hardlinks/alternates, full 3,757-commit history and fsck, exact tree/index leaf proof, fixed 300/60/90/5+5 caps and cleanup. Its full source has 30 top-level function/class definitions; 29 are byte-identical, with only fixed metadata literals in verify_receipts changed. The earlier shorthand count of 22 is not used as an asserted full definition count here.

## Offline review

review/check_source_carrier.py parses and compiles all five sources without importing or running their top-level code. It checks forward/inverse full-byte transformations, definition equality, exact FILES/HEAD/TREE, every relay→helper→inert→carrier/request hash, all real export versions, and the five unresolved importer slots. It executes only the receiver's selected nineteen pure public-receipt assertions against the original exact-integer export JSON; no I/O/child/network branch is selected. This is source-admission evidence, not a transport or import runtime pass.

No server, compiler, archive, authentication provider, H2 client or official CLI is started by this packet. Normal 44/7/9 and future QA six-component qualifications remain separate.
