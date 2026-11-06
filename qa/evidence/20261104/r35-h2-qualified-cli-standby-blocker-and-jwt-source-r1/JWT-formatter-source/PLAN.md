# Native JWT R2: fixed nine-file formatter SOURCE proposal

This proposal formats the nine changed Rust files in commit e3afc157447d35c861f275a761b29da3e42aff8e, tree 5497775d9d473541e13e1603be8c893a3e27681b. It does not authorize execution. Source stage request c1429991e9c597d1639f02a68f791043e6c8b9e5 is a separate prerequisite: root acceptance of its actual source identity, full canonical index, children, streams and terminal state is required before this exact formatter request can be admitted. The source-stage eight-file proposal is 3ca17dba3a401f552af627569d91e14f4344a4db. No actual source-stage result is asserted here.

## Why the input changes
The nine UTF-8 source files total 1,221,466 bytes; serializing their full bodies would exceed the Native 1 MiB stdin limit and the previous formatter's 262,144-byte input limit. The new stdin is only a 1,211-byte fixed name/size/SHA manifest. The formatter reads those nine exact committed files from the separate e3af checkout. Every file must resolve without symlinks, be regular, owned by the current uid and have one link. Original fd/name/full-nine identity and EOF checks are retained, exact size is admitted before reading, and SHA is checked before any fresh output directory is created.

It reads and fences the source files again in finally. Source files are never written or used as a child working directory. Only an independently created fresh output root contains candidate copies, formatter stdout/stderr and formatted copies.

## Preserved executable contract
The existing controller source 81211c8129b8d219672f88e5d7a2f9a0e7c3dea2 is the before image. Its actual root review 65bb4bd0a2dab04290d026db87dc3e209247c4b3 and actual 169-check result a268d6f0495932391365202436b1f9b2ac2847d6 are included as original evidence, not new qualification. The same fixed rustfmt binary SHA 5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877 and explicit edition-2024 config are retained. Canonical tree inspection found no rustfmt.toml or .rustfmt.toml anywhere in the exact new repository tree.

The shared absolute 50-second clock, per-child clipped 10 seconds, original cleanup wait clipped to remaining time, and outer 60 seconds are unchanged. The complete Popen/PGID/communicate/kill/wait code is byte-identical. Children stay in the supervisor process group. The original final tool/config fences, child stopped conjunction, receipt publication, flushed summary and final deadline exit remain byte-identical. There is no Cargo, product server, service activation, repository mutation or commit in this proposal. There are up to nine owned rustfmt children.

## Explicit finite output scope
The original 262,144-byte formatted-output bound cannot contain auth.rs or service.rs. This proposal explicitly requests 524,288 bytes for auth.rs and 655,360 bytes for service.rs. The other seven retain 262,144 bytes each; their sum is 3,014,656 bytes. A new success guard rejects stderr above 65,536 bytes per file. These changes do not increase any time budget.

The successful fixed output set is 38 files: nine candidate copies, nine formatted copies, nine stdout files, nine stderr files, one config and one public receipt. A later metadata-then-version-pinned body plan has an observation admission budget of 7,906,155 bytes, including a proposed 65,536-byte receipt read ceiling. That receipt ceiling is a read-plan refusal, not a new runtime-enforced receipt bound. Original code writes saved stdout before its shape guard; a failed artifact can exceed a success observation bound and does not authorize an expanded read. No file listing, alternate path, automatic retry or cleanup is implied.

## Reviewable delta and verification
There are 14 exact replacement pairs in five strict hunks. Four of five top-level helper definitions are whole-byte unchanged; read_pin only gains an optional exact-size admission. The original child custody block and final tail are whole-byte unchanged. The actual pure V8 checker executed 106 checks, including strict forward/reverse patch reconstruction, exact input pins, canonical source identities, request binding, fixed output names, source fences, and original deadlines. It did not execute Python, rustfmt, a candidate module, Rust, or any Runtime operation.

Two local checker-development errors are retained separately: structuredClone was unavailable in pure V8, and the first lexical selector accidentally skipped the original one-line sha definition. Their corrections changed neither controller nor request. These are checker failures, not target execution results.

## Release and compilation gate
The only exact proposal is requests/FORMAT.REVIEW-ONLY.public.json. It has the pinned inline candidate and fixed manifest, original host/executable/cwd/argv shape and timeout, with a distinct formatter key. It is still unsubmitted. Root review and explicit lane authorization are required.

After an actual known success, independently collect the fixed outputs using closed metadata and immutable version-bearing reads, compare candidate/source and stdout/formatted/receipt hashes, and verify original children, source/tool/config fences and final deadline. If any Rust byte changes, freeze a separately reviewed successor source tree/commit before compiling it. Never modify e3af or claim its old baseline binary/runtime results qualify the formatted source. The fifteen new JWT regressions and adjacent existing Auth/JWT/Identity regressions still require actual compilation and execution.
