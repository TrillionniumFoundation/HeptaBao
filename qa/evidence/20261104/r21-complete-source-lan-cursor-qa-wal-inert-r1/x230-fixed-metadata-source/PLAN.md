# Fixed metadata input for an X230 relay effect fence

Status: SOURCE ONLY. This exact request has not been submitted. It cannot create a fence.

## Purpose and fixed scope

The original job 1a1aa57458d-fc05-4156 remains UNKNOWN. The original approved relay is Git blob b076da8a629694e0dc988c57c13e03fa1b2ec548, 21085 bytes, SHA256 732fa7e74d859c48cd3844967409254e6f7cd44d4ceb148a20d2ea89ed07388f.

This metadata program observes the exact desktop parent D, its fixed controls directory, and sender.py / receiver.py / relay.py. It holds the fixed ancestor chain / -> /home -> /home/qian-qi -> D using O_DIRECTORY/O_NOFOLLOW and verifies every held descriptor against the corresponding name. No directory is listed. The only extra name queried is D/normal-cold-h2-x230-transfer-r1, twice, using the held D descriptor with follow_symlinks=False. It is not opened when present.

D is /home/qian-qi/heptabao-ha-closure-20261103-r1. The controls directory is D/normal-cold-h2-x230-transfer-controls-r1. The three source identities are the complete nine fields from the actual successful inert publication, including exact integer nanoseconds. Changed source metadata refuses. No current source file bytes are read or hashed; the report therefore does not substitute for the future fence's full source-byte check.

The identity order is dev, ino, uid, gid, full st_mode, nlink, size, mtime_ns, ctime_ns. All fields stay Python integers in the original JSON. Downstream readers must retain the original decimal strings or use lossless parsing.

## Exact resource contract

- New shared soft deadline: 5 seconds from Metadata construction, including final descriptor closure and publication eligibility.
- New supervisor cap: 60 seconds, independent of the old transport's budgets.
- Exactly five held directory descriptors and three source-file descriptors on success: eight registered, peak eight.
- At most 42 explicit metadata observations: five directory binds × 3; three file binds × 3; eight final held/named checks × 2; two absence observations.
- Three files are opened read-only/nonblocking/nofollow, fstat'ed, and never read.
- No filesystem writes, listing, child launch, network, signal to another process, SQLite, Git, source import or artifact transport.
- Every registered descriptor has one close-attempt marker. Close failure stays false, is not retried, and prevents success.
- The full code argument is independently hashed from sys.orig_argv; exact -I -S -B -c and the one SHA argument are required.
- No success is accepted unless authoritative exit 0, full durable stdout, all registered descriptors closed, and the post-flush original deadline check all hold. An earlier status field alone is insufficient.

No absence observation reserves a name or proves a process never existed. If either ROOT observation finds any entry (including a symlink), the metadata run refuses. It never changes that entry.

## Source-specific CAS argument for the later proposal

The original relay's top-level try first checks ROOT/CONTROL absence (lines 246-247), then reads fixed source/trust inputs, then requires ROOT.mkdir(mode=0700) at line 260. It does not pass exist_ok=True. CONTROL.mkdir and the durable intent follow (261-264). Its first start_child is the effective-config child reached at 267; receiver and sender follow at 269 and 272. No original source path removes or renames ROOT.

If a future fence's mkdirat wins the same parent/name race, a delayed exact original relay either fails its first absence check or fails its mandatory ROOT.mkdir with FileExistsError. created remains false and the transport/config children are never started. If the original relay's mkdir wins, the fence must refuse without opening, changing or deleting the original ROOT. A prior absence observation cannot replace the atomic mkdir operation.

The original finally always attempts snapshot(), which invokes /bin/ps. Therefore this proposed fence blocks entry into the transport start_child path; it does not promise that a delayed original Python process or its read-only ps never runs, nor that worker job logs are never written.

The argument requires the same verified code and continued binding of the absolute parent namespace and reserved name. Held/named before-and-after checks are observations, not a perpetual filesystem namespace lock. An unrelated writer could invalidate the argument by deleting or renaming the fence or parent. The future flow must preserve and reverify the fence; it must not clean the old ROOT.

## Future fence remains unbound

No fence implementation is admitted by this metadata request. Its directory identity pins remain unresolved until an actual successful metadata receipt and independent root review exist. The future fence must retain ready=false until those pins, exact source-byte checks, its own fixed new key, and its separately reviewed create-only request are complete.

The future fence may create only the fixed old ROOT directory and one fixed public tombstone after winning mkdir. It must keep the original job UNKNOWN. Success would prove a future effect barrier under the stated namespace/code conditions, not historical terminal state, old process custody, or old remote cleanup.

An independent subsequent validation needs separate authorization, fresh roots/key, current source/artifact admission and resource quiet evidence. It may not treat this metadata observation or a future tombstone alone as performance/product qualification.

## Offline verification scope

The attached local verifier compiled the entire metadata source as AST without executing its module or main. It also checked the original relay's actual AST ordering and selected only the invocation, once-close and deadline methods for deterministic fake-component checks. It did not invoke native metadata, open files, reserve directories, start a candidate child or access a physical host. Counts of zero I/O/children in that result refer to those selected candidate operations, not ordinary interpreter/stdlib loading or the one local verifier executor process. Raw executor output is preserved.
