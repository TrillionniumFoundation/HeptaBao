# Fresh Mac sandbox plumbing probe — source candidate R1

## Actual failure retained

The sole Mac R4 runtime job `1a1a9af7832-fc05-36bb` ended with authoritative exit 1, complete durable output and no timeout. Its complete immutable packet is tree `eb341a5dd61c31e2e5ff4396b009e95cbbbd2a81`. The outer read the frozen credential-origin inputs and formed its projection; the sandbox capture child refused before opening the current databases. No consumer, service or launchd phase began. Both owned children and all recorded descriptors closed.

The child public receipt (blob `bd6fdb84fefc995a8c579d7dd299b1e66af014e6`, 1,299 B) reports PermissionError, no errno, no completed command row, a successfully held T5 anchor and no UUID verification. This limits the observed location; it does not uniquely identify the failed syscall.

## Concrete source gap and minimum candidate change

The exact entry source `d972159225b1d7478746c9296eb9bb69eb99844c` generates the capture policy at lines 84–114. It permits writing /dev/null but has no read rule for that literal; none of its read subtrees contains /dev/null. The exact Commands source `c102dfdc565484421bf7dbbb04b7c8b9e4cd5511` calls Popen with stdin=DEVNULL at lines 47–49 before adding its row at 50–53. require_waitid checks only available APIs and SIGCHLD disposition. Opening /dev/null read-only is therefore a concrete missing permission on this path. Other possible PermissionError causes in Popen are not excluded by the existing receipt.

The candidate entry changes one policy list: add exactly `(allow file-read* (literal "/dev/null"))`. Its original file-write, current-private-input and network policy remains unchanged. It is a source candidate, not a modification of the installed R4 entry. No new production capture generation is dispatched by this packet.

## One new owned proof

The exact new root is:

`/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1/devnull-sandbox-probe-r1`

It must be absent under a held, verified T5 parent before creation. It is a sibling of captures. The failed captures/before directory and its files are never opened or reused. No existing source, candidate receipt, QA directory member or production file is written.

The probe reuses the original pure capture_profile function. A local selected-function check reproduces the actual failed policy hash `de74f118ead7f9769dd12e692b116fc80aaaa5953d559c8f63b0f8c3125cf387`. For this new proof it replaces only the three fixed captures/before path references with the new owned root. The paired policies then differ by the one /dev/null read literal. The original four kernel-refusal checks retain their body except for their fixed owned-directory expression.

The parent verifies four existing public source files and three fixed public tools by full hashes; tools also retain all nine actual identity fields. These are the original entry, HeldT5, Commands, retained-child helper, sandbox-exec, diskutil and ps. It imports only the three ownership helpers. It does not import the capture library, SQLite, SDK or a consumer. The source-only candidate entry is not imported.

Before any new write the parent must hold the original 27 T5 anchor strings and accept one fixed owned diskutil result. It creates three directories and four files: this controller, two profiles and one small owned main-file sentinel. It verifies all four exact bytes after publication and again at the end. Old public source and tool observations must be identical before and after.

1. Under the original policy, a fresh os.open('/dev/null', O_RDONLY) must be refused with EACCES or EPERM. There is no inner diskutil attempt in this expected-refusal case.
2. Under the patched policy, the same open must succeed, refer to a character device, return EOF for a one-byte read and close. The child then executes fixed diskutil through the original Commands / retained-child lifecycle and checks the original held T5 anchor and UUID.
3. The patched child executes the original owned main-file write-open, owned WAL/SHM create and loopback-connect refusal checks. All four must still be refused with the existing EACCES/EPERM predicate. The sentinel must retain its exact bytes and identity; both sidecars must remain absent.

There is no current SQLite connection, credential-body read, provider request, production service change, launchd use, retry or business replay. The only attempted connection is the original fixed 127.0.0.1:9 negative sandbox check, with no application data.

## Deadline and closure

The two child cases and all parent work share one parent-start + 45-second absolute deadline. Child processes receive that original monotonic endpoint, never a fresh 45 seconds. Each diskutil limit is min(30 seconds, remaining). The same retained-child helper preserves TERM1 / wait5 / group3 / PS4 cleanup, no post-reap signal. Root-level supervision is 60 seconds for this separate proof.

Public pin reads have per-file and aggregate bounds; the reported byte counter counts the closed public_read set. Owned proof file reads are separately bounded by their exact fixed sizes and HeldT5 limits. No bound is a new allowance for production inputs.

Success requires both typed child reports, expected child exits, original deadlines, all FD / socket / T5 closures, all owned children reaped with empty groups, unchanged originals, final stdout and authoritative exit 0. A JSON candidate alone cannot qualify the proof. Unknown or failed results stop; the key and owned directory are not reused.

## Public diagnostics

The new probe records only a source-controlled error stage, exception type, bounded integer errno and fixed Refused code. It does not copy OSError message, filename, child stderr text or private data. This explicitly distinguishes direct /dev/null open from the later child diskutil launch / custody path. Typed unavailable or inconsistent child reports become unknown.

For a future capture-entry successor, the same safe diagnostic projection can be added at its fixed source-pin, held-anchor, diskutil, synthetic-proof, kernel-refusal, current-capture, publication and closure boundaries. That diagnostic integration and the next fresh consumer generation are separate source changes; this packet does not silently alter the other 17 R4 sources.

## Offline evidence and execution state

Three full Python sources were parsed and compiled without executing their modules. Selected pure functions proved the actual profile hash, exact one-literal delta, unchanged private / write / network rules and omission of a synthetic OSError message and filename. Only the AST-selected policy and diagnostic functions were executed; no tested ownership helper, actual socket, subprocess, physical host or database was exercised. The offline wrapper read and wrote its own /tmp source artifacts.

The exact proposed request is included. It has not been submitted. Source review is required before this one owned proof; a successful proof would not authorize current credentials, capture, launchd, cutover or production behavior.
