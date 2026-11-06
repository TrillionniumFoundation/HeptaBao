# Fixed ready-PID libproc successor — SOURCE only

## Original failure remains qualified and unresolved in its exact scope

R2 original mac/1a1afeed843-fc05-6cd7, stdout a7a080a2776800e25c1a55fe31d2b853b3de2b48 (15,809 B), authority 46658c20db6acfbd69df748277528554477313a6 and full actual tree 80235457cc3c2190e76f8c809347de281023dd22 remain unchanged. Root review e65caf0cf0e3447b50a205d1d6033796dfb75ad8 qualifies the original failure and new direct-helper UNKNOWN.

The reached facts are first current print (2,004 B, not running, runs 1, no PID, last exit 1), valid 640 B ready identity, and valid 4,816 B terminal at home_admission with child_absolute_deadline. The original child reported no same-birth admission and no T5 entry. These are fresh observations. They do not recover the old 2,276 B print, explain its exact parser rejection, rewrite R4, close the registered label, or qualify AuthBus.

The new R2 diagnostic then failed at current_ready_pid_first. Its explicit ps helper PID 87650 had no returned custody, was not reaped, had no complete group-empty proof, and remains UNKNOWN. Only its output streams closed. Second print, either complete ready-PID observation, and the final file/directory fences were not reached.

## Exact finite source diagnosis

Original mac_owned_unreaped_r1, blob 53cddd9243f9f890d9a1b9975b435280ff58ab77:

- capture_child lines 73–79 first obtains the one exact-PID ps row and checks row.ppid == os.getpid(), row.pgid == child.pid, and row.uid == os.geteuid().
- The shared code is owned_child_scope_mismatch. It does not identify which conjunct was false.
- The first exit_observation is later (line 83); the fast-exit/zombie handling is later still (lines 94–99). Short lifetime does not bypass the earlier scope check.
- stop_once_unreaped calls capture_child again when the initial owner is None before it can signal or reap under its normal ownership rules.

Original mac_owned_commands_r1, blob c102dfdc565484421bf7dbbb04b7c8b9e4cd5511:

- Lines 47–54 use start_new_session=True, register the row, then assign row.custody from capture_child.
- Lines 72–75 only serialize str(error) as errorCode for CommandRefused. A Refusal from the custody module therefore has errorType Refusal but a null initial errorCode.
- Cleanup at line 80 can call capture_child again. The actual later cleanupErrorCode was owned_child_scope_mismatch; it must not be backfilled as the unknown initial code.

The public record contains neither the failed PPID/PGID/UID tuple nor an initial custody record. It proves a rejection in the cleanup scope check, not which value was unequal, whether short lifetime caused it, or any permission/OS-root cause. No change to these original helpers, ownership predicates or cleanup protocol is proposed.

## Narrow successor

Only the explicit ready-PID ps operation is removed. It is replaced with fixed /usr/lib/libproc.dylib proc_pidinfo, flavor 3, arg 1, for the already validated ready PID. The unchanged ProcessReader initializes the ctypes function declaration. Two additional self-only calls cross-check local ABI layout and basic self PID/PPID/PGID/UID plus birth before any target sample.

The original two launchctl print calls still use original Commands and its internal custody ps calls. This proposal does not remove or repair those internal checks, does not guarantee they cannot refuse, and cannot close helper 87650.

All original filesystem inputs, full9/SHA gates, dynamic public-leaf validators, 11 print error codes, signals, FixedIO once-close, helper unknown aggregation and final fences remain. Parent deadline 45 seconds, helper admission at 35 seconds, outer 60 seconds and original direct-owner 1/5/3/ps4 bounds remain. Each ready-PID observation now uses one explicit four-second absolute deadline for all its C calls, clipped to the existing helper-admission cutoff. No retry, sleep, group scan or process path lookup is added. Six full 136-byte returns at most add a bounded numeric return domain of 816 bytes; no application-file cap is raised.

The diagnostic does not query PID 87650. The ready PID is obtained again only from the same already-created ready record after the unchanged exact schema, fixed source/plan/home and process-shape gates. No hardcoded later PID is guessed.

## Official-source boundary

Four exact Apple files at xnu commit f6217f891ac0bb64f3d375211650a4c1ff8ca1ea are preserved with original Git fetch SDKs and whole hashes. Their URLs and filenames are in CONTRACT.public.json.

libproc.c lines 101–109 declare the wrapper's observable contract: __proc_info failure -1 is converted to return 0; errno is captured immediately by the candidate. proc_info.h lines 729–730 define flavor 3 and full struct size; libproc.h line 96 declares uint64_t arg. The candidate keeps the original full struct and validates size 136 and the exact numeric offsets before its self check.

Kernel proc_info.c lines 2166–2182 request the zombie lookup branch for the BSD-info flavor when arg is nonzero, and return ESRCH if both regular and requested zombie lookup miss. The file also contains policy/error paths, including proc_security_policy at 2210–2213. The wrapper's return convention does not turn every ESRCH on an unknown installed kernel into an unconditional lifetime/absence proof.

Accordingly, count 0 / errno ESRCH is published only as lookup_esrch. Two such samples have originalBirthPresent=null and existenceOrDepartureAutomaticallyConcluded=false. The report carries a separate readyPidLibprocEsrchObservedTwice fact and leaves registrationClosureClaimed=false and all historical UNKNOWNs intact. A different validated birth may be reported as reused_different_birth, but no such PID is owned or signalled.

The exact official commit is API/ABI reference material, not the installed Darwin kernel's whole identity. A successful self cross-check would establish only the actual local size/offset/returned-length/basic-identity behavior during that new run. It would not establish a zombie branch executed, kernel-file hash, all permission policies, or the managed registration's closure.

## Concrete admission and outputs

New request uses stdin (not stdin_text), the same fixed regular Python executable, args, cwd and timeout, and a new SOURCE-bound key. Journal changes only its slot, exact request pin and observer key prefix. It has not been initialized, armed or submitted.

The original failed R2 slot and all SDKs are preserved. The existing R4 registration and old AuthBus EX_CONFIG registration remain untouched. No bootstrap, bootout, managed signalling/reaping, admission file, T5 I/O, private capsule, credential, SDK/factory, provider/model/refresh/quota or product operation is authorized by this source package.

V8 verification in this package checks whole/source/request bindings and strict mechanical differences only. It does not execute Python, libproc, the diagnostic, old component harnesses or any Native operation. A future actual observation must still follow a separate exact root GO and close its own original observers. Parent exit 0 would qualify only a complete bounded fresh observation plus its own closure; it would not close PID 87650 or rewrite R4.
