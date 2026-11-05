# Exact Apple source basis and executable contract

All source files listed below are preserved byte-for-byte under references/apple with their original headers. source-pins.public.json gives repository, exact commit, public retrieval URL, SHA256 and Git blob for every file.

The XNU reference is apple-oss-distributions/xnu at f6217f891ac0bb64f3d375211650a4c1ff8ca1ea. The dynamic-loader header reference is apple-oss-distributions/dyld at fd8d0c4d52320ebf64db34f3cb280310d905c5ae. These are explicit reference commits, not an assertion that the installed Mac kernel or libraries are built from them.

| Source | Relevant contract | Probe consequence |
|---|---|---|
| xnu/bsd/sys/proc_info.h | PROC_PGRP_ONLY is 2; PROC_PIDTBSDINFO is 3; proc_bsdinfo has fixed integer fields, 16/32-byte names and two 64-bit birth fields. | Declare all 22 fields explicitly; require 136 bytes, alignment 8 and every expected offset before any query. Never publish name buffers. |
| xnu/bsd/sys/_types.h, _types/_uid_t.h, _types/_gid_t.h and param.h | PID is signed 32-bit, UID/GID unsigned 32-bit, MAXCOMLEN is 16. | Use explicit ctypes widths and reject malformed positive PID/PGID or birth fields. |
| xnu/bsd/sys/proc.h | SIDL, SRUN, SSLEEP, SSTOP and SZOMB are 1 through 5. | Preserve a separate numeric state schema. Do not disguise it as ps lstart/state output. |
| xnu/libsyscall/wrappers/libproc/libproc.h and libproc.c | proc_listpids/proc_pidinfo return byte counts; the wrappers translate syscall -1 into 0 while retaining errno. | Clear errno immediately before each call, require complete pidinfo bytes, and distinguish an empty group from a zero-with-error refusal. |
| xnu/bsd/kern/proc_info.c, proc_listpids | Group filtering uses p_pgrpid; a null-buffer sizing request is based on the host process count, and a supplied buffer can fill before enumeration ends. | Use only PROC_PGRP_ONLY with an actual retained PGID, one fixed 65-integer buffer, and at most 64 members. Reject saturation rather than resizing, retrying or listing the host. |
| xnu/bsd/kern/proc_info.c, proc_pidinfo | For PROC_PIDTBSDINFO, a nonzero arg enables lookup of a retained zombie. A short buffer is rejected; permission checks and process lookup can fail. | Always pass argument 1 for this flavor, require all 136 returned bytes, and reject ESRCH or any other incomplete/error result rather than treating it as process absence. |
| xnu/bsd/kern/proc_info.c, proc_pidbsdinfo | Status, parent, credential UID and p_start seconds/microseconds populate the result. Group/session-related fields are populated only when the session exists. | Compare full numeric birth and direct-parent/PGID/UID identity. If an actual retained zombie has no valid PGID, fail closed; do not infer it from the requested PID. |
| xnu/libsyscall/Libsyscall.xcodeproj/project.pbxproj and Libsyscall.xcconfig | libproc.c is part of the libsystem_kernel build; the install path/product establish /usr/lib/system/libsystem_kernel.dylib. | Request that fixed install name. This reference build configuration is not an installed whole-binary proof. |
| xnu/bsd/sys/sysctl.h | sysctlbyname has the declared pointer/size_t signature; KERN_OSVERSION describes the OS build. | Query only kern.osversion into a fixed 128-byte buffer and require a complete bounded NUL-terminated build identifier. |
| dyld/include/dlfcn.h | Dl_info contains four pointer fields; dladdr reports an image and symbol for an address. | Require a 32-byte, four-pointer layout and record only bounded system image paths/symbol names for the four fixed APIs. No addresses or whole-image hashes are published. |

Primary URLs use the exact commit, for example:
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c
- https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/include/dlfcn.h

## Preserved custody and finite observation

The native adapter replaces only process projection in an isolated module. The original QA helper remains untouched. Both implementations retain a real direct Popen child using waitid(WNOWAIT), verify birth/parent/group/UID before a group signal, repeat the ownership observation immediately before each signal, and wait until the live group is empty before the first reap. After reap there is observation only. No numeric PID or PGID acquired after custody loss grants signal authority.

A group view requires two identical filtered PID sets with complete per-PID numeric rows between them. This is a finite sequence of observations, not an atomic process-table snapshot. The retained direct child prevents its own PID/group-leader number from being reused during the signal-bearing period. Group membership drift, foreign UID, returned-PID mismatch or incomplete metadata is a refusal.

The original TERM1/wait5/group3 cleanup bounds are retained. Each projection is clipped to the existing stage deadline and a 4-second maximum; the complete actual probe still requires its original shared 45-second deadline after closure. Native calls are synchronous, so a late return can only be rejected after control returns. No detached worker, thread, signal retry, deadline extension or alternate library is introduced.

## Actual qualification boundary

The actual probe will record Darwin release/version/machine, the kern.osversion build, the fixed install names and bounded dladdr observations. Before any native-owned child it must match self PID/PPID/PGID/UID against independent os calls and keep the same second/microsecond birth across observations. A fixed ctypes layout alone cannot prove the installed kernel follows the reference ABI; full-return and behavioral gates are required.

If a library is served from the dyld shared cache, the probe neither materializes it nor invents a regular-file whole hash. It does not claim the complete dynamic-library dependency closure. Permission refusal, a missing symbol, a changed ABI, a short return or a zero PGID remain explicit failures. None permits a mainline helper replacement or a current-credential run.
