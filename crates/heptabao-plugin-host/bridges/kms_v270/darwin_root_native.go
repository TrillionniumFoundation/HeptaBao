//go:build darwin && cgo
// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main
/*
#cgo LDFLAGS: -lproc -lsandbox
#include <errno.h>
#include "darwin_sandbox_spi.h"
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
static int hbp_child_event(int pid, int *event, int *status) {
    siginfo_t si = {0};
    // Original parent's child list only; never reap a stop or exit here.
    if (waitid(P_PID, (id_t)pid, &si, WSTOPPED|WEXITED|WNOWAIT|WNOHANG)) return errno;
    *event = 0; *status = 0;
    if (!si.si_pid) return 0;
    if (si.si_pid != pid) return ECHILD;
    if (si.si_code == CLD_STOPPED) { *event = 1; *status = si.si_status; return 0; }
    if (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED) {
        *event = 2; *status = si.si_status; return 0;
    }
    return EIO;
}
static int hbp_trace_continue(int pid,int signal) {
    // Original Cmd is unreaped. XNU checks P_LTRACED, actual p_pptr == caller,
    // and SSTOP while holding the original proc. This never signals by PID.
    return ptrace(PT_CONTINUE, pid, (caddr_t)1, signal) ? errno : 0;
}
static int hbp_traced(int pid) {
    struct proc_bsdinfo b = {0};
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != sizeof(b))
        return errno ? -errno : -EIO;
    return b.pbi_ppid == getpid() && (b.pbi_flags & PROC_FLAG_TRACED) != 0;
}
static int hbp_task_capture(int pid, int version, unsigned uid, uint32_t *out) {
    task_t port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &port);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(port)) return EPERM;
    audit_token_t info = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kr = task_info(port, TASK_AUDIT_TOKEN, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT ||
        info.val[5] != (uint32_t)pid || info.val[7] != (uint32_t)version ||
        info.val[1] != uid || info.val[3] != uid) {
        mach_port_deallocate(mach_task_self(), port); return ESTALE;
    }
    // The kernel-granted TASK_CONTROL right is authority. Public token fields
    // only identify it; no locally manufactured audit token grants anything.
    *out = port; return 0;
}
static void hbp_task_release(uint32_t port) {
    if (MACH_PORT_VALID(port)) mach_port_deallocate(mach_task_self(), port);
}
static int hbp_fork_barrier(void) {
    if (getuid() == 0 || geteuid() != getuid()) return EPERM;
    struct rlimit limit = {1, 1}, observed = {0};
    if (setrlimit(RLIMIT_NPROC, &limit) || getrlimit(RLIMIT_NPROC, &observed)) return errno;
    if (observed.rlim_cur != 1 || observed.rlim_max != 1) return EIO;
    return 0;
}
static int hbp_exec_barrier(const char *provider) {
    char *error = NULL;
    sandbox_params_t params = sandbox_create_params();
    if (!params) return ENOMEM;
    if (sandbox_set_param(params,"PROVIDER",provider)) { sandbox_free_params(params); return EINVAL; }
    // Fixed bootstrap source, external operator-pin provenance. Only this one
    // root-sealed pathname may exec. Root unlinks it at the expected exec stop.
    const char *source = "(version 1)\n(allow default)\n(deny process-fork)\n"
        "(deny file-write* (require-not (subpath \"/Volumes/T5\")))\n"
        "(deny process-exec (require-not (literal (param \"PROVIDER\"))))\n";
    sandbox_profile_t profile = sandbox_compile_string(source,params,&error);
    if (!profile) {
        sandbox_free_params(params); if (error) sandbox_free_error(error); return EINVAL;
    }
    int rc = sandbox_apply(profile);
    sandbox_free_profile(profile); sandbox_free_params(params);
    if (error) sandbox_free_error(error);
    return rc == 0 ? 0 : EPERM;
}
static int hbp_mount_owner(int fd) {
    struct statfs fs = {0};
    if (fstatfs(fd, &fs)) return errno;
    return fs.f_flags & MNT_IGNORE_OWNERSHIP ? EPERM : 0;
}
static int hbp_guest_empty(unsigned uid) {
    int pids[2] = {0};
    errno = 0;
    int n = proc_listpids(PROC_UID_ONLY, uid, pids, sizeof(pids));
    if (n < 0 || (n == 0 && errno)) return errno ? errno : EIO;
    if (n != 0) return EBUSY;
    errno = 0;
    n = proc_listpids(PROC_RUID_ONLY, uid, pids, sizeof(pids));
    if (n < 0 || (n == 0 && errno)) return errno ? errno : EIO;
    return n == 0 ? 0 : EBUSY;
}
static int hbp_fd_path(int fd,char *out) { return fcntl(fd,F_GETPATH,out) ? errno : 0; }
static int hbp_image_path(int pid, char *out, int capacity) {
    errno = 0;
    return proc_pidpath(pid, out, capacity) > 0 ? 0 : (errno ? errno : EIO);
}
*/
import "C"
import ("errors"; "syscall"; "unsafe")
type taskControl uint32
func originalEvent(pid int) (int, int, error) {
    var event, status C.int
    if e := C.hbp_child_event(C.int(pid), &event, &status); e != 0 { return 0, 0, syscall.Errno(e) }
    return int(event), int(status), nil
}
func continueOriginal(pid int) error { return continueOriginalSignal(pid,0) }
func continueOriginalSignal(pid,signal int) error {
    if e := C.hbp_trace_continue(C.int(pid),C.int(signal)); e != 0 { return syscall.Errno(e) }; return nil
}
func originalTraced(pid int) bool { return C.hbp_traced(C.int(pid)) == 1 }
func captureTask(id birthIdentity) (taskControl, error) {
    var port C.uint32_t
    if e := C.hbp_task_capture(C.int(id.PID), C.int(id.Version), C.uint(id.UID), &port); e != 0 {
        return 0, syscall.Errno(e)
    }
    now, err := identity(id.PID)
    if err != nil || now != id || !originalTraced(id.PID) {
        C.hbp_task_release(port); return 0, errors.New("original stopped task changed")
    }
    return taskControl(port), nil
}
func (p taskControl) release() { C.hbp_task_release(C.uint32_t(p)) }
func installForkBarrier() error {
    if e := C.hbp_fork_barrier(); e != 0 { return syscall.Errno(e) }; return nil
}
func ownershipEnabled(fd int) error {
    if e := C.hbp_mount_owner(C.int(fd)); e != 0 { return syscall.Errno(e) }; return nil
}
func guestAbsent(uid uint32) error {
    if e := C.hbp_guest_empty(C.uint(uid)); e != 0 { return syscall.Errno(e) }; return nil
}
func originalImagePath(pid int) (string, error) {
    var b [4096]C.char
    if e := C.hbp_image_path(C.int(pid), &b[0], C.int(len(b))); e != 0 { return "", syscall.Errno(e) }
    return C.GoString(&b[0]), nil
}

func originalFDPath(fd int) (string,error) {
    var b [4096]C.char
    if e:=C.hbp_fd_path(C.int(fd),&b[0]); e!=0 { return "",syscall.Errno(e) }; return C.GoString(&b[0]),nil
}

func installExecBarrier(path string) error {
    p:=C.CString(path); defer C.free(unsafe.Pointer(p))
    if e:=C.hbp_exec_barrier(p); e!=0 { return syscall.Errno(e) }; return nil
}
