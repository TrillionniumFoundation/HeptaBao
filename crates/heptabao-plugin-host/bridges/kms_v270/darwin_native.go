//go:build darwin && cgo

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <mach/message.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <unistd.h>

// Apple xnu proc_info_private.h: public ABI flavor 18, private SDK declaration.
// Kept local so an unavailable private header is never guessed by a compiler.
struct hbp_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    int32_t p_idversion;
    int32_t p_orig_ppidversion;
    uint64_t p_reserve2;
    uint64_t p_reserve3;
};
_Static_assert(sizeof(struct hbp_uniqidentifierinfo) == 56, "Apple unique identity ABI");
struct hbp_bsdinfowithuniqid {
    struct proc_bsdinfo pbsd;
    struct hbp_uniqidentifierinfo uniq;
};
struct hbp_identity {
    int32_t pid, ppid, pgid, sid;
    uint32_t uid, ruid;
    uint64_t uniqueid, start_sec, start_usec;
    int32_t idversion;
};
static int hbp_capture(int pid, struct hbp_identity *out) {
    struct hbp_bsdinfowithuniqid info = {0};
    errno = 0;
    if (pid <= 0 || out == NULL) return EINVAL;
    int n = proc_pidinfo(pid, 18, 0, &info, sizeof(info));
    if (n != sizeof(info)) return errno ? errno : EIO;
    errno = 0;
    pid_t sid = getsid(pid);
    if (sid <= 0) return errno ? errno : EIO;
    if (info.pbsd.pbi_pid != pid || !info.uniq.p_uniqueid ||
        info.pbsd.pbi_start_tvusec >= 1000000) return EIO;
    *out = (struct hbp_identity){
        .pid = pid, .ppid = info.pbsd.pbi_ppid, .pgid = info.pbsd.pbi_pgid,
        .sid = sid, .uid = info.pbsd.pbi_uid, .ruid = info.pbsd.pbi_ruid,
        .uniqueid = info.uniq.p_uniqueid, .idversion = info.uniq.p_idversion,
        .start_sec = info.pbsd.pbi_start_tvsec, .start_usec = info.pbsd.pbi_start_tvusec
    };
    return 0;
}
static int hbp_signal_original(const struct hbp_identity *birth) {
    if (birth == NULL || birth->pid <= 0 || !birth->uniqueid) return EINVAL;
    struct hbp_identity now = {0};
    int e = hbp_capture(birth->pid, &now);
    if (e) return e;
    // Exec changes pidversion and Mach task, but preserves process uniqueid.
    // The observed full original birth/group/owner identity must still match.
    if (now.uniqueid != birth->uniqueid || now.start_sec != birth->start_sec ||
        now.start_usec != birth->start_usec || now.uid != birth->uid ||
        now.ruid != birth->ruid || now.ppid != birth->ppid ||
        now.pgid != birth->pgid || now.sid != birth->sid)
        return ESTALE;
    // This is a publicly observable, forgeable identity SELECTOR, never a grant.
    // Apple only reads pid/version to identify the process and independently
    // checks current-caller MAC policy and cansignal credentials in kernel.
    audit_token_t selector = {{0}};
    selector.val[5] = (uint32_t)now.pid;
    selector.val[7] = (uint32_t)now.idversion;
    // No kill(pid), killpg, Process.Kill or numeric-only fallback exists.
    return proc_signal_with_audittoken(&selector, SIGKILL);
}
static int hbp_group_members(int pgid, int *pids, int capacity) {
    if (pgid <= 0 || capacity <= 0) return -EINVAL;
    errno = 0;
    int n = proc_listpgrppids(pgid, pids, capacity * sizeof(int));
    if (n < 0 || n == 0 && errno != 0) return -(errno ? errno : EIO);
    if (n % sizeof(int) || n >= capacity * sizeof(int)) return -EOVERFLOW;
    return n / sizeof(int);
}
*/
import "C"

import (
    "errors"
    "syscall"
)

type birthIdentity struct {
    PID, PPID, PGID, SID int
    UID, RUID uint32
    Unique, StartSec, StartUsec uint64
    Version int32
}
func identity(pid int) (birthIdentity, error) {
    var native C.struct_hbp_identity
    if e := C.hbp_capture(C.int(pid), &native); e != 0 {
        return birthIdentity{}, syscall.Errno(e)
    }
    return birthIdentity{PID: int(native.pid), PPID: int(native.ppid), PGID: int(native.pgid),
        SID: int(native.sid), UID: uint32(native.uid), RUID: uint32(native.ruid),
        Unique: uint64(native.uniqueid), StartSec: uint64(native.start_sec),
        StartUsec: uint64(native.start_usec), Version: int32(native.idversion)}, nil
}
func signalOriginal(id birthIdentity) error {
    native := C.struct_hbp_identity{pid: C.int32_t(id.PID), ppid: C.int32_t(id.PPID),
        pgid: C.int32_t(id.PGID), sid: C.int32_t(id.SID), uid: C.uint32_t(id.UID),
        ruid: C.uint32_t(id.RUID), uniqueid: C.uint64_t(id.Unique),
        start_sec: C.uint64_t(id.StartSec), start_usec: C.uint64_t(id.StartUsec),
        idversion: C.int32_t(id.Version)}
    if e := C.hbp_signal_original(&native); e != 0 { return syscall.Errno(e) }
    return nil
}
func ownedGroupMembers(pgid int) ([]int, error) {
    // A full buffer is a gap, never an empty/retired group.
    var pids [65536]C.int
    n := C.hbp_group_members(C.int(pgid), &pids[0], C.int(len(pids)))
    if n < 0 { return nil, syscall.Errno(-n) }
    out := make([]int, int(n))
    for i := range out {
        out[i] = int(pids[i])
        if out[i] <= 0 { return nil, errors.New("invalid native group identity") }
    }
    return out, nil
}
