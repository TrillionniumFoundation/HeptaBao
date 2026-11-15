//go:build darwin && cgo
// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main
import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"
    "golang.org/x/sys/unix"
)
// Externally sealed operator role, never request fields. Actual root/debugging
// permissions must be observed; these declarations cannot grant them.
type darwinRootDeployment struct {
    BrokerImage string `json:"broker_image"`
    BrokerImageSHA256 string `json:"broker_image_sha256"`
    CallerUID uint32 `json:"caller_uid"`
    GuestUID uint32 `json:"guest_uid"`
    GuestGID uint32 `json:"guest_gid"`
    EnvelopeRoot string `json:"envelope_root"`
    OwnedTemp string `json:"owned_temp"`
}
const darwinEnvelopeRoot = "/Volumes/T5/.hbk"
type rootEnvelope struct {
    ancestors []*os.File
    lock *os.File
    broker *pinnedFile
    guestUID, guestGID uint32
}
func onT5(path string) bool {
    return filepath.IsAbs(path) && filepath.Clean(path) == path &&
        strings.HasPrefix(path, "/Volumes/T5/") && !strings.ContainsAny(path, "\x00\r\n")
}
// The kernel may reject writes on a read-only mount before its ACL check.
// EROFS is accepted only with an independent live MNT_RDONLY observation on
// this same held ancestor FD. No pathname, caller field or unknown errno grants it.
func callerWriteDenied(fd int) bool {
    failure := unix.Faccessat(fd, ".", unix.W_OK, 0)
    return errors.Is(failure, syscall.EACCES) ||
        errors.Is(failure, syscall.EROFS) && readonlyMount(fd)
}
func sealedAncestors(path string) (held []*os.File, err error) {
    defer func() { if err != nil { for _, f := range held { f.Close() } } }()
    prefixes := []string{"/"}
    current := ""
    for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
        current += "/" + part; prefixes = append(prefixes, current)
    }
    for _, prefix := range prefixes {
        fd, failure := unix.Open(prefix, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
        if failure != nil { return held, failure }
        f := os.NewFile(uintptr(fd), prefix); held = append(held, f)
        st, failure := f.Stat()
        if failure != nil { return held, failure }
        raw, ok := st.Sys().(*syscall.Stat_t)
        if !ok || !st.IsDir() || raw.Uid != 0 || st.Mode().Perm()&0002 != 0 ||
            raw.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 { return held, errors.New("unsealed root ancestor") }
        if failure = ownershipEnabled(fd); failure != nil { return held, failure }
        // flags zero checks the real caller; EROFS needs the same held mount proof.
        if !callerWriteDenied(fd) { return held, errors.New("caller-writable root ancestor or failed access proof") }
    }
    return held, nil
}
func (e *rootEnvelope) unchanged() bool {
    if e == nil || e.broker == nil || !e.broker.unchanged() { return false }
    for _, f := range e.ancestors {
        st, err := f.Stat(); ps, pe := os.Lstat(f.Name())
        if err != nil || pe != nil || !os.SameFile(st, ps) || !st.IsDir() { return false }
        raw, ok := st.Sys().(*syscall.Stat_t)
        if !ok || raw.Uid != 0 || st.Mode().Perm()&0002 != 0 || ownershipEnabled(int(f.Fd())) != nil ||
            !callerWriteDenied(int(f.Fd())) { return false }
    }
    return true
}
func (e *rootEnvelope) close() {
    if e == nil { return }
    if e.broker != nil { e.broker.close() }
    if e.lock != nil { e.lock.Close() }
    for _, f := range e.ancestors { f.Close() }
}
func acquireRootEnvelope(d deployment, ownedTemp string) (e *rootEnvelope, err error) {
    grant := d.DarwinRoot
    if grant == nil || os.Geteuid() != 0 || os.Getuid() == 0 ||
        grant.CallerUID != uint32(os.Getuid()) || grant.GuestUID == 0 ||
        grant.GuestUID == grant.CallerUID || grant.GuestGID == 0 ||
        grant.EnvelopeRoot != darwinEnvelopeRoot || !onT5(grant.OwnedTemp) ||
        grant.OwnedTemp != ownedTemp || len(grant.EnvelopeRoot) > 60 { return nil, errors.New("Darwin root operator role unavailable") }
    e = &rootEnvelope{guestUID: grant.GuestUID, guestGID: grant.GuestGID}
    defer func() { if err != nil { e.close() } }()
    for _, path := range []string{grant.EnvelopeRoot, grant.OwnedTemp, filepath.Dir(grant.BrokerImage)} {
        if !onT5(path) { return e, errors.New("root envelope requires T5") }
        if path==grant.EnvelopeRoot || path==grant.OwnedTemp {
            st,failure:=os.Lstat(path)
            if failure!=nil || !st.IsDir() || st.Mode().Perm()!=0711 { return e,errors.New("root guest-search directory must be mode0711") }
        }
        held, failure := sealedAncestors(path)
        if failure != nil { return e, failure }
        e.ancestors = append(e.ancestors, held...)
    }
    actual, err := originalImagePath(os.Getpid())
    if err != nil || actual != grant.BrokerImage { return e, errors.New("external broker image binding") }
    e.broker, err = pinRootBroker(grant.BrokerImage, grant.BrokerImageSHA256)
    if err != nil { return e, err }
    lockPath := filepath.Join(grant.EnvelopeRoot, "uid-"+strconv.FormatUint(uint64(grant.GuestUID), 10)+".lock")
    fd, failure := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
    if errors.Is(failure, syscall.EEXIST) { fd, failure = unix.Open(lockPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) }
    if failure != nil { return e, failure }
    e.lock = os.NewFile(uintptr(fd), lockPath)
    st, failure := e.lock.Stat()
    if failure != nil { return e, failure }
    raw, ok := st.Sys().(*syscall.Stat_t)
    if !ok || !st.Mode().IsRegular() || raw.Uid != 0 || raw.Nlink != 1 || st.Mode().Perm() != 0600 { return e, errors.New("root UID lease owner") }
    if failure = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); failure != nil { return e, failure }
    if failure = guestAbsent(grant.GuestUID); failure != nil { return e, failure }
    if !e.unchanged() { return e, errors.New("root envelope changed") }
    return e, nil
}
func prepareGuestSocket(path string, uid, gid uint32) error {
    fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
    if err != nil { return err }; defer unix.Close(fd)
    var before, after unix.Stat_t
    if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Mode&07777 != 0700 { return errors.New("original plugin socket owner") }
    if unix.Fchown(fd, int(uid), int(gid)) != nil || unix.Fchmod(fd, 0700) != nil { return errors.New("guest socket ownership") }
    if unix.Fstatat(unix.AT_FDCWD, path, &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
        before.Dev != after.Dev || before.Ino != after.Ino { return errors.New("original plugin socket replaced") }
    return nil
}
func platformInvocationGuard() (func(), error) {
    // Before deployment/request IO, arm the original absolute budget. Failure
    // exits the root broker nonzero; proc_exit force-kills actual traced
    // PCHILDREN through proc_ref, never a numeric-PID kill fallback. No receipt
    // or successful original Wait is claimed if this backstop fires.
    absolute, err := strconv.ParseInt(os.Getenv("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS"), 10, 64)
    now, clockErr := monotonicNanos()
    if err != nil || clockErr != nil || absolute <= now || absolute-now > int64(time.Hour) ||
        os.Geteuid() != 0 || os.Getuid() == 0 { return nil, errors.New("original root deadline/identity") }
    timer := time.AfterFunc(time.Duration(absolute-now), func() { os.Exit(2) })
    return func() { timer.Stop() }, nil
}
func waitOriginalStop(ctx context.Context, pid int, expected *birthIdentity) error {
    tick := time.NewTicker(time.Millisecond); defer tick.Stop()
    for {
        event, status, err := originalEvent(pid)
        if err != nil { return err }
        if event == 1 {
            if !originalTraced(pid) { return errors.New("original trace unavailable") }
            if status==int(syscall.SIGTRAP) { return nil }
            // Normal bootstrap runtime signals must not deadlock pre-exec.
            if expected==nil || status<=0 { return errors.New("unexpected initial exec stop") }
            now,failure:=identity(pid)
            if failure!=nil || now!=*expected || continueOriginalSignal(pid,status)!=nil { return errors.New("original bootstrap signal gap") }
        }
        if event == 2 { return errors.New("original child exited before entry") }
        select { case <-ctx.Done(): return ctx.Err(); case <-tick.C: }
    }
}
