//go:build darwin && cgo

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
    "context"
    "errors"
    "io"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "golang.org/x/sys/unix"
)
type execCmd = exec.Cmd
type childReceipt struct {
    Started bool `json:"started"`
    PID int `json:"pid"`
    Birth string `json:"birth"`
    PGID int `json:"pgid"`
    SID int `json:"sid"`
    OriginalWait bool `json:"original_wait"`
    ExitCode int `json:"exit_code"`
    IdentityGap bool `json:"identity_gap"`
    SignalError bool `json:"signal_error"`
    Forced bool `json:"forced"`
    GroupRetired bool `json:"group_retired"`
    PinsUnchanged bool `json:"pins_unchanged"`
    AuditSelectorBound bool `json:"audit_selector_bound"`
    BootstrapBound bool `json:"bootstrap_bound"`
    Qualified bool `json:"qualified"`
}
type ownedRunner struct {
    cmd *exec.Cmd
    stdout, stderr io.ReadCloser
    pins []*pinnedFile
    private *privateDirectory
    socketDir string
    ctx context.Context
    gate net.Conn
    gateChild *os.File
    gateDeadline time.Time
    mu sync.Mutex
    started, entryReleased bool
    birth birthIdentity
    receipt childReceipt
    waitOnce sync.Once
    waitDone chan struct{}
    waitErr error
}
func validatePlatformDeployment(d deployment) error {
    if d.DarwinBootstrap == nil || d.DarwinBootstrap.Image == "" || d.DarwinBootstrap.ImageSHA256 == "" {
        return errors.New("Darwin requires an external operator-pinned bootstrap")
    }
    return nil
}
func newOwnedRunner(spec *exec.Cmd, d deployment, socketDir, ownedTemp string, ctx context.Context) (r *ownedRunner, err error) {
    if validatePlatformDeployment(d) != nil || len(socketDir) > 90 { return nil, errors.New("Darwin deployment boundary") }
    absolute, deadline, err := bootstrapDeadline(ctx)
    if err != nil { return nil, err }
    private, err := newPrivateDirectory(ownedTemp)
    if err != nil { return nil, err }
    r = &ownedRunner{ctx: ctx, socketDir: socketDir, private: private, gateDeadline: deadline,
        waitDone: make(chan struct{}), receipt: childReceipt{ExitCode: -999}}
    defer func() { if err != nil { r.releaseFiles() } }()
    hold := func(path, digest, name string, executable bool) (*pinnedFile, error) {
        original, e := pinFile(path, digest, executable)
        if e != nil { return nil, e }
        r.pins = append(r.pins, original)
        copy, e := private.copyPinned(original, name, executable)
        if e != nil { return nil, e }
        r.pins = append(r.pins, copy)
        return copy, nil
    }
    image, err := hold(d.Image, d.ImageSHA256, "provider", true)
    if err != nil { return r, err }
    bootstrap, err := hold(d.DarwinBootstrap.Image, d.DarwinBootstrap.ImageSHA256, "bootstrap", true)
    if err != nil { return r, err }
    // The bootstrap digest is supplied in the operator-pinned deployment.
    // No os.Executable/self-hash or request value creates bootstrap authority.
    files := []*os.File{image.file}
    aliases := map[string]string{}
    seen := map[string]bool{}
    for i, lib := range d.Libraries {
        if lib.Alias == "" || len(lib.Alias) > 128 || strings.ContainsAny(lib.Alias, "=,\x00\r\n") || seen[lib.Alias] {
            return r, errors.New("invalid library alias")
        }
        seen[lib.Alias] = true
        p, e := hold(lib.Path, lib.SHA256, "library-"+strconv.Itoa(i), false)
        if e != nil { return r, e }
        files = append(files, p.file)
        aliases[lib.Alias] = heldLibraryDescriptor(i)
    }
    args, err := providerArguments(d, aliases)
    if err != nil { return r, err }
    pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
    if err != nil { return r, err }
    unix.CloseOnExec(pair[0])
    unix.CloseOnExec(pair[1])
    parentFile := os.NewFile(uintptr(pair[0]), "original-bootstrap-parent")
    r.gateChild = os.NewFile(uintptr(pair[1]), "original-bootstrap-child")
    r.gate, err = net.FileConn(parentFile)
    parentFile.Close()
    if err != nil { return r, err }
    gateFD := 3 + len(files)
    files = append(files, r.gateChild)
    bootstrapArgs := []string{darwinBootstrapMarker, strconv.Itoa(gateFD), strconv.FormatInt(absolute, 10), image.path, d.ImageSHA256, d.Image}
    cmd := exec.Command(bootstrap.path, append(bootstrapArgs, args...)...)
    cmd.ExtraFiles = files
    cmd.Env = append([]string{}, spec.Env...)
    // go-plugin generated mTLS env is retained, host environment is skipped.
    // No request/ambient loader environment can compete with held aliases.
    for _, value := range cmd.Env {
        name := strings.SplitN(value, "=", 2)[0]
        if strings.HasPrefix(name, "DYLD_") || strings.HasPrefix(name, "LD_") { return r, errors.New("ambient Darwin loader environment") }
    }
    cmd.Env = append(cmd.Env, "TMPDIR="+ownedTemp, "BAO_PKCS11_ALIASES=")
    cmd.Stdin = nil
    cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
    r.cmd = cmd
    r.stdout, err = cmd.StdoutPipe()
    if err != nil { return r, err }
    r.stderr, err = cmd.StderrPipe()
    if err != nil { return r, err }
    return r, nil
}
func (r *ownedRunner) Start(ctx context.Context) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.started { return errors.New("already started") }
    if ctx.Err() != nil || r.ctx.Err() != nil { return errors.New("start deadline") }
    if !r.private.unchanged() { return errors.New("private image directory changed") }
    for _, p := range r.pins { if !p.unchanged() { return errors.New("image changed before entry") } }
    if ctx.Err() != nil || r.ctx.Err() != nil { return errors.New("original budget expired during pin verification") }
    if err := r.cmd.Start(); err != nil { return err }
    // Custody precedes gate/metadata observation. All later paths use this Cmd.
    r.started = true
    r.receipt.Started = true
    r.receipt.PID = r.cmd.Process.Pid
    r.gateChild.Close()
    r.gateChild = nil
    // Cancellation closes the inherited gate even while Start holds mu during
    // capture; the trusted bootstrap exits without entering a provider.
    go func() {
        select {
        case <-r.ctx.Done():
            r.gate.Close()
            _ = r.Kill(context.Background())
        case <-r.waitDone:
        }
    }()
    // Capture failure cannot enter arbitrary provider: closing this private
    // inherited gate makes the trusted pinned bootstrap exit by original budget.
    fail := func() error {
        r.receipt.IdentityGap = true
        r.gate.Close()
        return errors.New("Darwin original child capture")
    }
    if r.gate.SetDeadline(r.gateDeadline) != nil { return fail() }
    var ready [1]byte
    if _, err := io.ReadFull(r.gate, ready[:]); err != nil || ready[0] != 1 { return fail() }
    id, err := identity(r.cmd.Process.Pid)
    if err != nil || id.PPID != os.Getpid() || id.UID != uint32(os.Geteuid()) ||
        id.RUID != uint32(os.Getuid()) || id.PGID != id.PID || id.SID != id.PID { return fail() }
    r.birth = id
    r.receipt.Birth = strconv.FormatUint(id.Unique, 10)
    r.receipt.PGID, r.receipt.SID = id.PGID, id.SID
    r.receipt.AuditSelectorBound = true
    r.receipt.BootstrapBound = true
    if r.ctx.Err() != nil || ctx.Err() != nil { return fail() }
    if _, err := r.gate.Write([]byte{2}); err != nil { return fail() }
    r.entryReleased = true
    r.gate.Close()
    return nil
}
func (r *ownedRunner) Wait(context.Context) error {
    r.waitOnce.Do(func() {
        r.mu.Lock()
        started := r.started
        r.mu.Unlock()
        if started {
            r.waitErr = r.cmd.Wait()
            r.mu.Lock()
            r.receipt.OriginalWait = true
            if r.cmd.ProcessState != nil { r.receipt.ExitCode = r.cmd.ProcessState.ExitCode() }
            r.mu.Unlock()
        }
        close(r.waitDone)
    })
    <-r.waitDone
    return r.waitErr
}
func (r *ownedRunner) Kill(context.Context) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    if !r.started || r.receipt.OriginalWait { return nil }
    r.receipt.Forced = true
    if !r.entryReleased {
        // Bootstrap exits itself. No missing selector is replaced by PID kill.
        return r.gate.Close()
    }
    if !r.receipt.AuditSelectorBound {
        r.receipt.IdentityGap, r.receipt.SignalError = true, true
        return errors.New("original Darwin selector unavailable")
    }
    err := signalOriginal(r.birth)
    if err != nil {
        r.receipt.SignalError = true
        if errors.Is(err, syscall.ESTALE) || errors.Is(err, syscall.ESRCH) { r.receipt.IdentityGap = true }
    }
    return err
}
func (r *ownedRunner) retireGroup() bool {
    if r.birth.PID <= 0 { r.receipt.IdentityGap = true; return false }
    pids, err := ownedGroupMembers(r.birth.PGID)
    if err != nil { r.receipt.IdentityGap = true; return false }
    if len(pids) != 0 {
        // After original Wait a newly looked-up group member is not an
        // original held child. Its PID/group match cannot grant signal rights.
        // Surviving descendants/non-original members are always False; no
        // unowned member is signalled to manufacture a retired-group receipt.
        r.receipt.IdentityGap = true
        return false
    }
    left, err := ownedGroupMembers(r.birth.PGID)
    if err != nil { r.receipt.IdentityGap = true; return false }
    if len(left) != 0 { r.receipt.IdentityGap = true; return false }
    // Empty PGID observations cannot exclude an original descendant that
    // escaped via setsid(). No original kernel lineage/exit authority has
    // been proved for Darwin; do not turn this information lookup into a
    // GroupRetired/Qualified grant. SourceOnly remains unqualified.
    r.receipt.IdentityGap = true
    return false
}
func (r *ownedRunner) releaseFiles() {
    if r.gate != nil { r.gate.Close() }
    if r.gateChild != nil { r.gateChild.Close(); r.gateChild = nil }
    for _, p := range r.pins { p.file.Close() }
    if r.stdout != nil { r.stdout.Close() }
    if r.stderr != nil { r.stderr.Close() }
    if r.private != nil { r.private.close() }
}
func (r *ownedRunner) closeOriginal(graceful bool) childReceipt {
    defer r.releaseFiles()
    if r.cmd == nil { return r.receipt }
    r.mu.Lock()
    started := r.started
    r.mu.Unlock()
    if started {
        if !graceful { _ = r.Kill(context.Background()) }
        // Same original Wait, including Start/gate/capture failures.
        _ = r.Wait(context.Background())
    }
    r.mu.Lock()
    defer r.mu.Unlock()
    r.receipt.GroupRetired = started && r.retireGroup()
    r.receipt.PinsUnchanged = r.private != nil && r.private.unchanged()
    for _, p := range r.pins { if !p.unchanged() { r.receipt.PinsUnchanged = false } }
    r.receipt.Qualified = r.receipt.Started && r.receipt.BootstrapBound &&
        r.receipt.AuditSelectorBound && r.receipt.OriginalWait && r.receipt.ExitCode == 0 &&
        !r.receipt.IdentityGap && !r.receipt.SignalError && !r.receipt.Forced &&
        r.receipt.GroupRetired && r.receipt.PinsUnchanged
    return r.receipt
}
func (r *ownedRunner) Stdout() io.ReadCloser { return r.stdout }
func (r *ownedRunner) Stderr() io.ReadCloser { return r.stderr }
func (r *ownedRunner) ID() string {
    r.mu.Lock(); defer r.mu.Unlock()
    if !r.started { return "" }
    return strconv.Itoa(r.receipt.PID)
}
func (r *ownedRunner) Name() string { return "operator-pinned-openbao-KMS-Darwin" }
func (r *ownedRunner) Diagnose(context.Context) string { return "provider handshake failed" }
func (r *ownedRunner) PluginToHost(network, address string) (string, string, error) {
    if network != "unix" || filepath.Clean(address) != address ||
        !strings.HasPrefix(address, r.socketDir+"/") || len(address) >= 104 {
        return "", "", errors.New("unowned plugin IPC")
    }
    return network, address, nil
}
func (r *ownedRunner) HostToPlugin(network, address string) (string, string, error) {
    return r.PluginToHost(network, address)
}
func monotonicNanos() (int64, error) {
    var ts unix.Timespec
    if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil { return 0, err }
    if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 ||
        ts.Sec > (1<<63-1)/1_000_000_000 ||
        ts.Sec == (1<<63-1)/1_000_000_000 && ts.Nsec > (1<<63-1)%1_000_000_000 {
        return 0, errors.New("monotonic clock")
    }
    return ts.Sec*1_000_000_000 + ts.Nsec, nil
}
