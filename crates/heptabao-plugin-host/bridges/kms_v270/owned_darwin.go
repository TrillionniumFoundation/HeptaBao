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
    SandboxBound bool `json:"sandbox_bound"`
    TaskControlBound bool `json:"task_control_bound"`
    TraceBound bool `json:"trace_bound"`
    RootEnvelopeBound bool `json:"root_envelope_bound"`
    ForkLimitBound bool `json:"fork_limit_bound"`
    Qualified bool `json:"qualified"`
}
type ownedRunner struct {
    cmd *exec.Cmd
    stdout, stderr io.ReadCloser
    pins []*pinnedFile
    private *privateDirectory
    root *rootEnvelope
    task taskControl
    imagePath, bootstrapPath string
    image *pinnedFile
    socketDir string
    ctx context.Context
    gate net.Conn
    gateChild *os.File
    gateDeadline time.Time
    mu sync.Mutex
    started, entryReleased bool
    birth birthIdentity
    receipt childReceipt
    releaseOnce sync.Once
    providerCloseRequired, providerCloseOK bool
    waitOnce sync.Once
    waitDone chan struct{}
    waitErr error
}
func validatePlatformDeployment(d deployment) error {
    if d.DarwinBootstrap == nil || d.DarwinBootstrap.Image == "" || d.DarwinBootstrap.ImageSHA256 == "" ||
        d.DarwinRoot == nil { return errors.New("Darwin requires external bootstrap and root-envelope deployment") }
    return nil
}
func newOwnedRunner(spec *exec.Cmd, d deployment, socketDir, ownedTemp string, ctx context.Context) (r *ownedRunner, err error) {
    if validatePlatformDeployment(d) != nil || len(socketDir) > 90 { return nil, errors.New("Darwin deployment boundary") }
    absolute, deadline, err := bootstrapDeadline(ctx)
    if err != nil { return nil, err }
    root, err := acquireRootEnvelope(d, ownedTemp)
    if err != nil { return nil, err }
    r = &ownedRunner{ctx:ctx, socketDir:socketDir, root:root, gateDeadline:deadline,
        waitDone:make(chan struct{}), receipt:childReceipt{ExitCode:-999}}
    defer func() { if err != nil { r.releaseFiles() } }()
    r.private, err = newPrivateDirectory(d.DarwinRoot.EnvelopeRoot)
    if err != nil { return r, err }
    r.private.guestGID = root.guestGID
    hold := func(path, digest, name string, executable bool) (*pinnedFile, error) {
        original, failure := pinFile(path, digest, executable)
        if failure != nil { return nil, failure }
        r.pins = append(r.pins, original)
        copy, failure := r.private.copyPinned(original, name, executable)
        if failure != nil { return nil, failure }
        r.pins = append(r.pins, copy)
        return copy, nil
    }
    image, err := hold(d.Image, d.ImageSHA256, "provider", true)
    if err != nil { return r, err }
    bootstrap, err := hold(d.DarwinBootstrap.Image, d.DarwinBootstrap.ImageSHA256, "bootstrap", true)
    if err != nil { return r, err }
    r.imagePath, r.bootstrapPath = image.path, bootstrap.path
    r.image=image
    files := []*os.File{image.file}
    aliases := map[string]string{}
    seen := map[string]bool{}
    for i, lib := range d.Libraries {
        if lib.Alias == "" || len(lib.Alias)>128 || strings.ContainsAny(lib.Alias,"=,\x00\r\n") || seen[lib.Alias] { return r, errors.New("invalid library alias") }
        seen[lib.Alias] = true
        p, failure := hold(lib.Path, lib.SHA256, "library-"+strconv.Itoa(i), false)
        if failure != nil { return r, failure }
        files = append(files,p.file); aliases[lib.Alias] = heldLibraryDescriptor(i)
    }
    args, err := providerArguments(d,aliases)
    if err != nil { return r,err }
    pair, err := unix.Socketpair(unix.AF_UNIX,unix.SOCK_STREAM,0)
    if err != nil { return r,err }
    unix.CloseOnExec(pair[0]); unix.CloseOnExec(pair[1])
    parent := os.NewFile(uintptr(pair[0]),"original-bootstrap-parent")
    r.gateChild = os.NewFile(uintptr(pair[1]),"original-bootstrap-child")
    r.gate,err = net.FileConn(parent); parent.Close()
    if err != nil { return r,err }
    gateFD := 3+len(files); files=append(files,r.gateChild)
    bootstrapArgs := []string{darwinBootstrapMarker,strconv.Itoa(gateFD),strconv.FormatInt(absolute,10),image.path,d.ImageSHA256,d.Image}
    cmd := exec.Command(bootstrap.path,append(bootstrapArgs,args...)...)
    cmd.ExtraFiles=files; cmd.Env=append([]string{},spec.Env...)
    for _, value := range cmd.Env {
        name:=strings.SplitN(value,"=",2)[0]
        if strings.HasPrefix(name,"DYLD_") || strings.HasPrefix(name,"LD_") { return r,errors.New("ambient Darwin loader environment") }
    }
    cmd.Env=append(cmd.Env,"TMPDIR="+socketDir,"BAO_PKCS11_ALIASES=")
    cmd.Stdin=nil
    // TRACE_ME precedes credential drop in frozen Go exec_libc2. Kernel exec
    // SIGTRAP stops both images before user entry. Root role and MAC permission
    // are actually checked; no declaration substitutes for a successful stop.
    cmd.SysProcAttr=&syscall.SysProcAttr{Ptrace:true,Setsid:true,
        Credential:&syscall.Credential{Uid:root.guestUID,Gid:root.guestGID,Groups:[]uint32{}}}
    r.cmd=cmd
    r.stdout,err=cmd.StdoutPipe(); if err!=nil { return r,err }
    r.stderr,err=cmd.StderrPipe(); if err!=nil { return r,err }
    if err=r.private.allowGuest(); err!=nil { return r,err }
    if err=prepareGuestSocket(socketDir,root.guestUID,root.guestGID); err!=nil { return r,err }
    return r,nil
}
func sameOriginalProcess(a,b birthIdentity) bool {
    // Only the one expected bootstrap -> provider exec may change version.
    a.Version=0; b.Version=0
    return a==b
}
func (r *ownedRunner) Start(ctx context.Context) error {
    r.mu.Lock(); defer r.mu.Unlock()
    if r.started { return errors.New("already started") }
    if ctx.Err()!=nil || r.ctx.Err()!=nil || !r.root.unchanged() || !r.private.unchanged() { return errors.New("Darwin original entry boundary") }
    for _,p:=range r.pins { if !p.unchanged() { return errors.New("image changed before entry") } }
    if ctx.Err()!=nil || r.ctx.Err()!=nil { return errors.New("original budget expired during pins") }
    if err:=r.cmd.Start(); err!=nil { return err }
    r.started=true; r.receipt.Started=true; r.receipt.PID=r.cmd.Process.Pid
    r.gateChild.Close(); r.gateChild=nil
    fail:=func() error {
        r.receipt.IdentityGap=true; r.receipt.Forced=true
        r.gate.Close()
        return errors.New("Darwin original entry capture")
    }
    // No provider code has run at the first stop. The original Cmd is retained
    // on every subsequent failure. Root deadline backstop covers failed native
    // observations before a usable task/selector exists.
    if waitOriginalStop(r.ctx,r.receipt.PID,nil)!=nil { return fail() }
    first,err:=identity(r.receipt.PID)
    path,pathErr:=originalImagePath(r.receipt.PID)
    if err!=nil || pathErr!=nil || path!=r.bootstrapPath || first.PPID!=os.Getpid() ||
        first.UID!=r.root.guestUID || first.RUID!=r.root.guestUID ||
        first.PGID!=first.PID || first.SID!=first.PID { return fail() }
    r.birth=first
    r.receipt.Birth=strconv.FormatUint(first.Unique,10)
    r.receipt.PGID,r.receipt.SID=first.PGID,first.SID
    r.receipt.AuditSelectorBound=true; r.receipt.TraceBound=true
    if continueOriginal(first.PID)!=nil { return fail() }
    if r.gate.SetDeadline(r.gateDeadline)!=nil { return fail() }
    if r.awaitBootstrapReady(first)!=nil { return fail() }
    r.receipt.BootstrapBound=true; r.receipt.ForkLimitBound=true; r.receipt.SandboxBound=true
    if ctx.Err()!=nil || r.ctx.Err()!=nil { return fail() }
    if _,err=r.gate.Write([]byte{2}); err!=nil { return fail() }
    if waitOriginalStop(r.ctx,first.PID,&first)!=nil { return fail() }
    provider,err:=identity(first.PID)
    path,pathErr=originalImagePath(first.PID)
    if err!=nil || pathErr!=nil || path!=r.imagePath || !sameOriginalProcess(first,provider) ||
        provider.Version==first.Version { return fail() }
    r.birth=provider
    r.task,err=captureTask(provider)
    if err!=nil { return fail() }
    r.receipt.TaskControlBound=true
    // The only sandbox-allowed exec pathname is unlinked through the held
    // original directory before provider entry; the original image FD lives.
    // With no guest search permission, it cannot be rebuilt or entered again.
    // The installed sandbox denies every other exec pathname. Any observed
    // unexpected exec/version gap makes this invocation False; the actual
    // trace remains attached forever.
    if r.image.retireOriginalPath(r.private)!=nil || r.private.sealGuest()!=nil || !r.root.unchanged() { return fail() }
    r.receipt.RootEnvelopeBound=true
    if ctx.Err()!=nil || r.ctx.Err()!=nil || continueOriginal(provider.PID)!=nil { return fail() }
    r.entryReleased=true; r.gate.Close()
    return nil
}
func (r *ownedRunner) Wait(context.Context) error {
    r.waitOnce.Do(func() {
        r.mu.Lock(); started:=r.started; pid:=r.receipt.PID; r.mu.Unlock()
        if started {
            tick:=time.NewTicker(time.Millisecond); defer tick.Stop()
            cancelled:=r.ctx.Done()
            for {
                // A traced wait4 can report SSTOP even without WUNTRACED.
                // Sole observer waits non-reapingly for WEXITED before Cmd.Wait.
                event,status,err:=originalEvent(pid)
                if err!=nil {
                    r.mu.Lock(); r.receipt.IdentityGap=true; r.receipt.Forced=true; r.receipt.SignalError=true; r.mu.Unlock()
                    os.Exit(2)
                }
                if event==1 {
                    // Go's SIGURG preemption and ordinary signals also trace.
                    // Forward only while exact original birth/version and
                    // parent trace still match. No exec/version gap is resumed.
                    now, failure:=identity(pid)
                    r.mu.Lock(); expected:=r.birth; released:=r.entryReleased; r.mu.Unlock()
                    if failure!=nil || !released || now!=expected || !originalTraced(pid) ||
                        status==int(syscall.SIGTRAP) || status<=0 ||
                        continueOriginalSignal(pid,status)!=nil {
                        r.mu.Lock();r.receipt.IdentityGap=true;r.receipt.Forced=true;r.mu.Unlock()
                        os.Exit(2)
                    }
                }
                if event==2 {
                    r.waitErr=r.cmd.Wait()
                    r.mu.Lock(); r.receipt.OriginalWait=true
                    if r.cmd.ProcessState!=nil { r.receipt.ExitCode=r.cmd.ProcessState.ExitCode() }
                    r.mu.Unlock()
                    break
                }
                select {
                case <-cancelled:
                    _=r.Kill(context.Background())
                    cancelled=nil
                    // The independently armed absolute guard terminates broker
                    // if original child has not exited. Never rearm a grace time.
                case <-tick.C:
                }
            }
        }
        close(r.waitDone)
    })
    <-r.waitDone
    return r.waitErr
}
func (r *ownedRunner) Kill(context.Context) error {
    r.mu.Lock(); defer r.mu.Unlock()
    if !r.started || r.receipt.OriginalWait { return nil }
    r.receipt.Forced=true
    if r.gate!=nil { r.gate.Close() }
    if !r.receipt.AuditSelectorBound {
        r.receipt.IdentityGap,r.receipt.SignalError=true,true
        return errors.New("original Darwin selector unavailable")
    }
    // signalOriginal requires EXACT captured version in r02. XNU atomically
    // compares version and independently checks root caller cansignal/MAC.
    // Captured task is kept for authority provenance, never task_terminate:
    // Apple's task_terminate explicitly refuses tasks with BSD proc info.
    err:=signalOriginal(r.birth)
    if err!=nil {
        r.receipt.SignalError=true
        if errors.Is(err,syscall.ESTALE) || errors.Is(err,syscall.ESRCH) { r.receipt.IdentityGap=true }
    }
    return err
}
func (r *ownedRunner) releaseFiles() {
    r.releaseOnce.Do(func() {
    if r.gate!=nil { r.gate.Close() }
    if r.gateChild!=nil { r.gateChild.Close(); r.gateChild=nil }
    for _,p:=range r.pins { p.close() }
    if r.stdout!=nil { r.stdout.Close() }; if r.stderr!=nil { r.stderr.Close() }
    if r.private!=nil { r.private.close() }
    r.task.release()
    if r.root!=nil { r.root.close() }
    })
}
func (r *ownedRunner) closeOriginal(graceful bool) childReceipt {
    defer r.releaseFiles()
    r.mu.Lock(); started:=r.started; r.mu.Unlock()
    if started {
        if !graceful { _=r.Kill(context.Background()) }
        // Start/capture failure first attempts original selector cleanup. A
        // still-stopped/uncaptured child triggers the root parent exit path.
        _=r.Wait(context.Background())
    }
    r.mu.Lock(); defer r.mu.Unlock()
    r.receipt.PinsUnchanged=r.private!=nil && r.private.unchanged() && r.root!=nil && r.root.unchanged()
    for _,p:=range r.pins { if !p.unchanged() { r.receipt.PinsUnchanged=false } }
    // Hard NPROC=1 with guest real/saved IDs, inherited kernel limit, no fork
    // before trusted bootstrap barrier, and original attached trace. There
    // can be no original descendant or escaped session to retire. No PGID
    // snapshot is elevated into an authority claim.
    r.receipt.GroupRetired=started && r.entryReleased && r.receipt.ForkLimitBound &&
        r.receipt.TraceBound && r.receipt.SandboxBound && r.receipt.OriginalWait && !r.receipt.IdentityGap
    r.receipt.Qualified=graceful && (!r.providerCloseRequired || r.providerCloseOK) && r.receipt.Started && r.receipt.BootstrapBound &&
        r.receipt.AuditSelectorBound && r.receipt.TaskControlBound && r.receipt.TraceBound &&
        r.receipt.RootEnvelopeBound && r.receipt.ForkLimitBound && r.receipt.SandboxBound &&
        r.receipt.OriginalWait && r.receipt.ExitCode==0 && !r.receipt.IdentityGap &&
        !r.receipt.SignalError && !r.receipt.Forced && r.receipt.GroupRetired && r.receipt.PinsUnchanged
    return r.receipt
}
func (r *ownedRunner) Stdout() io.ReadCloser { return r.stdout }
func (r *ownedRunner) Stderr() io.ReadCloser { return r.stderr }
func (r *ownedRunner) ID() string { r.mu.Lock(); defer r.mu.Unlock(); if !r.started { return "" }; return strconv.Itoa(r.receipt.PID) }
func (r *ownedRunner) Name() string { return "operator-root-envelope-openbao-KMS-Darwin" }
func (r *ownedRunner) Diagnose(context.Context) string { return "provider handshake failed" }
func (r *ownedRunner) PluginToHost(network,address string) (string,string,error) {
    if network!="unix" || filepath.Clean(address)!=address || !strings.HasPrefix(address,r.socketDir+"/") || len(address)>=104 { return "","",errors.New("unowned plugin IPC") }
    return network,address,nil
}
func (r *ownedRunner) HostToPlugin(network,address string) (string,string,error) { return r.PluginToHost(network,address) }
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

func platformProviderOpened(r *ownedRunner) {
    if r!=nil { r.mu.Lock(); r.providerCloseRequired=true; r.mu.Unlock() }
}
func platformProviderClosed(r *ownedRunner) {
    if r!=nil { r.mu.Lock(); r.providerCloseOK=true; r.mu.Unlock() }
}

func (r *ownedRunner) awaitBootstrapReady(expected birthIdentity) error {
    ready:=make(chan error,1)
    go func() { var b [1]byte;_,err:=io.ReadFull(r.gate,b[:]);if err==nil && b[0]!=1 { err=errors.New("original gate protocol") };ready<-err }()
    tick:=time.NewTicker(time.Millisecond);defer tick.Stop()
    for {
        select {
        case err:=<-ready:return err
        case <-r.ctx.Done():return r.ctx.Err()
        case <-tick.C:
            event,status,err:=originalEvent(expected.PID)
            if err!=nil || event==2 { return errors.New("original bootstrap exited/gap") }
            if event==1 {
                now,failure:=identity(expected.PID)
                if failure!=nil || now!=expected || !originalTraced(expected.PID) ||
                    status<=0 || status==int(syscall.SIGTRAP) || continueOriginalSignal(expected.PID,status)!=nil {
                    return errors.New("original bootstrap trace gap")
                }
            }
        }
    }
}
