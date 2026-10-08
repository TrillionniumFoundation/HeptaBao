//go:build linux

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type execCmd = exec.Cmd

type childReceipt struct {
	Started       bool   `json:"started"`
	PID           int    `json:"pid"`
	Birth         string `json:"birth"`
	PGID          int    `json:"pgid"`
	SID           int    `json:"sid"`
	OriginalWait  bool   `json:"original_wait"`
	ExitCode      int    `json:"exit_code"`
	IdentityGap   bool   `json:"identity_gap"`
	SignalError   bool   `json:"signal_error"`
	Forced        bool   `json:"forced"`
	GroupRetired  bool   `json:"group_retired"`
	PinsUnchanged bool   `json:"pins_unchanged"`
	Qualified     bool   `json:"qualified"`
}
type birthIdentity struct {
	PID, PPID, PGID, SID, UID int
	Ticks                     string
}

func identity(pid int) (birthIdentity, error) {
	var id birthIdentity
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return id, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return id, errors.New("process metadata")
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return id, errors.New("process metadata")
	}
	ppid, e1 := strconv.Atoi(f[1])
	pgid, e2 := strconv.Atoi(f[2])
	sid, e3 := strconv.Atoi(f[3])
	st, e4 := os.Stat("/proc/" + strconv.Itoa(pid))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return id, errors.New("process metadata")
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return id, errors.New("process metadata")
	}
	id = birthIdentity{PID: pid, PPID: ppid, PGID: pgid, SID: sid, UID: int(raw.Uid), Ticks: f[19]}
	return id, nil
}
func sameFileStat(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

type pinnedFile struct {
	file         *os.File
	path, digest string
	stat         syscall.Stat_t
}

func openPinned(path, digest string, executable bool) (*os.File, error) {
	p, err := pinFile(path, digest, executable)
	if err != nil {
		return nil, err
	}
	return p.file, nil
}
func pinFile(path, digest string, executable bool) (*pinnedFile, error) {
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != 32 || digest != hex.EncodeToString(expected) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid operator pin")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || raw.Nlink != 1 || (raw.Uid != uint32(os.Getuid()) && raw.Uid != 0) || st.Mode().Perm()&0022 != 0 || raw.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 ||
		(executable && st.Mode().Perm()&0100 == 0) {
		return nil, errors.New("operator image owner")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, errors.New("operator image digest")
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	afterRaw, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !sameFileStat(raw, afterRaw) {
		return nil, errors.New("operator image changed")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	keep = true
	return &pinnedFile{file: f, path: path, digest: digest, stat: *raw}, nil
}
func (p *pinnedFile) unchanged() bool {
	st, err := p.file.Stat()
	if err != nil {
		return false
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !sameFileStat(raw, &p.stat) {
		return false
	}
	pathStat, err := os.Lstat(p.path)
	if err != nil {
		return false
	}
	pathRaw, ok := pathStat.Sys().(*syscall.Stat_t)
	if !ok || !sameFileStat(pathRaw, &p.stat) {
		return false
	}
	if _, err = p.file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	h := sha256.New()
	if _, err = io.Copy(h, p.file); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == p.digest
}

type ownedRunner struct {
	cmd            *exec.Cmd
	stdout, stderr io.ReadCloser
	pins           []*pinnedFile
	socketDir      string
	ctx            context.Context
	mu             sync.Mutex
	started        bool
	birth          birthIdentity
	receipt        childReceipt
	waitOnce       sync.Once
	waitDone       chan struct{}
	waitErr        error
}

func newOwnedRunner(spec *exec.Cmd, d deployment, socketDir, ownedTemp string, ctx context.Context) (r *ownedRunner, err error) {
	if !filepath.IsAbs(ownedTemp) || filepath.Clean(ownedTemp) != ownedTemp ||
		!(strings.HasPrefix(ownedTemp, "/data/") || strings.HasPrefix(ownedTemp, "/home/qian/")) || len(socketDir) > 90 {
		return nil, errors.New("invalid owned socket directory")
	}
	st, err := os.Lstat(ownedTemp)
	if err != nil {
		return nil, err
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm() != 0700 || raw.Uid != uint32(os.Getuid()) {
		return nil, errors.New("invalid owned socket directory")
	}
	r = &ownedRunner{ctx: ctx, socketDir: socketDir, waitDone: make(chan struct{}), receipt: childReceipt{ExitCode: -999}}
	defer func() {
		if err != nil {
			for _, p := range r.pins {
				p.file.Close()
			}
			if r.stdout != nil {
				r.stdout.Close()
			}
			if r.stderr != nil {
				r.stderr.Close()
			}
		}
	}()
	image, err := pinFile(d.Image, d.ImageSHA256, true)
	if err != nil {
		return r, err
	}
	r.pins = append(r.pins, image)
	files := []*os.File{image.file}
	aliases := []string{}
	seen := map[string]bool{}
	for _, lib := range d.Libraries {
		if lib.Alias == "" || len(lib.Alias) > 128 || strings.ContainsAny(lib.Alias, "=,\x00\r\n") || seen[lib.Alias] {
			return r, errors.New("invalid library alias")
		}
		seen[lib.Alias] = true
		p, e := pinFile(lib.Path, lib.SHA256, false)
		if e != nil {
			return r, e
		}
		r.pins = append(r.pins, p)
		files = append(files, p.file)
		aliases = append(aliases, lib.Alias+"=/proc/self/fd/"+strconv.Itoa(2+len(files)))
	}
	// No request-supplied executable, path, environment or library mapping is used.
	cmd := exec.Command("/proc/self/fd/3", d.Args...)
	cmd.Args[0] = d.Image
	cmd.ExtraFiles = files
	cmd.Env = append([]string{}, spec.Env...)
	cmd.Env = append(cmd.Env, "TMPDIR="+ownedTemp, "BAO_PKCS11_ALIASES="+strings.Join(aliases, ","))
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	r.cmd = cmd
	r.stdout, err = cmd.StdoutPipe()
	if err != nil {
		return r, err
	}
	r.stderr, err = cmd.StderrPipe()
	if err != nil {
		return r, err
	}
	return r, nil
}
func (r *ownedRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errors.New("already started")
	}
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return errors.New("start deadline")
	}
	for _, p := range r.pins {
		if !p.unchanged() {
			return errors.New("image changed before entry")
		}
	}
	if err := r.cmd.Start(); err != nil {
		return err
	}
	// Retain the original command before identity observation, even if observation fails.
	r.started = true
	r.receipt.Started = true
	r.receipt.PID = r.cmd.Process.Pid
	id, err := identity(r.cmd.Process.Pid)
	if err != nil || id.PPID != os.Getpid() || id.UID != os.Getuid() || id.PGID != id.PID {
		r.receipt.IdentityGap = true
		return errors.New("native child identity")
	}
	r.birth = id
	r.receipt.Birth = id.Ticks
	r.receipt.PGID = id.PGID
	r.receipt.SID = id.SID
	go func() {
		select {
		case <-r.ctx.Done():
			_ = r.Kill(context.Background())
		case <-r.waitDone:
		}
	}()
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
			if r.cmd.ProcessState != nil {
				r.receipt.ExitCode = r.cmd.ProcessState.ExitCode()
			}
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
	if !r.started || r.receipt.OriginalWait {
		return nil
	}
	r.receipt.Forced = true
	id, err := identity(r.cmd.Process.Pid)
	if err == nil && id == r.birth && id.PGID == id.PID {
		// Group signaling is authorized only while the retained original leader identity matches.
		err = syscall.Kill(-id.PGID, syscall.SIGKILL)
		if err == nil || errors.Is(err, syscall.ESRCH) {
			return nil
		}
	}
	// Metadata is not a precondition for cleaning up the exact original child.
	r.receipt.IdentityGap = true
	err = r.cmd.Process.Kill()
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		r.receipt.SignalError = true
		return err
	}
	return nil
}
func groupRetired(id birthIdentity) bool {
	if id.PID == 0 {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		v, err := identity(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// Unknown /proc identities owned by other users are outside this child's group.
			st, se := os.Stat("/proc/" + e.Name())
			if se == nil {
				if x, ok := st.Sys().(*syscall.Stat_t); ok && int(x.Uid) != id.UID {
					continue
				}
			}
			return false
		}
		if v.UID == id.UID && v.PGID == id.PGID && v.SID == id.SID {
			return false
		}
	}
	return true
}

func (r *ownedRunner) cleanupOwnedMembers() {
	// The original group identity remains the cleanup domain after its leader was waited.
	// Signal each observed member through a pidfd, rechecking its complete birth identity.
	if r.birth.PID == 0 || r.birth.PGID != r.birth.PID {
		r.receipt.IdentityGap = true
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		r.receipt.IdentityGap = true
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		id, err := identity(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			st, se := os.Stat("/proc/" + entry.Name())
			if se == nil {
				if raw, ok := st.Sys().(*syscall.Stat_t); ok && int(raw.Uid) != r.birth.UID {
					continue
				}
			}
			r.receipt.IdentityGap = true
			continue
		}
		if id.UID != r.birth.UID || id.PGID != r.birth.PGID || id.SID != r.birth.SID {
			continue
		}
		r.receipt.Forced = true
		fd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			r.receipt.SignalError = true
			continue
		}
		now, err := identity(pid)
		if err == nil && now == id {
			err = unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				r.receipt.SignalError = true
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			r.receipt.IdentityGap = true
		}
		_ = unix.Close(fd)
	}
}

func (r *ownedRunner) closeOriginal(graceful bool) childReceipt {
	defer func() {
		for _, p := range r.pins {
			p.file.Close()
		}
		if r.stdout != nil {
			r.stdout.Close()
		}
		if r.stderr != nil {
			r.stderr.Close()
		}
	}()
	if r.cmd == nil {
		return r.receipt
	}
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if started {
		if !graceful {
			_ = r.Kill(context.Background())
		}
		// Always call the same original command Wait, including Start/metadata failures.
		_ = r.Wait(context.Background())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if started && !groupRetired(r.birth) {
		r.cleanupOwnedMembers()
	}
	r.receipt.GroupRetired = started && groupRetired(r.birth)
	r.receipt.PinsUnchanged = true
	for _, p := range r.pins {
		if !p.unchanged() {
			r.receipt.PinsUnchanged = false
		}
	}
	r.receipt.Qualified = r.receipt.Started && r.receipt.OriginalWait && r.receipt.ExitCode == 0 &&
		!r.receipt.IdentityGap && !r.receipt.SignalError && !r.receipt.Forced && r.receipt.GroupRetired && r.receipt.PinsUnchanged
	return r.receipt
}
func (r *ownedRunner) Stdout() io.ReadCloser { return r.stdout }
func (r *ownedRunner) Stderr() io.ReadCloser { return r.stderr }
func (r *ownedRunner) ID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return ""
	}
	return strconv.Itoa(r.receipt.PID)
}
func (r *ownedRunner) Name() string                    { return "operator-pinned-openbao-KMS" }
func (r *ownedRunner) Diagnose(context.Context) string { return "provider handshake failed" }
func (r *ownedRunner) PluginToHost(network, address string) (string, string, error) {
	if network != "unix" || filepath.Clean(address) != address || !strings.HasPrefix(address, r.socketDir+"/") || len(address) >= 108 {
		return "", "", errors.New("unowned plugin IPC")
	}
	return network, address, nil
}
func (r *ownedRunner) HostToPlugin(network, address string) (string, string, error) {
	return r.PluginToHost(network, address)
}

func monotonicNanos() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 || ts.Sec > (1<<63-1)/1_000_000_000 || ts.Sec == (1<<63-1)/1_000_000_000 && ts.Nsec > (1<<63-1)%1_000_000_000 {
		return 0, errors.New("monotonic clock")
	}
	return ts.Sec*1_000_000_000 + ts.Nsec, nil
}
