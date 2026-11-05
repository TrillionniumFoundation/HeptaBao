//go:build darwin && cgo

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "os"
    "path/filepath"
    "sync"
    "syscall"

    "golang.org/x/sys/unix"
)

func sameFileStat(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtimespec == b.Mtimespec && a.Ctimespec == b.Ctimespec && a.Birthtimespec == b.Birthtimespec && a.Gid == b.Gid && a.Flags == b.Flags
}

type pinnedFile struct {
	file         *os.File
	path, digest string
	stat         syscall.Stat_t
    ancestors []*os.File
    pathRetired bool
}

func openPinned(path, digest string, executable bool) (*os.File, error) {
	p, err := pinFile(path, digest, executable)
	if err != nil {
		return nil, err
	}
	for _, f := range p.ancestors { f.Close() }
    p.ancestors=nil
	return p.file, nil
}
func pinFile(path, digest string, executable bool) (*pinnedFile, error) {
    return pinDarwinFile(path,digest,executable,false)
}
func pinRootBroker(path,digest string) (*pinnedFile,error) {
    return pinDarwinFile(path,digest,true,true)
}
func pinDarwinFile(path, digest string, executable, broker bool) (*pinnedFile, error) {
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != 32 || digest != hex.EncodeToString(expected) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid operator pin")
	}
	if !onT5(path) { return nil, errors.New("Darwin operator files require T5") }
    ancestors, err := sealedAncestors(filepath.Dir(path))
    if err != nil { return nil, err }
    holdAncestors := false
    defer func() { if !holdAncestors { for _, f := range ancestors { f.Close() } } }()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
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
	if !ok || !st.Mode().IsRegular() || raw.Nlink != 1 || raw.Uid != 0 || st.Mode().Perm()&0022 != 0 || (raw.Mode&syscall.S_ISGID != 0 || !broker && raw.Mode&syscall.S_ISUID != 0) ||
		(executable && st.Mode().Perm()&0100 == 0) {
		return nil, errors.New("operator image owner")
	}
	if !errors.Is(unix.Faccessat(unix.AT_FDCWD,path,unix.W_OK,0),syscall.EACCES) { return nil, errors.New("caller-writable operator file") }
    if broker && (st.Mode().Perm()&0222 != 0 || raw.Mode&syscall.S_ISUID != 0 && raw.Mode&07777 != 04555) { return nil, errors.New("external root broker mode") }
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
    holdAncestors = true
	return &pinnedFile{file: f, path: path, digest: digest, stat: *raw, ancestors:ancestors}, nil
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
    if p.pathRetired {
        if !errors.Is(err,os.ErrNotExist) || raw.Nlink!=0 { return false }
    } else {
        if err!=nil { return false }
        pathRaw,ok:=pathStat.Sys().(*syscall.Stat_t)
        if !ok || !sameFileStat(pathRaw,&p.stat) { return false }
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

type privateDirectory struct {
    file, parent *os.File
    path, parentPath string
    stat, parentStat syscall.Stat_t
    assets []string
    guestGID uint32
    closeOnce sync.Once
}
func directoryIdentity(file *os.File, path string, original *syscall.Stat_t) bool {
    st, err := file.Stat()
    if err != nil { return false }
    raw, ok := st.Sys().(*syscall.Stat_t)
    if !ok || raw.Dev != original.Dev || raw.Ino != original.Ino ||
        raw.Uid != original.Uid || raw.Gid != original.Gid || raw.Mode != original.Mode || !st.IsDir() { return false }
    ps, err := os.Lstat(path)
    if err != nil || !ps.IsDir() || !os.SameFile(st, ps) { return false }
    return true
}
func newPrivateDirectory(ownedTemp string) (d *privateDirectory, err error) {
    if !filepath.IsAbs(ownedTemp) || filepath.Clean(ownedTemp) != ownedTemp || len(ownedTemp) > 60 {
        return nil, errors.New("invalid owned socket directory")
    }
    openDir := func(path string) (*os.File, syscall.Stat_t, error) {
        fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
        if e != nil { return nil, syscall.Stat_t{}, e }
        file := os.NewFile(uintptr(fd), path)
        st, e := file.Stat()
        if e != nil { file.Close(); return nil, syscall.Stat_t{}, e }
        raw, ok := st.Sys().(*syscall.Stat_t)
        if !ok || !st.IsDir() || (st.Mode().Perm() != 0700 && st.Mode().Perm() != 0711) ||
            raw.Uid != uint32(os.Geteuid()) || raw.Mode&(syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) != 0 {
            file.Close(); return nil, syscall.Stat_t{}, errors.New("invalid private directory owner")
        }
        return file, *raw, nil
    }
    parent, parentStat, err := openDir(ownedTemp)
    if err != nil { return nil, err }
    d = &privateDirectory{parent: parent, parentPath: ownedTemp, parentStat: parentStat}
    defer func() { if err != nil { d.close() } }()
    d.path, err = os.MkdirTemp(ownedTemp, "d-")
    if err != nil { return d, err }
    d.file, d.stat, err = openDir(d.path)
    if err != nil { return d, err }
    if !d.unchanged() { return d, errors.New("private directory changed") }
    return d, nil
}
func (d *privateDirectory) unchanged() bool {
    return d != nil && d.file != nil && d.parent != nil &&
        directoryIdentity(d.file, d.path, &d.stat) &&
        directoryIdentity(d.parent, d.parentPath, &d.parentStat)
}
func (d *privateDirectory) copyPinned(original *pinnedFile, name string, executable bool) (pin *pinnedFile, err error) {
    if !d.unchanged() || !original.unchanged() || filepath.Base(name) != name || name == "." || name == ".." {
        return nil, errors.New("private image source changed")
    }
    fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
    if err != nil { return nil, err }
    d.assets = append(d.assets, name)
    path := filepath.Join(d.path, name)
    writer := os.NewFile(uintptr(fd), path)
    defer writer.Close()
    if _, err = original.file.Seek(0, io.SeekStart); err != nil { return nil, err }
    if _, err = io.Copy(writer, original.file); err != nil { return nil, err }
    if err = writer.Sync(); err != nil { return nil, err }
    mode := os.FileMode(0400)
    if executable {
        mode = 0510
        if err = writer.Chown(0,int(d.guestGID)); err != nil { return nil,err }
    }
    if err = writer.Chmod(mode); err != nil { return nil, err }
    if err = writer.Close(); err != nil { return nil, err }
    if !original.unchanged() || !d.unchanged() { return nil, errors.New("private image source changed") }
    pin, err = pinFile(path, original.digest, executable)
    if err != nil { return nil, err }
    if !d.unchanged() { pin.close(); return nil, errors.New("private image directory changed") }
    return pin, nil
}
func (d *privateDirectory) close() {
    if d == nil { return }
    d.closeOnce.Do(func() {
        samePath := d.unchanged()
        if d.file != nil {
            for _, name := range d.assets { _ = unix.Unlinkat(int(d.file.Fd()), name, 0) }
            d.file.Close()
        }
        if samePath { _ = os.Remove(d.path) }
        if d.parent != nil { d.parent.Close() }
    })
}

func (p *pinnedFile) close() {
    if p==nil { return }; p.file.Close(); for _,f:=range p.ancestors { f.Close() }
}
func closePlatformPin(p *pinnedFile) { p.close() }
func (d *privateDirectory) setGuestMode(mode os.FileMode) error {
    if !d.unchanged() { return errors.New("original private directory changed") }
    if err:=d.file.Chown(0,int(d.guestGID)); err!=nil { return err }
    if err:=d.file.Chmod(mode); err!=nil { return err }
    st,err:=d.file.Stat(); if err!=nil { return err }
    raw,ok:=st.Sys().(*syscall.Stat_t); if !ok { return errors.New("original private directory stat") }
    d.stat=*raw
    if !d.unchanged() { return errors.New("original private directory replaced") }; return nil
}
func (d *privateDirectory) allowGuest() error { return d.setGuestMode(0710) }
func (d *privateDirectory) sealGuest() error { return d.setGuestMode(0700) }

func (p *pinnedFile) retireOriginalPath(d *privateDirectory) error {
    if p.pathRetired || !p.unchanged() || !d.unchanged() || filepath.Dir(p.path)!=d.path { return errors.New("original exec pathname custody") }
    before:=p.stat
    if err:=unix.Unlinkat(int(d.file.Fd()),filepath.Base(p.path),0); err!=nil { return err }
    st,err:=p.file.Stat(); if err!=nil { return err }
    raw,ok:=st.Sys().(*syscall.Stat_t)
    if !ok || raw.Dev!=before.Dev || raw.Ino!=before.Ino || raw.Uid!=0 ||
        raw.Gid!=before.Gid || raw.Mode!=before.Mode || raw.Size!=before.Size ||
        raw.Mtimespec!=before.Mtimespec || raw.Birthtimespec!=before.Birthtimespec ||
        raw.Flags!=before.Flags || raw.Nlink!=0 { return errors.New("original exec inode changed during unlink") }
    p.stat=*raw;p.pathRetired=true
    if !p.unchanged() { return errors.New("original unlinked exec pin changed") }
    return nil
}
