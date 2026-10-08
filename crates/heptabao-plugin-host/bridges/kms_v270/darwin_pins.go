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

type privateDirectory struct {
    file, parent *os.File
    path, parentPath string
    stat, parentStat syscall.Stat_t
    assets []string
    closeOnce sync.Once
}
func directoryIdentity(file *os.File, path string, original *syscall.Stat_t) bool {
    st, err := file.Stat()
    if err != nil { return false }
    raw, ok := st.Sys().(*syscall.Stat_t)
    if !ok || raw.Dev != original.Dev || raw.Ino != original.Ino ||
        raw.Uid != original.Uid || raw.Mode != original.Mode || !st.IsDir() { return false }
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
        if !ok || !st.IsDir() || st.Mode().Perm() != 0700 ||
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
    if executable { mode = 0500 }
    if err = writer.Chmod(mode); err != nil { return nil, err }
    if err = writer.Close(); err != nil { return nil, err }
    if !original.unchanged() || !d.unchanged() { return nil, errors.New("private image source changed") }
    pin, err = pinFile(path, original.digest, executable)
    if err != nil { return nil, err }
    if !d.unchanged() { pin.file.Close(); return nil, errors.New("private image directory changed") }
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
