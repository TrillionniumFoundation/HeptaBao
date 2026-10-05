package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Darwin has no Linux parent-death syscall. Owner EOF cancels the original
// SDK RPC and the same go-plugin client holds its own plugin through Kill.
func bindPluginOwner(command *exec.Cmd) {}

type heldImage struct {
	file    *os.File
	witness ownedImage
}

func (h *heldImage) verify() error {
	st, err := h.file.Stat()
	if err != nil {
		return err
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0700 || raw.Uid != uint32(os.Getuid()) || raw.Nlink != 1 || raw.Flags != 2 || uint64(raw.Dev) != h.witness.Device || raw.Ino != h.witness.Inode || st.Size() != h.witness.Bytes {
		return fmt.Errorf("owned image identity")
	}
	named, err := os.Lstat(h.witness.Path)
	if err != nil {
		return err
	}
	if !os.SameFile(st, named) {
		return fmt.Errorf("owned image name")
	}
	if _, err = h.file.Seek(0, 0); err != nil {
		return err
	}
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(h.file, 256*1024*1024+1))
	if err != nil {
		return err
	}
	if n != h.witness.Bytes || hex.EncodeToString(sum.Sum(nil)) != h.witness.SHA256 {
		return fmt.Errorf("owned image digest")
	}
	return nil
}
func (h *heldImage) cleanup() error {
	defer h.file.Close()
	named, err := os.Lstat(h.witness.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	held, err := h.file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(held, named) {
		return fmt.Errorf("owned cleanup path replaced")
	}
	if err = h.verify(); err != nil {
		return err
	}
	if err = syscall.Fchflags(int(h.file.Fd()), 0); err != nil {
		return err
	}
	named, err = os.Lstat(h.witness.Path)
	if err != nil {
		return err
	}
	if !os.SameFile(held, named) {
		return fmt.Errorf("owned cleanup inode replaced")
	}
	return os.Remove(h.witness.Path)
}
func bindOwnedImages(plugin string, images []ownedImage) (func() error, error) {
	if len(images) != 2 {
		return nil, fmt.Errorf("two Darwin owned image witnesses required")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	dir, err := os.Stat(cwd)
	if err != nil {
		return nil, err
	}
	raw, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || !dir.IsDir() || dir.Mode().Perm() != 0700 || raw.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("owned image directory")
	}
	seen := map[string]bool{}
	held := []*heldImage{}
	fail := func(err error) (func() error, error) {
		for _, h := range held {
			h.file.Close()
		}
		return nil, err
	}
	for _, w := range images {
		expected := ""
		switch w.Role {
		case "companion":
			expected = self
		case "plugin":
			expected = plugin
		default:
			return fail(fmt.Errorf("owned image role"))
		}
		if seen[w.Role] || w.Path != expected || !filepath.IsAbs(w.Path) || filepath.Dir(w.Path) != cwd || !strings.HasPrefix(filepath.Base(w.Path), "image-") || w.Bytes <= 0 || w.Bytes > 256*1024*1024 || w.Device == 0 || w.Inode == 0 || len(w.SHA256) != 64 {
			return fail(fmt.Errorf("owned image witness"))
		}
		seen[w.Role] = true
		fd, err := syscall.Open(w.Path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		h := &heldImage{file: os.NewFile(uintptr(fd), w.Path), witness: w}
		held = append(held, h)
		if err = h.verify(); err != nil {
			return fail(err)
		}
	}
	return func() error {
		var out error
		for _, h := range held {
			out = errors.Join(out, h.cleanup())
		}
		return out
	}, nil
}
