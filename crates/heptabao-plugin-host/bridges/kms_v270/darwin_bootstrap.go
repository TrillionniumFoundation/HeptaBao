//go:build darwin && cgo

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "net"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"

)
const darwinBootstrapMarker = "--heptabao-owned-darwin-bootstrap-v1"

// Invoked only by an externally operator-pinned bootstrap image. This marker
// is an internal execution mode, not proof of authority or a request field.
func platformBootstrap() (bool, int) {
    if len(os.Args) < 2 || os.Args[1] != darwinBootstrapMarker { return false, 0 }
    if len(os.Args) < 7 { return true, 2 }
    fd, e1 := strconv.Atoi(os.Args[2])
    absolute, e2 := strconv.ParseInt(os.Args[3], 10, 64)
    observed := time.Now()
    now, e3 := monotonicNanos()
    path := os.Args[4]
    if e1 != nil || fd < 4 || fd > 36 || e2 != nil || e3 != nil ||
        absolute <= now || absolute-now > int64(time.Hour) ||
        !filepath.IsAbs(path) || filepath.Clean(path) != path { return true, 2 }
    // This original timer is armed before any regular-file IO. A blocked
    // hash or a failed parent capture cannot keep this trusted pre-exec image
    // alive by rearming its budget. Successful exec replaces this Go runtime;
    // the provider's original deadline remains the parent's responsibility.
    expires := observed.Add(time.Duration(absolute-now))
    expiry := time.AfterFunc(time.Until(expires), func() { os.Exit(2) })
    defer expiry.Stop()
    // The inherited image FD and private path must remain the same regular
    // inode. Replacement during gate waiting is checked again after release.
    image := os.NewFile(3, "original-private-provider-image")
    if image == nil { return true, 2 }
    defer image.Close() // Keeps original image FD live until exec or failure.
    // Digest was supplied by the original operator deployment, not computed
    // from this bootstrap/self image to manufacture an execution grant.
    if !verifyBootstrapImage(image, path, os.Args[5]) { return true, 2 }
    gateFile := os.NewFile(uintptr(fd), "original-bootstrap-gate")
    if gateFile == nil { return true, 2 }
    gate, e := net.FileConn(gateFile)
    gateFile.Close()
    if e != nil { return true, 2 }
    defer gate.Close()
    // Observe remaining monotonic time before wall-clock mapping. This never
    // grants a fresh provider budget, including gate/parent capture failures.
    observed = time.Now()
    now, e = monotonicNanos()
    if e != nil || now >= absolute { return true, 2 }
    deadline := observed.Add(time.Duration(absolute-now))
    if e = gate.SetDeadline(deadline); e != nil { return true, 2 }
    if _, e = gate.Write([]byte{1}); e != nil { return true, 2 }
    var release [1]byte
    if _, e = io.ReadFull(gate, release[:]); e != nil || release[0] != 2 { return true, 2 }
    if !verifyBootstrapImage(image, path, os.Args[5]) { return true, 2 }
    now, e = monotonicNanos()
    if e != nil || now >= absolute { return true, 2 }
    // Gate is not inherited into the provider. Libraries remain original FDs.
    gate.Close()
    env := make([]string, 0, len(os.Environ()))
    for _, value := range os.Environ() {
        if !strings.HasPrefix(value, "DYLD_") && !strings.HasPrefix(value, "LD_") {
            env = append(env, value)
        }
    }
    if syscall.Exec(path, append([]string{os.Args[6]}, os.Args[7:]...), env) != nil { return true, 2 }
    return true, 2
}
// This closes replacement during gate waiting. Darwin still lacks proved
// atomic held-FD exec; the final pathname check-to-exec interval is an explicit
// SourceOnly entry blocker, not a claimed Linux /proc/self/fd equivalent.
func verifyBootstrapImage(image *os.File, path, externalDigest string) bool {
    decoded, err := hex.DecodeString(externalDigest)
    if err != nil || len(decoded) != sha256.Size ||
        hex.EncodeToString(decoded) != externalDigest { return false }
    st, err := image.Stat()
    pst, pathErr := os.Lstat(path)
    if err != nil || pathErr != nil || !st.Mode().IsRegular() || !pst.Mode().IsRegular() ||
        !os.SameFile(st, pst) || pst.Mode().Perm() != 0500 { return false }
    before, ok := st.Sys().(*syscall.Stat_t)
    if !ok || before.Nlink != 1 || before.Uid != uint32(os.Geteuid()) { return false }
    if _, err = image.Seek(0, io.SeekStart); err != nil { return false }
    hash := sha256.New()
    if _, err = io.Copy(hash, image); err != nil ||
        hex.EncodeToString(hash.Sum(nil)) != externalDigest { return false }
    after, err := image.Stat()
    pathAfter, pathErr := os.Lstat(path)
    if err != nil || pathErr != nil || !os.SameFile(after, pathAfter) { return false }
    raw, ok := after.Sys().(*syscall.Stat_t)
    pathRaw, pathOK := pathAfter.Sys().(*syscall.Stat_t)
    if !ok || !pathOK || !sameFileStat(before, raw) || !sameFileStat(raw, pathRaw) { return false }
    _, err = image.Seek(0, io.SeekStart)
    return err == nil
}
func bootstrapDeadline(ctx context.Context) (int64, time.Time, error) {
    deadline, ok := ctx.Deadline()
    if !ok || ctx.Err() != nil { return 0, time.Time{}, errors.New("original bootstrap deadline") }
    now, err := monotonicNanos()
    if err != nil { return 0, time.Time{}, err }
    left := time.Until(deadline)
    if left <= 0 || left > time.Hour || now > (1<<63-1)-int64(left) {
        return 0, time.Time{}, errors.New("original bootstrap deadline")
    }
    return now + int64(left), deadline, nil
}
