//go:build darwin && cgo

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "os"
    "os/exec"
    "path/filepath"
    "testing"
    "time"
)

// Future native unit execution must explicitly use the task's authorized disk.
// SourceOnly preparation never executes these tests or provider images.
func darwinTestDirectory(t *testing.T) string {
    t.Helper()
    root := os.Getenv("HEPTABAO_TEST_OWNED_TMP")
    if os.Geteuid()!=0 || os.Getuid()==0 { t.Skip("requires real external root/caller test role; no native qualification inferred") }
    if !onT5(root) || len(root) > 40 {
        t.Fatal("set a short HEPTABAO_TEST_OWNED_TMP on the authorized task disk")
    }
    dir, err := os.MkdirTemp(root, "k-")
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { os.RemoveAll(dir) })
    return dir
}
func darwinFixturePin(t *testing.T, dir, name string) (string, string) {
    t.Helper()
    path := filepath.Join(dir, name)
    content := []byte("source-only pinned fixture; never executed\n")
    if err := os.WriteFile(path, content, 0700); err != nil { t.Fatal(err) }
    digest := sha256.Sum256(content)
    return path, hex.EncodeToString(digest[:])
}
func TestDarwinPrivateCopyKeepsOriginalExternalPinAndHeldInode(t *testing.T) {
    dir := darwinTestDirectory(t)
    path, digest := darwinFixturePin(t, dir, "original")
    original, err := pinFile(path, digest, true)
    if err != nil { t.Fatal(err) }
    defer original.close()
    private, err := newPrivateDirectory(dir)
    if err != nil { t.Fatal(err) }
    defer private.close()
    copy, err := private.copyPinned(original, "provider", true)
    if err != nil { t.Fatal(err) }
    defer copy.close()
    a, _ := original.file.Stat()
    b, _ := copy.file.Stat()
    if os.SameFile(a, b) || !original.unchanged() || !copy.unchanged() || b.Mode().Perm() != 0510 {
        t.Fatal("private execution copy lost external provenance or became a hardlink")
    }
    if err := os.WriteFile(path, []byte("mutated external image"), 0700); err != nil { t.Fatal(err) }
    if original.unchanged() || !copy.unchanged() {
        t.Fatal("external mutation was hidden or changed private held bytes")
    }
}
func TestDarwinConstructorFailureClosesPrivateAssetsBeforeAnyChild(t *testing.T) {
    dir := darwinTestDirectory(t)
    image, digest := darwinFixturePin(t, dir, "image")
    d := deployment{Provider: "opaque", Image: image, ImageSHA256: digest,
        DarwinBootstrap: &darwinBootstrapDeployment{Image: filepath.Join(dir, "missing"),
            ImageSHA256: digest}}
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()
    r, err := newOwnedRunner(&exec.Cmd{}, d, dir, dir, ctx)
    if err == nil || r != nil { t.Fatal("missing root role acquired child custody") }
    entries, err := os.ReadDir(dir)
    if err != nil || len(entries) != 1 || entries[0].Name() != "image" {
        t.Fatal("constructor failure retained unowned private assets")
    }
}
func TestDarwinBootstrapProvenanceCannotBeMissingOrImplicit(t *testing.T) {
    for _, d := range []deployment{{}, {DarwinBootstrap: &darwinBootstrapDeployment{}},
        {DarwinBootstrap: &darwinBootstrapDeployment{Image: "/operator/bootstrap"}}} {
        if validatePlatformDeployment(d) == nil { t.Fatal("an implicit/self-selected bootstrap was accepted") }
    }
}
func TestDarwinCanceledOriginalBudgetCannotConstructProvider(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    cancel()
    if _, _, err := bootstrapDeadline(ctx); err == nil {
        t.Fatal("canceled original budget was rearmed")
    }
    if _, _, err := bootstrapDeadline(context.Background()); err == nil {
        t.Fatal("an absent original budget gained a provider deadline")
    }
}

func TestDarwinOriginalProcessSelectorRejectsForeignBirth(t *testing.T) {
    original:=birthIdentity{PID:17,PPID:8,PGID:17,SID:17,UID:401,RUID:401,Unique:99,StartSec:22,StartUsec:33,Version:7}
    expected:=original;expected.Version=8
    if !sameOriginalProcess(original,expected) { t.Fatal("expected single exec changed original process birth") }
    controls:=[]birthIdentity{original,original,original,original,original,original}
    controls[0].Unique++;controls[1].StartUsec++;controls[2].UID++;controls[3].PPID++;controls[4].SID++;controls[5].PID++
    for _,foreign:=range controls { if sameOriginalProcess(original,foreign) { t.Fatal("foreign birth became original") } }
}
func TestDarwinRootRoleAndT5PathsAreExplicit(t *testing.T) {
    if validatePlatformDeployment(deployment{DarwinBootstrap:&darwinBootstrapDeployment{Image:"/Volumes/T5/b",ImageSHA256:"operator"}})==nil {
        t.Fatal("bootstrap declaration manufactured root authority")
    }
    for _,path:=range []string{"/tmp/job","/Volumes/T5","/Volumes/T5/../other/job","/Volumes/T5/a/./b"} {
        if onT5(path) { t.Fatal("unsealed write namespace accepted") }
    }
}

func TestDarwinRetireOnlyPrivatePathKeepsOriginalProviderAndFD(t *testing.T) {
    dir:=darwinTestDirectory(t);path,digest:=darwinFixturePin(t,dir,"external-provider")
    original,err:=pinFile(path,digest,true);if err!=nil {t.Fatal(err)};defer original.close()
    private,err:=newPrivateDirectory(dir);if err!=nil {t.Fatal(err)};defer private.close()
    copy,err:=private.copyPinned(original,"provider",true);if err!=nil {t.Fatal(err)};defer copy.close()
    if original.retireOriginalPath(private)==nil {t.Fatal("external provider pathname could be retired")}
    if err=copy.retireOriginalPath(private);err!=nil {t.Fatal(err)}
    if _,err=os.Lstat(copy.path);!os.IsNotExist(err) {t.Fatal("private exec pathname survived retirement")}
    if !copy.unchanged() || !original.unchanged() {t.Fatal("held FD or external original was lost")}
    if copy.retireOriginalPath(private)==nil {t.Fatal("one-way path retirement was repeated")}
}
