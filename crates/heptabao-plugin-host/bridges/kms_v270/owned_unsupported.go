//go:build (!linux && !darwin) || (darwin && !cgo)

// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

type execCmd = exec.Cmd
type childReceipt struct {
	Qualified bool `json:"qualified"`
}
type pinnedFile struct{ file *os.File }

func pinFile(string, string, bool) (*pinnedFile, error) {
	return nil, errors.New("native KMS owner unavailable; Darwin requires CGO")
}
func (p *pinnedFile) unchanged() bool { return false }

type ownedRunner struct{}

func newOwnedRunner(*exec.Cmd, deployment, string, string, context.Context) (*ownedRunner, error) {
	return nil, errors.New("native KMS owner unavailable; Darwin requires CGO")
}
func (r *ownedRunner) closeOriginal(bool) childReceipt { return childReceipt{} }
func (r *ownedRunner) Start(context.Context) error     { return errors.New("native KMS owner unavailable; Darwin requires CGO") }
func (r *ownedRunner) Wait(context.Context) error      { return errors.New("native KMS owner unavailable; Darwin requires CGO") }
func (r *ownedRunner) Kill(context.Context) error      { return nil }
func (r *ownedRunner) Stdout() io.ReadCloser           { return nil }
func (r *ownedRunner) Stderr() io.ReadCloser           { return nil }
func (r *ownedRunner) ID() string                      { return "" }
func (r *ownedRunner) Name() string                    { return "unsupported-KMS-runner" }
func (r *ownedRunner) Diagnose(context.Context) string { return "native KMS owner unavailable; Darwin requires CGO" }
func (r *ownedRunner) PluginToHost(string, string) (string, string, error) {
	return "", "", errors.New("native KMS owner unavailable; Darwin requires CGO")
}
func (r *ownedRunner) HostToPlugin(string, string) (string, string, error) {
	return "", "", errors.New("native KMS owner unavailable; Darwin requires CGO")
}

func monotonicNanos() (int64, error) {
	return 0, errors.New("genuine KMS requires a qualified native owner")
}

func validatePlatformDeployment(deployment) error { return errors.New("native KMS platform ownership unavailable; Darwin requires CGO") }
func platformBootstrap() (bool, int) { return false, 0 }
