package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

func bindPluginOwner(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func bindOwnedImages(plugin string, images []ownedImage) (func() error, error) {
	if len(images) != 0 {
		return nil, fmt.Errorf("Darwin image witness on Linux")
	}
	return func() error { return nil }, nil
}
