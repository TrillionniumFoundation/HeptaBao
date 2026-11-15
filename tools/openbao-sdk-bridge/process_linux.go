package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func bindPluginOwner(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func bindLaunchOwnedImages() (func(message) error, func() error, error) {
	if os.Getenv("HBP_SDK_OWNED_IMAGES") != "" {
		return nil, nil, fmt.Errorf("Darwin owned descriptor bootstrap on Linux")
	}
	return func(m message) error {
		if len(m.OwnedImages) != 0 {
			return fmt.Errorf("Darwin image witness on Linux")
		}
		return nil
	}, func() error { return nil }, nil
}
