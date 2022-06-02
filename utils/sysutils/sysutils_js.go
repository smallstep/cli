//go:build js
// +build js

package sysutils

import (
	"errors"
	"syscall"
)

var errNotImplemented = errors.New("not implemented")

func flock(fd, how int) error {
	return errNotImplemented
}

func fileLock(fd int) error {
	return errNotImplemented
}

func fileUnlock(fd int) error {
	return errNotImplemented
}

func kill(pid int, signum syscall.Signal) error {
	return errNotImplemented
}

func exec(argv0 string, argv, envv []string) error {
	return errNotImplemented
}
