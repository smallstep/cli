package sysutils

import "syscall"

func flock(fd int, how int) error {
	return syscall.EWINDOWS
}

func fileLock(fd int) error {
	return nil
}

func fileUnlock(fd int) error {
	return nil
}

func kill(pid int, signum syscall.Signal) error {
	return syscall.EWINDOWS
}

func exec(argv0 string, argv []string, envv []string) error {
	return syscall.EWINDOWS
}
