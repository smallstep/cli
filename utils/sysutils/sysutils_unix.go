// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package sysutils

import "syscall"

func flock(fd int, how int) error {
	return syscall.Flock(fd, how)
}

func fileLock(fd int) error {
	return syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
}

func fileUnlock(fd int) error {
	return syscall.Flock(fd, syscall.LOCK_UN)
}

func kill(pid int, signum syscall.Signal) error {
	return syscall.Kill(pid, signum)
}

func exec(argv0 string, argv []string, envv []string) error {
	return syscall.Exec(argv0, argv, envv)
}
