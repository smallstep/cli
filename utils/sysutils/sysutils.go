package sysutils

import "syscall"

func Flock(fd int, how int) error {
	return flock(fd, how)
}

func FileLock(fd int) error {
	return fileLock(fd)
}

func FileUnlock(fd int) error {
	return fileUnlock(fd)
}

func Kill(pid int, signum syscall.Signal) error {
	return kill(pid, signum)
}

func Exec(argv0 string, argv []string, envv []string) error {
	return exec(argv0, argv, envv)
}
