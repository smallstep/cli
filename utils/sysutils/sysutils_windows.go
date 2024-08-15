package sysutils

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func init() {
	var inMode, outMode uint32
	maj, _, build := windows.RtlGetNtVersionNumbers()
	if maj < 10 || (maj == 10 && build <= 14393) {
		// the Windows 10 Anniversary Edition added VT100 support
		// enable vterm support in older versions of the Windows terminal
		if err := windows.GetConsoleMode(windows.Stdin, &inMode); err == nil {
			inMode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
			if err := windows.SetConsoleMode(windows.Stdin, inMode); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to set console mode: %v", err)
			}
		}
		if err := windows.GetConsoleMode(windows.Stdout, &outMode); err == nil {
			outMode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
			if err := windows.SetConsoleMode(windows.Stdout, outMode); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to set console mode: %v", err)
			}
		}
	}
}

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
