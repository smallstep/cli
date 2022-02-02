//go:build !windows
// +build !windows

package eab

import (
	"os"
	"os/signal"
	"syscall"
)

func pipeSignalHandler() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGCHLD)

	for range signals {
		signal.Stop(signals)
		os.Exit(0)
	}
}
