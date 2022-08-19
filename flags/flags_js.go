//go:build js
// +build js

package flags

import (
	"syscall"

	"github.com/urfave/cli"
)

var (

	// Signal is a cli.Flag used to specify the signal (number) to send to
	// a process with PID.
	Signal = cli.IntFlag{
		Name: "signal",
		Usage: `The signal <number> to send to the selected PID, so it can reload the
			configuration and load the new certificate. Default value is SIGHUP (1)`,
		Value: int(syscall.SIGTERM), // in js/wasm, there's no SIGHUP; default to SIGTERM (for now)
	}
)
