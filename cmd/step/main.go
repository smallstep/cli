package main

import (
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/step"

	"github.com/smallstep/cli/internal/cmd"
)

// Version is set by an LDFLAG at build time representing the git tag or commit
// for the current release
var Version = "N/A"

// BuildTime is set by an LDFLAG at build time representing the timestamp at
// the time of build
var BuildTime = "N/A"

// AppName is the name of the binary. Defaults to "step" if not set.
var AppName = ""

func init() {
	step.Set("Smallstep CLI", Version, BuildTime)
	ca.UserAgent = step.Version()
	cmd.SetName(AppName)
}

func main() {
	cmd.Run()
}
