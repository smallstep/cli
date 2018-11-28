package flags

import (
	"github.com/urfave/cli"
)

// Subtle is the flag required for delicate operations.
var Subtle = cli.BoolFlag{
	Name: "subtle",
}

// Insecure is the flag required on insecure operations
var Insecure = cli.BoolFlag{
	Name: "insecure",
}

// Force is a cli.Flag used to overwrite files.
var Force = cli.BoolFlag{
	Name:  "f,force",
	Usage: "Force the overwrite of files without asking.",
}
