package acme

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/acme/eab"
)

// Command returns the acme subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:        "acme",
		Usage:       "manage ACME settings",
		UsageText:   "**step ca acme** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca acme** command group provides facilities for managing ACME.`,
		Subcommands: cli.Commands{
			eab.Command(),
		},
	}
}
