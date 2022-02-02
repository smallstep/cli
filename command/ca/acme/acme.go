package acme

import (
	"github.com/smallstep/cli/command/ca/acme/eab"
	"github.com/urfave/cli"
)

// Command returns the acme subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:        "acme",
		Usage:       "manage ACME",
		UsageText:   "**step beta ca acme** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step beta ca acme** command group provides facilities for managing ACME.`,
		Subcommands: cli.Commands{
			eab.Command(),
		},
	}
}
