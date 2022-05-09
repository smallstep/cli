package acme

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/acme/eab"
	"github.com/smallstep/cli/internal/command"
)

// Command returns the acme subcommand.
func Command() cli.Command {
	ctx := context.Background()
	return cli.Command{
		Name:        "acme",
		Usage:       "manage ACME settings",
		UsageText:   "**step ca acme** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca acme** command group provides facilities for managing ACME.`,
		Hidden:      command.ShouldBeHidden(ctx), // the `step ca acme` command is not shown in help (for now), unless STEPBETA=1 is provided
		Subcommands: cli.Commands{
			eab.Command(),
		},
	}
}
