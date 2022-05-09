package host

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the SSH host policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithSSHHostPolicy(ctx)
	return cli.Command{
		Name:        "host",
		Usage:       "manage SSH host certificate issuance policies",
		UsageText:   "**step ca policy ssh host** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh host** command group provides facilities for managing SSH host certificate issuance policies.`,
		Subcommands: cli.Commands{
			allowCommand(ctx),
			denyCommand(ctx),
		},
	}
}
