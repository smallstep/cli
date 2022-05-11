package user

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the SSH user policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithSSHUserPolicy(ctx)
	return cli.Command{
		Name:        "user",
		Usage:       "manage SSH user certificate issuance policies",
		UsageText:   "**step ca policy ssh user** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh user** command group provides facilities for managing SSH user certificate issuance policies.`,
		Subcommands: cli.Commands{
			allowCommand(ctx),
			denyCommand(ctx),
		},
	}
}
