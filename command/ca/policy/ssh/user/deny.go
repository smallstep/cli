package user

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// denyCommand returns the SSH user deny subcommand.
func denyCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithDeny(ctx)
	return cli.Command{
		Name:        "deny",
		Usage:       "manage denied SSH user certificate principals",
		UsageText:   "**step ca policy ssh user deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh user deny** command group provides facilities for managing SSH user certificate principals to be denied.`,
		Subcommands: cli.Commands{
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
