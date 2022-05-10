package user

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// allowCommand returns the SSH user allow subcommand.
func allowCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithAllow(ctx)
	return cli.Command{
		Name:        "allow",
		Usage:       "manage allowed SSH user certificate principals",
		UsageText:   "**step ca policy ssh user allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh user allow** command group provides facilities for managing SSH user certificate principals to be allowed.`,
		Subcommands: cli.Commands{
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
