package user

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// allowCommand returns the policy subcommand.
func allowCommand(ctx context.Context) cli.Command {
	ctx = policycontext.NewContextWithAllow(ctx)
	return cli.Command{
		Name:        "allow",
		Usage:       "manage SSH user certificate issuance policies",
		UsageText:   "**ssh user allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**ssh user allow** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
