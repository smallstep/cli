package user

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// denyCommand returns the policy subcommand.
func denyCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "deny",
		Usage:       "manage SSH host certificate issuance policies",
		UsageText:   "**ssh user deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**ssh user deny** command group provides facilities for managing SSH certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.EmailCommand(policycontext.NewContextWithDeny(ctx)),
			actions.PrincipalsCommand(policycontext.NewContextWithDeny(ctx)),
		},
	}
}
