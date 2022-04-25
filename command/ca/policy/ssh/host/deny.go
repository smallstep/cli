package host

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the policy subcommand.
func denyCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "deny",
		Usage:       "manage SSH host certificate issuance policies",
		UsageText:   "**ssh host deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**ssh host deny** command group provides facilities for managing SSH certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.DNSCommand(policycontext.NewContextWithDeny(ctx)),
			actions.EmailCommand(policycontext.NewContextWithAllow(ctx)),
			actions.PrincipalsCommand(policycontext.NewContextWithDeny(ctx)),
		},
	}
}
