package host

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the policy subcommand.
func allowCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithAllow(ctx)
	return cli.Command{
		Name:        "allow",
		Usage:       "manage SSH host certificate issuance policies",
		UsageText:   "**ssh host allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**ssh host allow** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
