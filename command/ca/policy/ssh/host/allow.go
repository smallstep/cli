package host

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the SSH host allow subcommand.
func allowCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithAllow(ctx)
	return cli.Command{
		Name:        "allow",
		Usage:       "manage allowed SSH host certificate principals",
		UsageText:   "**step ca policy ssh host allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh host allow** command group provides facilities for managing SSH host certificate principals to be allowed.`,
		Subcommands: cli.Commands{
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
