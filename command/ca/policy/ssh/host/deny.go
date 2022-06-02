package host

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the SSH host deny subcommand.
func denyCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithDeny(ctx)
	return cli.Command{
		Name:        "deny",
		Usage:       "manage denied dSSH host certificate principals",
		UsageText:   "**step ca policy ssh host deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh host deny** command group provides facilities for managing SSH host certificate principals to be denied.`,
		Subcommands: cli.Commands{
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.PrincipalsCommand(ctx),
		},
	}
}
