package authority

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/command/ca/policy/ssh"
	"github.com/smallstep/cli/command/ca/policy/x509"
)

// Command returns the authority policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithAuthorityPolicyLevel(ctx)
	return cli.Command{
		Name:        "authority",
		Usage:       "manage certificate issuance policies for authorities",
		UsageText:   "**step ca policy authority** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy authority** command group provides facilities for managing certificate issuance policies for authorities.`,
		Subcommands: cli.Commands{
			actions.ViewCommand(ctx),
			actions.RemoveCommand(ctx),
			x509.Command(ctx),
			ssh.Command(ctx),
		},
	}
}
