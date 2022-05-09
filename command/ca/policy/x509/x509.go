package x509

import (
	"context"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/urfave/cli"
)

// Command returns the policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithX509Policy(ctx)
	return cli.Command{
		Name:        "x509",
		Usage:       "manage X.509 certificate issuance policies",
		UsageText:   "**step ca policy x509** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy x509** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			allowCommand(ctx),
			denyCommand(ctx),
		},
	}
}
