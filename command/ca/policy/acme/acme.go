package acme

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/command/ca/policy/x509"
)

// Command returns the ACME account policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithACMEPolicyLevel(ctx)
	return cli.Command{
		Name:      "acme",
		Usage:     "manage certificate issuance policies for ACME accounts.",
		UsageText: "**step ca policy acme** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy acme** command group provides facilities for managing certificate issuance policies for ACME accounts.

Please note that certificate issuance policies for ACME accounts are currently only supported in Certificate Manager: https://u.step.sm/cm.				

`,
		Subcommands: cli.Commands{
			actions.ViewCommand(ctx),
			actions.RemoveCommand(ctx),
			x509.Command(ctx),
		},
	}
}
