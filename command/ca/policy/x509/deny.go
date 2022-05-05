package x509

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the policy subcommand.
func denyCommand(ctx context.Context) cli.Command {
	ctx = policycontext.NewContextWithDeny(ctx)
	return cli.Command{
		Name:        "deny",
		Usage:       "manage denied names for X.509 certificate issuance policies",
		UsageText:   "**x509 deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**x509 deny** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.CommonNamesCommand(ctx),
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.IPCommand(ctx),
			actions.URICommand(ctx),
		},
	}
}
