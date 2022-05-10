package x509

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the deny subcommand.
func denyCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithDeny(ctx)
	return cli.Command{
		Name:        "deny",
		Usage:       "manage denied names for X.509 certificate issuance policies",
		UsageText:   "**step ca policy x509 deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy x509 deny** command group provides facilities for managing X.509 names to be denied.`,
		Subcommands: cli.Commands{
			actions.CommonNamesCommand(ctx),
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.IPCommand(ctx),
			actions.URICommand(ctx),
		},
	}
}
