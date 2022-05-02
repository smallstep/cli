package x509

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
		Usage:       "manage denied names for X.509 certificate issuance policies",
		UsageText:   "**x509 deny** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**x509 deny** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.CommonNamesCommand(policycontext.NewContextWithDeny(ctx)),
			actions.DNSCommand(policycontext.NewContextWithDeny(ctx)),
			actions.EmailCommand(policycontext.NewContextWithDeny(ctx)),
			actions.IPCommand(policycontext.NewContextWithDeny(ctx)),
			actions.URICommand(policycontext.NewContextWithDeny(ctx)),
		},
	}
}
