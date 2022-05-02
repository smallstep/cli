package x509

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// Command returns the policy subcommand.
func allowCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "allow",
		Usage:       "manage allowed names for X.509 certificate issuance policies",
		UsageText:   "**x509 allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**x509 allow** command group provides facilities for managing X.509 certificate issuance policies.`,
		Subcommands: cli.Commands{
			actions.CommonNamesCommand(policycontext.NewContextWithAllow(ctx)),
			actions.DNSCommand(policycontext.NewContextWithAllow(ctx)),
			actions.EmailCommand(policycontext.NewContextWithAllow(ctx)),
			actions.IPCommand(policycontext.NewContextWithAllow(ctx)),
			actions.URICommand(policycontext.NewContextWithAllow(ctx)),
		},
	}
}
