package x509

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
)

// allowCommand returns the allow subcommand.
func allowCommand(ctx context.Context) cli.Command {
	ctx = policycontext.WithAllow(ctx)
	return cli.Command{
		Name:        "allow",
		Usage:       "manage allowed names for X.509 certificate issuance policies",
		UsageText:   "**step ca policy <scope> x509 allow** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy <scope> x509 allow** command group provides facilities for managing X.509 names to be allowed.`,
		Subcommands: cli.Commands{
			actions.CommonNamesCommand(ctx),
			actions.DNSCommand(ctx),
			actions.EmailCommand(ctx),
			actions.IPCommand(ctx),
			actions.URICommand(ctx),
		},
	}
}
