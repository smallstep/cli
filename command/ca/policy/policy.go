package policy

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/acme"
	"github.com/smallstep/cli/command/ca/policy/authority"
	"github.com/smallstep/cli/command/ca/policy/provisioner"
)

// Command returns the policy subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:        "policy",
		Usage:       "manage certificate issuance policies",
		UsageText:   "**step beta ca policy** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step beta ca policy** command group provides facilities for managing certificate issuance policies.`,
		Subcommands: cli.Commands{
			authority.Command(context.Background()),
			provisioner.Command(context.Background()),
			acme.Command(context.Background()),
		},
	}
}
