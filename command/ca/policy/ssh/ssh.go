package ssh

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/ssh/host"
	"github.com/smallstep/cli/command/ca/policy/ssh/user"
)

// Command returns the policy subcommand.
func Command(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "ssh",
		Usage:       "manage SSH certificate issuance policies",
		UsageText:   "**ssh** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**ssh** command group provides facilities for managing SSH certificate issuance policies.`,
		Subcommands: cli.Commands{
			host.Command(ctx),
			user.Command(ctx),
		},
	}
}
