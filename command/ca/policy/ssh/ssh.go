package ssh

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/ssh/host"
	"github.com/smallstep/cli/command/ca/policy/ssh/user"
)

// Command returns the ssh subcommand.
func Command(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "ssh",
		Usage:       "manage SSH certificate issuance policies",
		UsageText:   "**step ca policy ssh** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy ssh** command group provides facilities for managing SSH certificate issuance policies.`,
		Subcommands: cli.Commands{
			host.Command(ctx),
			user.Command(ctx),
		},
	}
}
