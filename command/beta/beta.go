package beta

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"

	"github.com/smallstep/cli/command/ca"
)

// init creates and registers the ca command
func init() {
	cmd := cli.Command{
		Name:      "beta",
		Usage:     "commands that are being tested; these APIs are likely to change",
		UsageText: "step beta <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step beta** command group provides access to new APIs that are in development.
`,
		Subcommands: cli.Commands{
			ca.BetaCommand(),
		},
	}

	command.Register(cmd)
}
