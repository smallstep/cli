package beta

import (
	"github.com/smallstep/cli/command/ca"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
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
