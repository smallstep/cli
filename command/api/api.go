package api

import (
	"github.com/smallstep/cli/command/api/token"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
)

func init() {
	cmd := cli.Command{
		Name:      "api",
		Usage:     "authenticate to the Smallstep API",
		UsageText: "**step api** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step api** provides commands for connecting to the Smallstep API.
`,
		Subcommands: cli.Commands{
			token.Command(),
		},
	}

	command.Register(cmd)
}
