package api

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"

	"github.com/smallstep/cli/command/api/token"
)

func init() {
	cmd := cli.Command{
		Hidden:    true,
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
