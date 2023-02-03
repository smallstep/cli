package token

import (
	"github.com/urfave/cli"
)

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "token",
		Usage:     "create and manage tokens for connecting to the Smallstep API",
		UsageText: "step api token <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			createCommand(),
		},
		Description: `**step api token** command group provides commands for managing the
tokens required to connect to the Smallstep API.
`,
	}
}

// common flags used in several commands
var (
	apiURLFlag = cli.StringFlag{
		Name:  "api-url",
		Usage: "URL where the Smallstep API can be found.",
		Value: "https://gateway.smallstep.com",
	}
)
