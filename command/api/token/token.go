package token

import (
	"github.com/urfave/cli"
)

// Command returns the token subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "token",
		Usage:     "create tokens for connecting to the Smallstep API",
		UsageText: "step api token <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			createCommand(),
		},
		Description: `**step api token** command group provides commands for creating the
tokens required to connect to the Smallstep API.
`,
	}
}

// common flags
var (
	apiURLFlag = cli.StringFlag{
		Name:  "api-url",
		Usage: "URL where the Smallstep API can be found",
		Value: "https://gateway.smallstep.com",
	}
	audienceFlag = cli.StringFlag{
		Name:  "audience",
		Usage: "Request a token for an audience other than the API Gateway",
	}
)
