package api

import (
	"fmt"

	"github.com/smallstep/cli/command/api/token"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/step"
)

func init() {
	cmd := cli.Command{
		Name:      "api",
		Usage:     "connect to the Smallstep API",
		UsageText: "**step api**",
		Description: `**step api** provides commands for connecting to the Smallstep API.
`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "api-url",
				Usage: "Override the default Smallstep API endpoint",
			},
		},
		Action: cli.ActionFunc(func(ctx *cli.Context) error {
			fmt.Println(step.Path())
			return nil
		}),
		Subcommands: cli.Commands{
			token.Command(),
		},
	}

	command.Register(cmd)
}
