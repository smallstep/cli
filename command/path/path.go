package path

import (
	"fmt"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/config"
	"github.com/urfave/cli"
)

func init() {
	cmd := cli.Command{
		Name:      "path",
		Usage:     "print the configured step path and exit",
		UsageText: "step path",
		Description: `**step path** command prints the configured step path and exits.

The default step path of $HOME/.step can be overridden with the **STEPPATH** environment variable.`,
		Action: cli.ActionFunc(func(ctx *cli.Context) error {
			fmt.Println(config.StepPath())
			return nil
		}),
	}

	command.Register(cmd)
}
