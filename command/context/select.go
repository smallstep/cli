package context

import (
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/step"
)

func selectCommand() cli.Command {
	return cli.Command{
		Name:      "select",
		Usage:     "select the default certificate authority context",
		UsageText: "**step context select**",
		Description: `**step context select** command sets the default certificate authority context.

## EXAMPLES

Select the default certificate authority context:
'''
$ step context select alpha-one
'''`,
		Action: command.ActionFunc(selectAction),
		Flags: []cli.Flag{
			flags.HiddenNoContext,
		},
	}
}

func selectAction(ctx *cli.Context) error {
	name := ctx.Args().Get(0)
	if err := step.Contexts().SaveCurrent(name); err != nil {
		return err
	}
	ui.PrintSelected("Context", name)
	return nil
}
