package context

import (
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
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
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	name := ctx.Args().Get(0)
	if err := step.Contexts().SaveCurrent(name); err != nil {
		return err
	}
	ui.PrintSelected("Context", name)
	return nil
}
