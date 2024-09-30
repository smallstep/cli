package context

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/step"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
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
