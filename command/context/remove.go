package context

import (
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
)

func removeCommand() cli.Command {
	return cli.Command{
		Hidden:    true,
		Name:      "remove",
		Usage:     "remove a context and all associated configuration",
		UsageText: "**step context remove** <name>",
		Description: `**step context remove** command removes a context, along
with all associated configuration, from disk.

## POSITIONAL ARGUMENTS

<name>
:  The name of the context to remove .

## EXAMPLES

Remove a context:
'''
$ step context remove alpha-one
'''`,
		Action: command.ActionFunc(removeAction),
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	name := ctx.Args()[0]

	if !step.IsContextEnabled() {
		return errors.Errorf("context '%s' not found - step path context management not enabled", name)
	}
	stepCtx := step.GetCurrentContext()
	if stepCtx.Name == name {
		return errors.Errorf("cannot remove current default context")
	}
	if err := step.SwitchCurrentContext(name); err != nil {
		return err
	}
	if err := os.RemoveAll(step.Path()); err != nil {
		return err
	}
	if err := os.RemoveAll(step.ProfilePath()); err != nil {
		return err
	}
	if err := step.RemoveContext(name); err != nil {
		return err
	}
	return nil
}
