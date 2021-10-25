package context

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
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
		UsageText: "**step context remove** <name> [**--force**]",
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
		Flags: []cli.Flag{
			flags.Force,
			flags.HiddenNoContext,
		},
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	name := ctx.Args()[0]

	if !ctx.Bool("force") {
		str, err := ui.Prompt(fmt.Sprintf("Are you sure you want to delete the configuration for context %s (this cannot be undone!) [y/n]", name), ui.WithValidateYesNo())
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(str)) {
		case "y", "yes":
		case "n", "no":
			return errors.New("context not removed")
		}
	}

	cs := step.Contexts()
	if !cs.Enabled() {
		return errors.Errorf("context '%s' not found - step path context management not enabled", name)
	}
	cur := cs.GetCurrent()
	c, ok := cs.Get(name)
	if !ok {
		return errors.Errorf("context '%s' not found", name)
	}
	if cur != nil && c.Name == cur.Name {
		return errors.Errorf("cannot remove current default context")
	}
	if err := os.RemoveAll(c.Path()); err != nil {
		return err
	}
	if err := os.RemoveAll(c.ProfilePath()); err != nil {
		return err
	}
	if err := cs.Remove(name); err != nil {
		return err
	}
	return nil
}
