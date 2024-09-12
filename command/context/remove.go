package context

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/fileutil"
	"github.com/smallstep/cli-utils/step"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
)

func removeCommand() cli.Command {
	return cli.Command{
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

	cs := step.Contexts()
	if !cs.Enabled() {
		return errors.Errorf("context '%s' not found - step path context management not enabled", name)
	}
	cur := cs.GetCurrent()
	target, ok := cs.Get(name)
	if !ok {
		return errors.Errorf("context '%s' not found", name)
	}
	if cur != nil && target.Name == cur.Name {
		return errors.Errorf("cannot remove current context")
	}

	// Check if either authority or profile should not be removed because it
	// is being used by another context.
	saveAuthority, saveProfile := false, false
	for _, c := range cs.List() {
		if target.Name == c.Name {
			continue
		}
		if saveAuthority && saveProfile {
			break
		}
		if !saveAuthority && target.Authority == c.Authority {
			saveAuthority = true
		}
		if !saveProfile && target.Profile == c.Profile {
			saveProfile = true
		}
	}

	if !ctx.Bool("force") && !(saveAuthority && saveProfile) {
		ui.Printf("The following directories will be removed:\n")
		ui.Println()
		if !saveAuthority {
			ui.Printf("  - %s\n", target.Path())
		}
		if !saveProfile {
			ui.Printf("  - %s\n", target.ProfilePath())
		}
		ui.Println()

		if ok, err := ui.PromptYesNo(fmt.Sprintf("Are you sure you want to delete the configuration for context %s (this cannot be undone!) [y/n]", name)); err != nil {
			return err
		} else if !ok {
			return errors.New("context not removed")
		}
	}

	if !saveAuthority {
		if err := os.RemoveAll(target.Path()); err != nil {
			return err
		}
	}
	if !saveProfile {
		if err := os.RemoveAll(target.ProfilePath()); err != nil {
			return err
		}
	}
	if err := cs.Remove(name); err != nil {
		return err
	}

	// Attempt to remove line associated with the authority from removed context.
	return fileutil.RemoveLine(filepath.Join(step.BasePath(), "ssh", "includes"), target.Authority)
}
