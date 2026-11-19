package context

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/step"

	"github.com/smallstep/cli/flags"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Usage:     "list available certificate authority contexts",
		UsageText: "**step context list**",
		Description: `**step context list** command lists available certificate authority contexts.

## EXAMPLES

List all certificate authority contexts:
'''
$ step context list
▶ alpha-one
alpha-two
ssh.beta
'''`,
		Action: command.ActionFunc(listAction),
		Flags: []cli.Flag{
			flags.HiddenNoContext,
		},
	}
}

func listAction(*cli.Context) error {
	cs := step.Contexts()

	contexts := cs.ListAlphabetical()
	if len(contexts) == 0 {
		// Printing nothing and exiting 0 is indistinguishable from a STEPPATH
		// that has contexts but none of them listable, so say so and fail the
		// way `step context current` does when there is nothing selected.
		return errors.New("no contexts present")
	}

	cur := cs.GetCurrent()
	if cur != nil {
		fmt.Printf("▶ %s\n", cur.Name)
	}

	for _, v := range contexts {
		if cur != nil && v.Name == cur.Name {
			continue
		}
		fmt.Println(v.Name)
	}
	return nil
}
