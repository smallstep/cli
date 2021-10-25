package context

import (
	"fmt"

	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/step"
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

func listAction(ctx *cli.Context) error {
	cs := step.Contexts()

	cur := cs.GetCurrent()
	if cur != nil {
		fmt.Printf("▶ %s\n", cur.Name)
	}

	for _, v := range cs.List() {
		if cur != nil && v.Name == cur.Name {
			continue
		}
		fmt.Println(v.Name)
	}
	return nil
}
