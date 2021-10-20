package context

import (
	"fmt"

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
	}
}

func listAction(ctx *cli.Context) error {
	cm := step.GetContextMap()

	def := step.GetCurrentContext()
	if def != nil {
		fmt.Printf("▶ %s\n", def.Name)
	}

	for k := range cm {
		if def != nil && k == def.Name {
			continue
		}
		fmt.Println(k)
	}
	return nil
}
