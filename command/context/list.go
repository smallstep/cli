package context

import (
	"github.com/smallstep/cli/ui"
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
alpha-one.ca.smallstep.com
alpha-two.ca.smallstep.com
beta.ca.smallstep.com
'''`,
		Action: command.ActionFunc(listAction),
	}
}

func listAction(ctx *cli.Context) error {
	cm := step.GetContextMap()

	def := step.GetCurrentContext()
	if def != nil {
		ui.Printf("▶ %s\n", def.Name)
	}

	for k := range cm {
		if k == def.Name {
			continue
		}
		ui.Println(k)
	}
	return nil
}
