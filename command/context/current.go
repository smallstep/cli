package context

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/step"

	"github.com/smallstep/cli/flags"
)

func currentCommand() cli.Command {
	return cli.Command{
		Name:      "current",
		Usage:     "current returns the name of the current context",
		UsageText: "**step context current** [**--json**]",
		Description: `**step context current** returns the name of the current context.

## EXAMPLES

List all certificate authority contexts:
'''
$ step context current
test-ca
'''

'''
$ step context current --json
{"name":"test-ca","authority":"internal.ca.smallstep.com","profile":"test-ca"}
'''`,
		Action: command.ActionFunc(currentAction),
		Flags: []cli.Flag{
			flags.HiddenNoContext,
			cli.BoolFlag{
				Name:  "json",
				Usage: `Return stringified JSON containing the main attributes of a context.`,
			},
		},
	}
}

func currentAction(ctx *cli.Context) error {
	cur := step.Contexts().GetCurrent()
	if cur == nil {
		return errors.New("no context selected")
	}

	if ctx.Bool("json") {
		b, err := json.Marshal(struct {
			Name      string `json:"name"`
			Authority string `json:"authority"`
			Profile   string `json:"profile"`
		}{
			Name:      cur.Name,
			Authority: cur.Authority,
			Profile:   cur.Profile,
		})
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
	} else {
		fmt.Printf("%s\n", cur.Name)
	}
	return nil
}
