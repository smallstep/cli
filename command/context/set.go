package context

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/step"
)

func setCommand() cli.Command {
	return cli.Command{
		Name:      "set",
		Usage:     "set the default certificate authority context",
		UsageText: "**step context set**",
		Description: `**step context set** command sets the default certificate authority context.

## EXAMPLES

Set the default certificate authority context:
'''
$ step context set alpha-one
'''`,
		Action: command.ActionFunc(setAction),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:   "force",
				Usage:  `Create the JWK key pair for the provisioner.`,
				Hidden: true,
			},
		},
	}
}

func setAction(ctx *cli.Context) error {
	ctxStr := ctx.Args().Get(0)
	if _, ok := step.GetContext(ctxStr); !ok {
		return errors.Errorf("context '%s' not found", ctxStr)
	}

	type currentCtxType struct {
		Context string `json:"context"`
	}
	def := currentCtxType{Context: ctxStr}
	b, err := json.Marshal(def)
	if err != nil {
		return err
	}
	ctx.Set("force", "true")
	if err = fileutil.WriteFile(step.CurrentContextFile(), b, 0644); err != nil {
		return errs.FileError(err, step.CurrentContextFile())
	}
	return nil
}
