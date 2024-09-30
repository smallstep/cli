package provisioner

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:   "list",
		Action: cli.ActionFunc(listAction),
		Usage:  "list provisioners configured in the CA",
		UsageText: `**step ca provisioner list**
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step ca provisioner list** lists the provisioners configured
in the CA.

## EXAMPLES

Prints a JSON list with active provisioners:
'''
$ step ca provisioner list
'''`,
	}
}

func listAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	root := ctx.String("root")
	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return errors.Wrap(err, "error getting the provisioners")
	}

	b, err := json.MarshalIndent(provisioners, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioners")
	}

	fmt.Println(string(b))
	return nil
}
