package ca

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func provisionersCommand() cli.Command {
	return cli.Command{
		Name:      "provisioners",
		Action:    cli.ActionFunc(provisionersAction),
		Usage:     "list provisioners configured in the CA",
		UsageText: `**step ca provisioners** [**--ca-url**=<uri>] [**--root**=<file>]`,
		Description: `**step ca provisioners** lists the provisioners configured on the certificate
authority`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
		},
	}
}

func provisionersAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	root := ctx.String("root")
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(provisioners, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioners")
	}

	fmt.Println(string(b))
	return nil
}
