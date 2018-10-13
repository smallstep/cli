package provisioner

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func getEncryptedKeyCommand() cli.Command {
	return cli.Command{
		Name:   "provisioning-key",
		Action: cli.ActionFunc(getEncryptedKeyAction),
		Usage:  "retrieves and prints a provisioning key in the CA",
		UsageText: `**step ca provisioner enc-key** <kid> [**--ca-url**=<uri>]
[**--root**=<file>]`,
		Description: `**step ca provisioner enc-key** retrieists the provisioners configured on the certificate
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

func getEncryptedKeyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	kid := ctx.Args().Get(0)
	root := ctx.String("root")
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	key, err := pki.GetProvisionerKey(caURL, root, kid)
	if err != nil {
		return errors.Wrap(err, "error getting the provisioning key")
	}

	fmt.Println(key)
	return nil
}
