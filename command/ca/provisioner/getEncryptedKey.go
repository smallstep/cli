package provisioner

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func getEncryptedKeyCommand() cli.Command {
	return cli.Command{
		Name:   "jwe-key",
		Action: cli.ActionFunc(getEncryptedKeyAction),
		Usage:  "retrieve and print a provisioning key in the CA",
		UsageText: `**step ca provisioner jwe-key** <kid> [**--ca-url**=<uri>]
[**--root**=<file>]`,
		Description: `**step ca provisioner jwe-key** returns the encrypted
private jwk for the given key-id.

## EXAMPLES

Retrieve the encrypted private jwk for the given key-id:
'''
$ step ca provisioner jwe-key 1234 --ca-url https://127.0.0.1 --root ./root.crt
'''
`,
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
