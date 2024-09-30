package provisioner

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

func getEncryptedKeyCommand() cli.Command {
	return cli.Command{
		Name:   "jwe-key",
		Action: cli.ActionFunc(getEncryptedKeyAction),
		Usage:  "retrieve and print a provisioning key in the CA",
		UsageText: `**step ca provisioner jwe-key** <kid>
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ca provisioner jwe-key** returns the encrypted
private jwk for the given key-id.

## EXAMPLES

Retrieve the encrypted private jwk for the given key-id:
'''
$ step ca provisioner jwe-key 1234 --ca-url https://127.0.0.1 --root ./root.crt
'''
`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func getEncryptedKeyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	kid := ctx.Args().Get(0)
	root := ctx.String("root")
	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	key, err := pki.GetProvisionerKey(caURL, root, kid)
	if err != nil {
		return errors.Wrap(err, "error getting the provisioning key")
	}

	fmt.Println(key)
	return nil
}
