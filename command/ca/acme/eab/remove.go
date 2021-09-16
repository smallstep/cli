package eab

import (
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove an ACME EAB Key from the CA",
		UsageText: `**step beta ca acme eab remove** <key_id> 
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca acme eab remove** removes an ACME EAB Key from the CA.

## POSITIONAL ARGUMENTS

<key_id>
: The ACME EAB Key ID to remove

## EXAMPLES

Remove ACME EAB Key with Key ID "zFGdKC1sHmNf3Wsx3OujY808chxwEdmr":
'''
$ step beta ca acme eab remove zFGdKC1sHmNf3Wsx3OujY808chxwEdmr
'''
`,
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	keyID := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	err = client.RemoveExternalAccountKey(keyID)
	if err != nil {
		return err
	}

	ui.Println("Key was deleted successfully!")

	return nil
}
