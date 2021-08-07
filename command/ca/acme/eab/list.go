package eab

import (
	"fmt"

	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(listAction),
		Usage:     "list all ACME External Account Binding Keys",
		UsageText: `**step beta ca acme eab list** [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca acme eab list** lists all ACME External Account Binding Keys.

## EXAMPLES

List all ACME External Account Binding Keys:
'''
$ step beta ca acme eab list
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	eaks, err := client.GetExternalAccountKeys()
	if err != nil {
		return err
	}

	fmt.Println(eaks)

	return nil
}
