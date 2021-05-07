package admin

import (
	"fmt"

	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(addAction),
		Usage:     "add an admin to the CA configuration",
		UsageText: `**step ca admin add** <name> <provisioner> [**--super**]`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.PasswordFile,
			cli.BoolFlag{
				Name:  "super",
				Usage: `Give administrator SuperAdmin privileges.`,
			},
		},
		Description: `**step ca admin add** adds an admin.

## POSITIONAL ARGUMENTS

<name>
: The name of the admin. This name must appear in the admin's identity certificate SANs.

<provisioner>
: The name of the provisioner

## EXAMPLES

Add regular Admin:
'''
$ step ca admin add max@smallstep.com admin-jwk
'''

Add SuperAdmin:
'''
$ step ca admin add max@smallstep.com admin-jwk
'''
`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if ctx.NArg() == 0 {
		return errs.TooFewArguments(ctx)
	}

	/*
		args := ctx.Args()
		name := args[0]

		caURL, err := flags.ParseCaURLIfExists(ctx)
		if err != nil {
			return err
		}
		rootFile := ctx.String("root")
		if len(rootFile) == 0 {
			rootFile = pki.GetRootCAPath()
		}

		// Create online client
		var options []ca.ClientOption
		options = append(options, ca.WithRootFile(rootFile))
		client, err := ca.NewMgmtClient(caURL, options...)
		if err != nil {
			return err
		}
	*/

	fmt.Println("success!\n")
	return nil
}
