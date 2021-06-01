package admin

import (
	"fmt"
	"os"
	"text/tabwriter"

	mgmtAPI "github.com/smallstep/certificates/authority/mgmt/api"
	"github.com/smallstep/certificates/linkedca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(addAction),
		Usage:     "add an admin to the CA configuration",
		UsageText: `**step ca admin add** <provisioner> <subject> [**--super**]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			cli.BoolFlag{
				Name:  "super",
				Usage: `Give administrator SuperAdmin privileges.`,
			},
		},
		Description: `**step ca admin add** adds an admin to the CA configuration.

## POSITIONAL ARGUMENTS

<provisioner>
: The name of the provisioner

<subject>
: The subject name that must appear in the identifying credential of the admin.

## EXAMPLES

Add regular Admin:
'''
$ step ca admin add admin-jwk max@smallstep.com admin-jwk
'''

Add SuperAdmin:
'''
$ step ca admin add admin-jwk max@smallstep.com --super
'''
`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	provName := args.Get(0)
	subject := args.Get(1)

	typ := linkedca.Admin_ADMIN
	if ctx.IsSet("super") {
		typ = linkedca.Admin_SUPER_ADMIN
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	adm, err := client.CreateAdmin(&mgmtAPI.CreateAdminRequest{
		Subject:     subject,
		Provisioner: provName,
		Type:        typ,
	})
	if err != nil {
		return err
	}

	cliAdm, err := toCLI(ctx, client, adm)
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "SUBJECT\tPROVISIONER\tTYPE")
	fmt.Fprintf(w, "%s\t%s (%s)\t%s\n", cliAdm.Subject, cliAdm.ProvisionerName, cliAdm.ProvisionerType, adm.Type.String())
	w.Flush()
	return nil
}
