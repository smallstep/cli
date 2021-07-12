package admin

import (
	"fmt"
	"os"
	"text/tabwriter"

	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/linkedca"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(addAction),
		Usage:     "add an admin to the CA configuration",
		UsageText: `**step beta ca admin add** <subject> <provisioner> [**--super**]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "super",
				Usage: `Give administrator SuperAdmin privileges.`,
			},
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca admin add** adds an admin to the CA configuration.

## POSITIONAL ARGUMENTS

<subject>
: The subject name that must appear in the identifying credential of the admin.

<provisioner>
: The name of the provisioner

## EXAMPLES

Add regular Admin:
'''
$ step beta ca admin add max@smallstep.com google
'''

Add SuperAdmin:
'''
$ step beta ca admin add max@smallstep.com google --super
'''
`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	subject := args.Get(0)
	provName := args.Get(1)

	typ := linkedca.Admin_ADMIN
	if ctx.Bool("super") {
		typ = linkedca.Admin_SUPER_ADMIN
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	adm, err := client.CreateAdmin(&adminAPI.CreateAdminRequest{
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
