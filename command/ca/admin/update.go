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

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update an admin",
		UsageText: `**step beta ca admin update** <subject> [**--super**] [**--provisioner**=<name>]
[**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "super",
				Usage: `Update the admin with super-admin privileges.`,
			},
			cli.StringFlag{
				Name:  "provisioner",
				Usage: `Filter admin by provisioner name`,
			},
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca admin update** updates an admin.

## POSITIONAL ARGUMENTS

<id>
: The name of the admin to update.

## EXAMPLES

Add super-admin privileges to an admin:
'''
$ step beta ca admin update max@smallstep.com --super
'''

Specify admin by provisioner:
'''
$ step beta ca admin update max@smallstep.com --super --provisioner devops-jwk
'''

Remove super-admin privileges from an admin:
'''
$ step beta ca admin update max@smallstep.com --super=false
'''
`,
	}
}

func updateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	setSuperAdmin := ctx.IsSet("super") && ctx.Bool("super")
	setNotSuperAdmin := ctx.IsSet("super") && !ctx.Bool("super")

	if !setSuperAdmin && !setNotSuperAdmin {
		return errs.RequiredFlag(ctx, "super")
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	admins, err := client.GetAdmins()
	if err != nil {
		return err
	}
	cliAdm, err := adminPrompt(ctx, client, admins)
	if err != nil {
		return err
	}

	var typ linkedca.Admin_Type
	if setSuperAdmin {
		typ = linkedca.Admin_SUPER_ADMIN
	}
	if setNotSuperAdmin {
		typ = linkedca.Admin_ADMIN
	}
	adm, err := client.UpdateAdmin(cliAdm.Id, &adminAPI.UpdateAdminRequest{
		Type: typ,
	})
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "SUBJECT\tPROVISIONER\tTYPE")
	fmt.Fprintf(w, "%s\t%s (%s)\t%s\n", adm.Subject, cliAdm.ProvisionerName, cliAdm.ProvisionerType, adm.Type.String())
	w.Flush()

	return nil
}
