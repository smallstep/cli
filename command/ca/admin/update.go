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

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update an admin",
		UsageText: `**step ca admin update** <subject> [**--super**]
[**--not-super**] [**--provisioner**=<name>] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "super",
				Usage: `Update the admin with super-admin privileges.`,
			},
			cli.BoolFlag{
				Name:  "not-super",
				Usage: `Update the admin to remove super-admin privileges.`,
			},
			cli.StringFlag{
				Name:  "provisioner",
				Usage: `Update the admin name.`,
			},
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca admin update** updates an admin.

## POSITIONAL ARGUMENTS

<id>
: The name of the admin to update.

## EXAMPLES

Add super-admin privileges to an admin:
'''
$ step ca admin update max@smallstep.com --super
'''

Specify admin by provisioner:
'''
$ step ca admin update max@smallstep.com --super --provisioner devops-jwk
'''

Remove super-admin privileges from an admin:
'''
$ step ca admin update max@smallstep.com --not-super
'''
`,
	}
}

func updateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	isSuperAdmin := ctx.IsSet("super")
	isNotSuperAdmin := ctx.IsSet("not-super")

	if isSuperAdmin && isNotSuperAdmin {
		return errs.IncompatibleFlag(ctx, "super", "not-super")
	}
	if !isSuperAdmin && !isNotSuperAdmin {
		return errs.RequiredOrFlag(ctx, "super", "not-super")
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
	if ctx.IsSet("super") {
		typ = linkedca.Admin_SUPER_ADMIN
	}
	if ctx.IsSet("not-super") {
		typ = linkedca.Admin_ADMIN
	}
	adm, err := client.UpdateAdmin(cliAdm.Id, &mgmtAPI.UpdateAdminRequest{
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
