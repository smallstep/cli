package admin

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/certificates/linkedca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:   "list",
		Action: cli.ActionFunc(listAction),
		Usage:  "list all admins in the CA configuration",
		UsageText: `**step ca admin list** [**--super**] ]**--not-super**] [**--provisioner**=<string>]
[**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			cli.BoolFlag{
				Name:  "super",
				Usage: `Only return super-admins.`,
			},
			flags.X5cCert,
			flags.X5cKey,
			flags.PasswordFile,
			cli.BoolFlag{
				Name:  "not-super",
				Usage: `Only return admins without 'super' privileges.`,
			},
			cli.StringFlag{
				Name:  "provisioner",
				Usage: `Only return admins linked to this provisioner.`,
			},
		},
		Description: `**step ca admin list** lists all admins in the CA configuration.

## EXAMPLES

List all admins:
'''
$ step ca admin list
'''

List only super-admins:
'''
$ step ca admin list --super
'''

List only admins without super-admin privileges:
'''
$ step ca admin list --not-super
'''

List all admins associated with a given provisioner:
'''
$ step ca admin list --provisioner admin-jwk
'''

List only super-admins associated with a given provisioner:
'''
$ step ca admin list --super --provisioner admin-jwk
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	isSuperAdmin := ctx.IsSet("super")
	isNotSuperAdmin := ctx.IsSet("not-super")

	if isSuperAdmin && isNotSuperAdmin {
		return errs.IncompatibleFlag(ctx, "super", "not-super")
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	admins, err := client.GetAdmins()
	if err != nil {
		return err
	}
	cliAdmins, err := listToCLI(ctx, client, admins)
	if err != nil {
		return err
	}
	provName := ctx.String("provisioner")
	cliAdmins = adminFilter(cliAdmins, func(a *cliAdmin) bool {
		if isSuperAdmin && a.Type != linkedca.Admin_SUPER_ADMIN {
			return false
		}
		if isNotSuperAdmin && a.Type == linkedca.Admin_SUPER_ADMIN {
			return false
		}
		if len(provName) > 0 && a.ProvisionerName != provName {
			return false
		}
		return true
	})

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "SUBJECT\tPROVISIONER\tTYPE")
	for _, cliAdm := range cliAdmins {
		fmt.Fprintf(w, "%s\t%s (%s)\t%s\n", cliAdm.Subject, cliAdm.ProvisionerName, cliAdm.ProvisionerType, cliAdm.Type)
	}
	w.Flush()
	return nil
}
