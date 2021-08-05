package admin

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/linkedca"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:   "list",
		Action: cli.ActionFunc(listAction),
		Usage:  "list all admins in the CA configuration",
		UsageText: `**step beta ca admin list** [**--super**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "super",
				Usage: `Only return super-admins.`,
			},
			provisionerFilterFlag,
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step beta ca admin list** lists all admins in the CA configuration.

## EXAMPLES

List all admins:
'''
$ step beta ca admin list
'''

List only super-admins:
'''
$ step beta ca admin list --super
'''

List only admins without super-admin privileges:
'''
$ step beta ca admin list --super=false
'''

List all admins associated with a given provisioner:
'''
$ step beta ca admin list --provisioner admin-jwk
'''

List only super-admins associated with a given provisioner:
'''
$ step beta ca admin list --super --provisioner admin-jwk
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	isSuperAdmin := ctx.IsSet("super") && ctx.Bool("super")
	isNotSuperAdmin := ctx.IsSet("super") && !ctx.Bool("super")

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
