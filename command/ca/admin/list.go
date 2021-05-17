package admin

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/certificates/authority/mgmt"
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

	client, err := cautils.NewMgmtClient(ctx)
	if err != nil {
		return err
	}

	admins, err := client.GetAdmins()
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		fmt.Println("authority no admins configured")
		return nil
	}
	provName := ctx.String("provisioner")
	admins = adminFilter(admins, func(adm *mgmt.Admin) bool {
		if isSuperAdmin && adm.Type != mgmt.AdminTypeSuper {
			return false
		}
		if isNotSuperAdmin && adm.Type == mgmt.AdminTypeSuper {
			return false
		}
		if len(provName) > 0 && adm.ProvisionerName != provName {
			return false
		}
		return true
	})

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "SUBJECT\tPROVISIONER\tTYPE\tSTATUS")
	for _, adm := range admins {
		fmt.Fprintf(w, "%s\t%s(%s)\t%s\t%s\n", adm.Subject, adm.ProvisionerName, adm.ProvisionerType, string(adm.Type), adm.Status)
	}
	w.Flush()
	return nil
}
