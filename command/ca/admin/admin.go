package admin

import (
	"errors"
	"fmt"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "admin",
		Usage:     "create and manage the certificate authority admins",
		UsageText: "step ca admin <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			//getCommand(),
			addCommand(),
			removeCommand(),
			updateCommand(),
		},
		Description: `The **step ca admin** command group provides facilities for managing the
certificate authority admins.

A admin is an entity that manages administrative resources within a certificate
authority. Admins manage

* certificate authority configuration
* provisioner configuration
* other admins and admin privileges

## EXAMPLES

List the active admins:
'''
$ step ca admin list
'''

Add an admin:
'''
$ step ca admin add max@smallstep.com my-jwk-provisioner
'''

Remove an admin:
'''
$ step ca admin remove max@smallstep.com my-jwk-provisioner
'''`,
	}
}

type adminSelect struct {
	Name  string
	Admin *admin.Admin
}

func adminPrompt(ctx *cli.Context, admins []*admin.Admin) (*admin.Admin, error) {
	if len(admins) == 0 {
		return nil, errors.New("no admins to update")
	}
	args := ctx.Args()
	subject := args[0]

	// Filter by subject
	admins = adminFilter(admins, func(adm *admin.Admin) bool {
		return adm.Subject == subject
	})
	if len(admins) == 0 {
		return nil, fmt.Errorf("no admins with subject %s", subject)
	}

	// Filter by provisionerName
	if provName := ctx.String("provisioner"); len(provName) != 0 {
		admins = adminFilter(admins, func(a *admin.Admin) bool {
			return a.ProvisionerName == provName
		})
		if len(admins) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "provisioner", provName, "")
		}
	}

	// Select admin
	var items []*adminSelect
	for _, adm := range admins {
		items = append(items, &adminSelect{
			Name: fmt.Sprintf("subject: %s, provisioner: %s(%s), type: %s", adm.Subject,
				adm.ProvisionerName, adm.ProvisionerType, adm.Type),
			Admin: adm,
		})
	}

	if len(items) == 1 {
		if err := ui.PrintSelected("Admin", items[0].Name); err != nil {
			return nil, err
		}
		return items[0].Admin, nil
	}

	i, _, err := ui.Select("Select an admin:", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Admin")))
	if err != nil {
		return nil, err
	}

	return items[i].Admin, nil
}

// adminFilter returns a slice of admins that pass the given filter.
func adminFilter(admins []*admin.Admin, f func(*admin.Admin) bool) []*admin.Admin {
	var result []*admin.Admin
	for _, a := range admins {
		if f(a) {
			result = append(result, a)
		}
	}
	return result
}

func getAdmins(client *ca.MgmtClient) ([]*admin.Admin, error) {
	var (
		cursor = ""
		admins = []*admin.Admin{}
	)
	for {
		resp, err := client.GetAdmins(ca.WithAdminCursor(cursor), ca.WithAdminLimit(100))
		if err != nil {
			return nil, err
		}
		admins = append(admins, resp.Admins...)
		if resp.NextCursor == "" {
			return admins, nil
		}
		cursor = resp.NextCursor
	}
}
