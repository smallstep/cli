package admin

import (
	"errors"
	"fmt"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/linkedca"
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
	Name     string
	CLIAdmin *cliAdmin
}

type cliAdmin struct {
	*linkedca.Admin
	ProvisionerName string
	ProvisionerType string
}

func toCLI(ctx *cli.Context, client *ca.AdminClient, adm *linkedca.Admin) (*cliAdmin, error) {
	// FIXME
	p, err := client.GetProvisionerByName("foo")
	if err != nil {
		return nil, err
	}
	return &cliAdmin{Admin: adm, ProvisionerName: p.GetName(), ProvisionerType: p.GetType().String()}, nil
}

func listToCLI(ctx *cli.Context, client *ca.AdminClient, admins []*linkedca.Admin) ([]*cliAdmin, error) {
	provs, err := client.GetProvisioners()
	if err != nil {
		return nil, err
	}

	var provMapByID = map[string]provisioner.Interface{}
	for _, p := range provs {
		provMapByID[p.GetID()] = p
	}
	var cliAdmins = make([]*cliAdmin, len(admins))
	for _, adm := range admins {
		p, ok := provMapByID[adm.ProvisionerId]
		if !ok {
			return nil, fmt.Errorf("provisioner %s not found for admin %s", adm.ProvisionerId, adm.Id)
		}
		cliAdmins = append(cliAdmins, &cliAdmin{Admin: adm, ProvisionerName: p.GetName(), ProvisionerType: p.GetType().String()})
	}
	return cliAdmins, nil
}

func adminPrompt(ctx *cli.Context, client *ca.AdminClient, admins []*linkedca.Admin) (*cliAdmin, error) {
	if len(admins) == 0 {
		return nil, errors.New("no admins to update")
	}
	args := ctx.Args()
	subject := args[0]

	cliAdmins, err := listToCLI(ctx, client, admins)
	if err != nil {
		return nil, err
	}

	// Filter by subject
	cliAdmins = adminFilter(cliAdmins, func(adm *cliAdmin) bool {
		return adm.Subject == subject
	})
	if len(cliAdmins) == 0 {
		return nil, fmt.Errorf("no admins with subject %s", subject)
	}

	// Filter by provisionerName
	if provName := ctx.String("provisioner"); len(provName) != 0 {
		cliAdmins = adminFilter(cliAdmins, func(a *cliAdmin) bool {
			return a.ProvisionerName == provName
		})
		if len(cliAdmins) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "provisioner", provName, "")
		}
	}

	// Select admin
	var items []*adminSelect
	for _, adm := range cliAdmins {
		items = append(items, &adminSelect{
			Name: fmt.Sprintf("subject: %s, provisioner: %s(%s), type: %s", adm.Subject,
				adm.ProvisionerName, adm.ProvisionerType, adm.Type),
			CLIAdmin: adm,
		})
	}

	if len(items) == 1 {
		if err := ui.PrintSelected("Admin", items[0].Name); err != nil {
			return nil, err
		}
		return items[0].CLIAdmin, nil
	}

	i, _, err := ui.Select("Select an admin:", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Admin")))
	if err != nil {
		return nil, err
	}

	return items[i].CLIAdmin, nil
}

// adminFilter returns a slice of admins that pass the given filter.
func adminFilter(cliAdmins []*cliAdmin, f func(*cliAdmin) bool) []*cliAdmin {
	var result []*cliAdmin
	for _, a := range cliAdmins {
		if f(a) {
			result = append(result, a)
		}
	}
	return result
}
