package admin

import (
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/linkedca"
)

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "admin",
		Usage:     "create and manage the certificate authority admins",
		UsageText: "**step ca admin** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			addCommand(),
			removeCommand(),
			updateCommand(),
		},
		Description: `**step ca admin** command group provides facilities for managing the
certificate authority admins.

An admin is an entity that manages administrative resources (like authority
configuration, provisioner configuration, and other admins) within a certificate
authority.

## EXAMPLES

List the active admins:
'''
$ step ca admin list
'''

Add an admin:
'''
$ step ca admin add max@smallstep.com my-jwk-provisioner --super
'''

Update an admin:
'''
$ step ca admin update max@smallstep.com --super=false
'''

Remove an admin:
'''
$ step ca admin remove max@smallstep.com
'''`,
	}
}

var provisionerFilterFlag = cli.StringFlag{
	Name:  "provisioner",
	Usage: `The provisioner <name> by which to filter admins.`,
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

func toCLI(_ *cli.Context, client *ca.AdminClient, adm *linkedca.Admin) (*cliAdmin, error) {
	p, err := client.GetProvisioner(ca.WithProvisionerID(adm.ProvisionerId))
	if err != nil {
		return nil, err
	}
	return &cliAdmin{Admin: adm, ProvisionerName: p.GetName(), ProvisionerType: p.GetType().String()}, nil
}

func listToCLI(ctx *cli.Context, client *ca.AdminClient, admins []*linkedca.Admin) ([]*cliAdmin, error) {
	var (
		err       error
		cliAdmins = make([]*cliAdmin, len(admins))
	)
	for i, adm := range admins {
		cliAdmins[i], err = toCLI(ctx, client, adm)
		if err != nil {
			return nil, err
		}
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
	if provName := ctx.String("provisioner"); provName != "" {
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
			//Name: fmt.Sprintf("%s\t%s (%s)\t%s", adm.Subject,
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

	i, _, err := ui.Select("Select an admin:", items,
		ui.WithSelectTemplates(ui.NamedSelectTemplates("Admin")))
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
