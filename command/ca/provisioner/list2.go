package provisioner

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func list2Command() cli.Command {
	return cli.Command{
		Name:      "list2",
		Action:    cli.ActionFunc(list2Action),
		Usage:     "list all provisioners in the CA configuration",
		UsageText: `**step ca provisioner list** [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner list** lists all provisioners in the CA configuration.

## EXAMPLES

List all provisioners:
'''
$ step ca provisioner list
'''
`,
	}
}

type listProvisioner struct {
	ID   string
	Type string
	Name string
}

/*
func toCLI(client *ca.MgmtClient, admins []*mgmt.Admin) ([]*Admin, error) {
	provs, err := client.GetProvisioners()
	if err != nil {
		return nil, err
	}

	var provMap = map[string]*mgmt.Provisioner{}
	for _, p := range provs {
		provMap[p.ID] = p
	}

	cliAdmins := []*Admin{}
	for _, adm := range admins {
		if !filter(adm) {
			continue
		}
		cliAdm := &Admin{
			ID:           adm.ID,
			Name:         adm.Name,
			Status:       adm.Status.String(),
			IsSuperAdmin: adm.IsSuperAdmin,
		}
		p, ok := provMap[adm.ProvisionerID]
		if ok {
			cliAdm.Provisioner = &Provisioner{
				ID:   p.ID,
				Name: p.Name,
				Type: p.Type,
			}
		} else {
			cliAdm.Provisioner = &Provisioner{
				ID:   adm.ProvisionerID,
				Name: "NaN",
				Type: "NaN",
			}
		}
		cliAdmins = append(cliAdmins, cliAdm)
	}
	return cliAdmins, nil
}
*/

func list2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return err
	}
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}
	rootFile := ctx.String("root")
	if len(rootFile) == 0 {
		rootFile = pki.GetRootCAPath()
		if _, err := os.Stat(rootFile); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	// Create online client
	var options []ca.ClientOption
	options = append(options, ca.WithRootFile(rootFile))
	client, err := ca.NewMgmtClient(caURL, options...)
	if err != nil {
		return err
	}

	provs, err := client.GetProvisioners()
	if err != nil {
		return err
	}
	listProvs := []*listProvisioner{}
	for _, prov := range provs {
		listProvs = append(listProvs, &listProvisioner{
			ID:   prov.ID,
			Type: prov.Type,
			Name: prov.Name,
		})
	}

	b, err := json.MarshalIndent(listProvs, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioners")
	}

	fmt.Println(string(b))
	return nil
}
