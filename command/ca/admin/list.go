package admin

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(listAction),
		Usage:     "list all admins in the CA configuration",
		UsageText: `**step ca admin list** [**--super**] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			cli.BoolFlag{
				Name:  "super",
				Usage: `Only return super-admins.`,
			},
		},
		Description: `**step ca admin list** lists all admins.

## EXAMPLES

List all admins:
'''
$ step ca admin list
'''

List only super-admins:
'''
$ step ca admin --super list
'''
`,
	}
}

// Admin is a abbreviated admin type for use in the cli interface.
type Admin struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Status       string       `json:"status"`
	IsSuperAdmin bool         `json:"isSuperAdmin"`
	Provisioner  *Provisioner `json:"provisioner"`
}

// Provisioner is a abbreviated provisioner type for consumption
// through the cli interface.
type Provisioner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func ToCLI(client *ca.MgmtClient, admins []*mgmt.Admin) ([]*Admin, error) {
	provs, err := client.GetProvisioners()
	if err != nil {
		return nil, err
	}

	var provMap = map[string]*mgmt.Provisioner{}
	for _, p := range provs {
		provMap[p.ID] = p
	}

	var cliAdmins = make([]*Admin, len(admins))
	for i, adm := range admins {
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
				ID:   "NaN",
				Name: "NaN",
				Type: "NaN",
			}
		}
		cliAdmins[i] = cliAdm
	}
	return cliAdmins, nil
}

func listAction(ctx *cli.Context) (err error) {
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

	admins, err := client.GetAdmins()
	if err != nil {
		return err
	}
	cliAdmins, err := ToCLI(client, admins)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(cliAdmins, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling admins")
	}

	fmt.Println(string(b))
	return nil
}
