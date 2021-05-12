package admin

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	mgmtAPI "github.com/smallstep/certificates/authority/mgmt/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update an admin",
		UsageText: `**step ca admin update** <id> [**--super**] [**--not-super**] [**--name=<string>**]
[**--provisioner-id=<string>**] [**--ca-url**=<uri>] [**--root**=<file>]
[**--ca-config**=<file>]`,
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
				Name:  "name",
				Usage: `Update the admin name.`,
			},
			cli.StringFlag{
				Name:  "provisioner-id",
				Usage: `Update the admin provisioner ID.`,
			},
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca admin update** updates an admin.

## POSITIONAL ARGUMENTS

<id>
: The id of the admin to update.

## EXAMPLES

Add super-admin privileges to an admin:
'''
$ step ca admin update RuDAMlHpn9LMyzSSCDmVSJNYQOXhnrdE --super
'''

Update name and add super-admin privileges to an admin:
'''
$ step ca admin update RuDAMlHpn9LMyzSSCDmVSJNYQOXhnrdE --super --name mariano@smallstep.com
'''

Update provisioner associated with an admin:
'''
$ step ca admin update RuDAMlHpn9LMyzSSCDmVSJNYQOXhnrdE --provisioner-id isxSMDpOvoSMT5fFMzkynofhuHKe9uRt
'''

Remove super-admin privileges from an admin:
'''
$ step ca admin update RuDAMlHpn9LMyzSSCDmVSJNYQOXhnrdE --not-super
'''
`,
	}
}

func updateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	id := args.Get(0)
	name := ctx.String("name")
	provisionerID := ctx.String("provisioner-id")
	isSuperAdmin := ctx.IsSet("super")
	isNotSuperAdmin := ctx.IsSet("not-super")

	if isSuperAdmin && isNotSuperAdmin {
		return errs.IncompatibleFlag(ctx, "super", "not-super")
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

	uar := &mgmtAPI.UpdateAdminRequest{
		Name:          name,
		ProvisionerID: provisionerID,
	}
	if isSuperAdmin {
		uar.IsSuperAdmin = "true"
	} else if isNotSuperAdmin {
		uar.IsSuperAdmin = "false"
	}

	adm, err := client.UpdateAdmin(id, uar)
	if err != nil {
		return err
	}
	cliAdmins, err := ToCLI(client, []*mgmt.Admin{adm})
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(cliAdmins[0], "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling admin")
	}

	fmt.Println(string(b))
	return nil
}
