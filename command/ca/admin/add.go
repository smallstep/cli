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

func addCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(addAction),
		Usage:     "add an admin to the CA configuration",
		UsageText: `**step ca admin add** <name> <provisioner> [**--super**]`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			cli.BoolFlag{
				Name:  "super",
				Usage: `Give administrator SuperAdmin privileges.`,
			},
		},
		Description: `**step ca admin add** adds an admin.

## POSITIONAL ARGUMENTS

<name>
: The name of the admin. This name must appear in the admin's identity certificate SANs.

<provisioner>
: The name of the provisioner

## EXAMPLES

Add regular Admin:
'''
$ step ca admin add max@smallstep.com admin-jwk
'''

Add SuperAdmin:
'''
$ step ca admin add max@smallstep.com admin-jwk --super
'''
`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)
	provisionerID := args.Get(1)

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

	adm, err := client.CreateAdmin(&mgmtAPI.CreateAdminRequest{
		Name:          name,
		ProvisionerID: provisionerID,
		IsSuperAdmin:  ctx.Bool("super"),
	})
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
