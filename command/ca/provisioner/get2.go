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

func get2Command() cli.Command {
	return cli.Command{
		Name:      "get2",
		Action:    cli.ActionFunc(get2Action),
		Usage:     "get a provisioner from the CA configuration",
		UsageText: `**step ca provisioner get** <name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner get** gets a provisioner from the CA configuration.

## EXAMPLES

Get a provisioner by name:
'''
$ step ca provisioner get admin-jwk
'''
`,
	}
}

func get2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

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
	client, err := ca.NewAdminClient(caURL, options...)
	if err != nil {
		return err
	}

	prov, err := client.GetProvisioner(ca.WithProvisionerName(name))
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(prov, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioner")
	}

	fmt.Println(string(b))
	return nil
}
