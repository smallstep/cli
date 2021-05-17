package config

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

func getCommand() cli.Command {
	return cli.Command{
		Name:      "get",
		Action:    cli.ActionFunc(getAction),
		Usage:     "get a provisioner from the CA configuration",
		UsageText: `**step ca provisioner get** <id> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner get** gets a provisioner from the CA configuration.

## EXAMPLES

Get the active certificate authority configuration:
'''
$ step ca config get
'''
`,
	}
}

func getAction(ctx *cli.Context) (err error) {
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

	ac, err := client.GetAuthConfig(mgmt.DefaultAuthorityID)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(ac, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling authConfig")
	}

	fmt.Println(string(b))
	return nil
}
