package ca

import (
	"fmt"
	"os"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func healthCommand() cli.Command {
	return cli.Command{
		Name:      "health",
		Action:    healthAction,
		Usage:     "get the status of the CA",
		UsageText: `**step ca health** [**--ca-url**=<URI>] [**--root**=<file>]`,
		Description: `**step ca health** makes an API request to the /health
endpoint of the Step CA to check if it is running. If the CA is healthy, the
response will be 'ok'.

## EXAMPLES

Using the required flags:
'''
$ step ca health --ca-url https://ca.smallstep.com:8080 --root path/to/root_ca.crt
ok
'''

With the required flags preconfigured:

**--ca-url** is set using environment variables (as STEP_CA_URL) or the default
configuration file in <$STEPPATH/config/defaults.json>.

**--root** is set using environment variables (as STEP_ROOT), the default
configuration file in <$STEPPATH/config/defaults.json> or the default root
certificate located in <$STEPPATH/certs/root_ca.crt>

'''
$ step ca health
ok
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
	}
}

func healthAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	caURL := ctx.String("ca-url")
	root := ctx.String("root")

	// Prepare client for bootstrap or provisioning tokens
	var options []ca.ClientOption
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}
	options = append(options, ca.WithRootFile(root))

	client, err := ca.NewClient(caURL, options...)
	if err != nil {
		return err
	}
	r, err := client.Health()
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", r.Status)
	return nil
}
