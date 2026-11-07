package ca

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

func healthCommand() cli.Command {
	return cli.Command{
		Name:   "health",
		Action: healthAction,
		Usage:  "get the status of the CA",
		UsageText: `**step ca health**
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
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
			flags.Context,
		},
	}
}

func healthAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	root := ctx.String("root")
	// Prepare client for bootstrap or provisioning tokens
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	var options []ca.ClientOption
	options = append(options, ca.WithRootFile(root))

	caClient, err := ca.NewClient(caURL, options...)
	if err != nil {
		return err
	}
	r, err := caClient.HealthWithContext(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", r.Status)
	return nil
}
