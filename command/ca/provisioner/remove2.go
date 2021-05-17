package provisioner

import (
	"os"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func remove2Command() cli.Command {
	return cli.Command{
		Name:      "remove2",
		Action:    cli.ActionFunc(remove2Action),
		Usage:     "remove a provisioner from the CA configuration",
		UsageText: `**step ca provisioner remove** <id> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner remove** removes a provisioner from the CA configuration.

## EXAMPLES

Remove provisioner by id:
'''
$ step ca provisioner remove isxSMDpOvoSMT5fFMzkynofhuHKe9uRt
'''
`,
	}
}

func remove2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	id := args.Get(0)

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

	if err := client.RemoveProvisioner(id); err != nil {
		return err
	}

	return nil
}
