package provisionerbeta

import (
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:      "remove",
		Action:    cli.ActionFunc(remove2Action),
		Usage:     "remove a provisioner from the CA configuration",
		UsageText: `**step ca provisioner remove** <name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.X5cCert,
			flags.X5cKey,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner remove** removes a provisioner from the CA configuration.

## EXAMPLES

Remove provisioner by name:
'''
$ step ca provisioner remove admin-jwk
'''
`,
	}
}

func remove2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	if err := client.RemoveProvisioner(ca.WithProvisionerName(name)); err != nil {
		return err
	}

	return nil
}
