package provisioner

import (
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func remove2Command() cli.Command {
	return cli.Command{
		Name:      "remove2",
		Action:    cli.ActionFunc(remove2Action),
		Usage:     "remove a provisioner from the CA configuration",
		UsageText: `**step ca provisioner remove** <name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner remove** removes a provisioner from the CA configuration.

## EXAMPLES

Remove provisioner by id:
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

	if err := client.RemoveProvisioner(name); err != nil {
		return err
	}

	return nil
}
