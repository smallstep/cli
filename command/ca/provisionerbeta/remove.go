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
		Action:    cli.ActionFunc(removeAction),
		Usage:     "remove a provisioner from the CA configuration",
		UsageText: `**step beta ca provisioner remove** <name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca provisioner remove** removes a provisioner from the CA configuration.

## EXAMPLES

Remove provisioner by name:
'''
$ step beta ca provisioner remove acme
'''
`,
	}
}

func removeAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	return client.RemoveProvisioner(ca.WithProvisionerName(name))
}
