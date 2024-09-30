package provisioner

import (
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove a provisioner from the CA configuration",
		UsageText: `**step ca provisioner remove** <name>
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.CaConfig,
		},
		Description: `**step ca provisioner remove** removes a provisioner from the CA configuration.

## EXAMPLES

Remove provisioner by name:
'''
$ step ca provisioner remove acme
'''

Remove provisioner from a ca.json that is not in the default location:
'''
$ step ca provisioner remove acme --ca-config /path/to/ca.json
'''`,
	}
}

func removeAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	return client.RemoveProvisioner(ca.WithProvisionerName(name))
}
