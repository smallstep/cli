package webhook

import (
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove a webhook from a provisioner",
		UsageText: `**step ca provisioner webhook remove** <name> **--provisioner**=my-provisioner
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			// General webhook flags
			provisionerFlag,

			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.CaConfig,
		},
		Description: `**step ca provisioner webhook remove** removes a webhook from a provisioner.

## POSITIONAL ARGUMENTS

<name>
: The name of the webhook.

## EXAMPLES

Remove a webhook:
'''
step ca provisioner webhook remove my_webhook --provisioner my_provisioner
'''`,
	}
}

func removeAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	provisionerName := ctx.String("provisioner")

	args := ctx.Args()

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	if err := client.DeleteProvisionerWebhook(provisionerName, args.Get(0)); err != nil {
		return err
	}

	return nil
}
