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
		UsageText: `**step ca provisioner webhook remove** <provisioner_name> <webhook_name>
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
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

<provisioner_name>
: The name of the provisioner.

<webhook_name>
: The name of the webhook.

## EXAMPLES

Remove a webhook:
'''
step ca provisioner webhook remove my_provisioner my_webhook
'''`,
	}
}

func removeAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()

	provisionerName := args.Get(0)

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	if err := client.DeleteProvisionerWebhook(provisionerName, args.Get(1)); err != nil {
		return err
	}

	return nil
}
