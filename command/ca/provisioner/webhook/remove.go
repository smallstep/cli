package webhook

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove a webhook from a provisioner",
		UsageText: `**step ca provisioner webhook remove** <provisioner_name> <webhook_name>
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

	return client.DeleteProvisionerWebhook(provisionerName, args.Get(1))
}
