package admin

import (
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove an admin from the CA configuration",
		UsageText: `**step beta ca admin remove** <subject> [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]`,
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step beta ca admin remove** removes an admin from the CA configuration.

## POSITIONAL ARGUMENTS

<name>
: The name of the admin to be removed.

## EXAMPLES

Remove an admin:
'''
$ step beta ca admin remove max@smallstep.com
'''

Remove an admin with additional filtering by provisioner:
'''
$ step beta ca admin remove max@smallstep.com --provisioner admin-jwk
'''
`,
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	admins, err := client.GetAdmins()
	if err != nil {
		return err
	}
	adm, err := adminPrompt(ctx, client, admins)
	if err != nil {
		return err
	}

	return client.RemoveAdmin(adm.Id)
}
