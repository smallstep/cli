package admin

import (
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove an admin from the CA configuration",
		UsageText: `**step ca admin remove** <id> [**--provisioner**=<id>] [**--ca-url**=<uri>]
[**--root**=<file>]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "provisioner",
				Usage: `Update the admin name.`,
			},
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca admin remove** removes an admin from the CA configuration.

## POSITIONAL ARGUMENTS

<id>
: The id of the admin to be removed.

## EXAMPLES

Remove an admin:
'''
$ step ca admin remove max@smallstep.com
'''

Remove an admin with additional filtering by provisioner:
'''
$ step ca admin remove max@smallstep.com --provisioner admin-jwk
'''
`,
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	client, err := cautils.NewMgmtClient(ctx)
	if err != nil {
		return err
	}

	admins, err := getAdmins(client)
	if err != nil {
		return err
	}
	adm, err := adminPrompt(ctx, admins)
	if err != nil {
		return err
	}

	if err := client.RemoveAdmin(adm.ID); err != nil {
		return err
	}

	return nil
}
