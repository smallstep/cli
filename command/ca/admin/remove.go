package admin

import (
	"os"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove an admin",
		UsageText: `**step ca admin remove** <id> [**--ca-url**=<uri>]
[**--root**=<file>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca admin remove** removes an admin.
from the configuration and writes the new configuration back to the CA config.

## POSITIONAL ARGUMENTS

<id>
: The id of the admin to be removed.

## EXAMPLES

Remove an admin:
'''
$ step ca admin remove RuDAMlHpn9LMyzSSCDmVSJNYQOXhnrdE
'''
`,
	}
}

func removeAction(ctx *cli.Context) error {
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

	if err := client.RemoveAdmin(id); err != nil {
		return err
	}

	return nil
}
