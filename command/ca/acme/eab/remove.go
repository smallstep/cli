package eab

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove an ACME EAB Key from the CA",
		UsageText: `**step ca acme eab remove** <provisioner> <eab-key-id>
[**--json**] [**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Flags: []cli.Flag{
			jsonFlag,
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step ca acme eab remove** removes an ACME EAB Key from the CA.

## POSITIONAL ARGUMENTS

<provisioner>
: Name of the provisioner to remove an ACME EAB key for

<eab-key-id>
: The ACME EAB Key ID to remove

## EXAMPLES

Remove ACME EAB Key with Key ID "zFGdKC1sHmNf3Wsx3OujY808chxwEdmr" from my_acme_provisioner:
'''
$ step ca acme eab remove my_acme_provisioner zFGdKC1sHmNf3Wsx3OujY808chxwEdmr
'''

Remove an ACME EAB Key and output the result as JSON:
'''
$ step ca acme eab remove my_acme_provisioner zFGdKC1sHmNf3Wsx3OujY808chxwEdmr --json
'''
`,
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	provisioner := args.Get(0)
	keyID := args.Get(1)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating admin client")
	}

	err = client.RemoveExternalAccountKey(provisioner, keyID)
	if err != nil {
		return errors.Wrap(notImplemented(err), "error removing ACME EAB key")
	}

	if ctx.Bool("json") {
		b, err := json.MarshalIndent(struct {
			Provisioner string `json:"provisioner"`
			ID          string `json:"id"`
			Deleted     bool   `json:"deleted"`
		}{
			Provisioner: provisioner,
			ID:          keyID,
			Deleted:     true,
		}, "", "  ")
		if err != nil {
			return errors.Wrap(err, "error marshaling ACME EAB key")
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Println("Key was deleted successfully!")

	return nil
}
