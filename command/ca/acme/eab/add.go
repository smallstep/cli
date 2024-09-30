package eab

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add ACME External Account Binding Key",
		UsageText: `**step ca acme eab add** <provisioner> [<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step ca acme eab add** adds ACME External Account Binding Key.

## POSITIONAL ARGUMENTS

<provisioner>
: Name of the provisioner to which the ACME EAB key will be added

<eab-key-reference>
: (Optional) reference (from external system) for the key that will be added

## EXAMPLES

Add an ACME External Account Binding Key without reference:
'''
$ step ca acme eab add my_acme_provisioner
'''

Add an ACME External Account Binding Key with reference:
'''
$ step ca acme eab add my_acme_provisioner my_first_eab_key
'''`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 2); err != nil {
		return err
	}

	args := ctx.Args()
	provisioner := args.Get(0)

	reference := ""
	if ctx.NArg() == 2 {
		reference = args.Get(1)
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating admin client")
	}

	eak, err := client.CreateExternalAccountKey(provisioner, &adminAPI.CreateExternalAccountKeyRequest{
		Reference: reference,
	})
	if err != nil {
		return errors.Wrap(notImplemented(err), "error creating ACME EAB key")
	}

	cliEAK := toCLI(ctx, client, eak)

	// TODO(hs): JSON output, so that executing this command can be more easily automated?

	out := os.Stdout
	format := "%-36s%-28s%-48s%s\n"
	fmt.Fprintf(out, format, "Key ID", "Provisioner", "Key (base64, raw url encoded)", "Reference")
	fmt.Fprintf(out, format, cliEAK.id, cliEAK.provisioner, cliEAK.key, cliEAK.reference)

	return nil
}
