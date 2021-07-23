package eab

import (
	"fmt"
	"os"
	"text/tabwriter"

	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(addAction),
		Usage:     "add ACME External Account Binding Key",
		UsageText: `**step beta ca acme eab add** <name_or_reference> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca acme eab add** adds ACME External Account Binding Key.

## POSITIONAL ARGUMENTS

<name_or_reference>
:  Name or (external) reference for the key to be created

## EXAMPLES

Add an ACME External Account Binding Key:
'''
$ step beta ca acme eab add my_first_eab_key
'''`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	eak, err := client.CreateExternalAccountKey(&adminAPI.CreateExternalAccountKeyRequest{
		Name: name,
	})
	if err != nil {
		return err
	}

	cliEAK, err := toCLI(ctx, client, eak)
	if err != nil {
		return err
	}

	// TODO: JSON output, so that executing this command can be more easily automated?

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "Key ID\tName\tKey (base64, std)")
	fmt.Fprintf(w, "%s\t%s \t%s\n", cliEAK.id, cliEAK.name, cliEAK.key)
	w.Flush()

	return nil
}
