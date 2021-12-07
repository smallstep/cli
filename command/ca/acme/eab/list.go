package eab

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:   "list",
		Action: cli.ActionFunc(listAction),
		Usage:  "list all ACME External Account Binding Keys",
		UsageText: `**step beta ca acme eab list** <provisioner> <reference>
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step beta ca acme eab list** lists all ACME External Account Binding Keys.

## POSITIONAL ARGUMENTS

<provisioner>
: Name of the provisioner to list ACME EAB keys for

<reference>
: (Optional) Reference (from external system) for the key to be created


## EXAMPLES

List all ACME External Account Binding Keys:
'''
$ step beta ca acme eab list my_provisioner
'''

Show ACME External Account Binding Key with specific reference:
'''
$ step beta ca acme eab list my_provisioner my_reference
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
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
		return err
	}

	eaks, err := client.GetExternalAccountKeys(provisioner, reference)
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "Key ID\tProvisioner\tReference\tKey (masked)\tCreated At\tBound At\tAccount")

	for _, k := range eaks {
		cliEAK, err := toCLI(ctx, client, k)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s \t%s \t%s \t%s \t%s \t%s\n", cliEAK.id, cliEAK.provisioner, cliEAK.reference, "*****", cliEAK.createdAt.Format("2006-01-02 15:04:05 -07:00"), cliEAK.boundAt, cliEAK.account)
	}

	w.Flush()

	return nil
}
