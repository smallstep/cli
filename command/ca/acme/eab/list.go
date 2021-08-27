package eab

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(listAction),
		Usage:     "list all ACME External Account Binding Keys",
		UsageText: `**step beta ca acme eab list** <provisioner_name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca acme eab list** lists all ACME External Account Binding Keys.

## POSITIONAL ARGUMENTS

<provisioner_name>
: Name of the provisioner to add an ACME EAB key to 

## EXAMPLES

List all ACME External Account Binding Keys:
'''
$ step beta ca acme eab list <provisioner_name>
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	provisionerName := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	eaks, err := client.GetExternalAccountKeys(provisionerName)
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "Key ID\tProvisioner\tName\tKey (masked)\tCreated At\tBound At\tAccount")

	for _, k := range eaks {
		cliEAK, err := toCLI(ctx, client, k)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s \t%s \t%s \t%s \t%s \t%s\n", cliEAK.id, cliEAK.provisioner, cliEAK.name, "*****", cliEAK.createdAt.Format("2006-01-02 15:04:05 -07:00"), cliEAK.boundAt, cliEAK.account)
	}

	w.Flush()

	return nil
}
