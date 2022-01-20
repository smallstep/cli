package eab

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/pkg/errors"
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
		UsageText: `**step beta ca acme eab list** <provisioner> [<reference>]
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
		Description: `**step beta ca acme eab list** lists all ACME External Account Binding (EAB) Keys.

Output will go to stdout by default. If many EAB keys are stored in the ACME provisioner, output will be sent to $PAGER (when set). 

## POSITIONAL ARGUMENTS

<provisioner>
: Name of the provisioner to list ACME EAB keys for

<reference>
: (Optional) reference (from external system) for the key to be listed


## EXAMPLES

List all ACME External Account Binding Keys:
'''
$ step beta ca acme eab list my_acme_provisioner
'''

Show ACME External Account Binding Key with specific reference:
'''
$ step beta ca acme eab list my_acme_provisioner my_reference
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
		return errors.Wrap(err, "error creating admin client")
	}

	eaks, err := client.GetExternalAccountKeys(provisioner, reference)
	if err != nil {
		return errors.Wrap(err, "error retrieving ACME EAB keys")
	}

	if len(eaks) == 0 {
		fmt.Printf("No ACME EAB keys stored for provisioner %s\n", provisioner)
		return nil
	}

	var out io.WriteCloser
	var cmd *exec.Cmd

	// prepare the $PAGER command to run
	pager := os.Getenv("PAGER")
	if pager != "" && len(eaks) > 15 { // use $PAGER only when more than 15 results are returned
		cmd = exec.Command(pager)
		var err error
		out, err = cmd.StdinPipe()
		if err != nil {
			return errors.Wrap(err, "error setting stdin")
		}
		cmd.Stdout = os.Stdout
		if err := cmd.Start(); err != nil {
			return errors.Wrap(err, "unable to start $PAGER")
		}
	} else {
		out = os.Stdout
	}

	format := "%-36s%-28s%-16s%-30s%-30s%-36s%s\n"
	fmt.Fprintf(out, format, "Key ID", "Provisioner", "Key (masked)", "Created At", "Bound At", "Account", "Reference")
	for _, k := range eaks {
		cliEAK := toCLI(ctx, client, k)
		_, err = fmt.Fprintf(out, format, cliEAK.id, cliEAK.provisioner, "*****", cliEAK.createdAt, cliEAK.boundAt, cliEAK.account, cliEAK.reference)
		if err != nil {
			return errors.Wrap(err, "error writing to output")
		}
	}

	out.Close()

	if cmd != nil {
		if err := cmd.Wait(); err != nil {
			return errors.Wrap(err, "error waiting for $PAGER")
		}
	}

	return nil
}
