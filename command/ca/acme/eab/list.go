package eab

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:   "list",
		Action: cli.ActionFunc(listAction),
		Usage:  "list all ACME External Account Binding Keys",
		UsageText: `**step ca acme eab list** <provisioner> [<eab-key-reference>]
[**--limit**=<number>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Flags: []cli.Flag{
			flags.Limit,
			flags.NoPager,
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step ca acme eab list** lists all ACME External Account Binding (EAB) Keys.

Output will go to stdout by default. If many EAB keys are stored in the ACME provisioner, output will be sent to $PAGER (when set). 

## POSITIONAL ARGUMENTS

<provisioner>
: Name of the provisioner to list ACME EAB keys for

<eab-key-reference>
: (Optional) reference (from external system) for the key to be listed


## EXAMPLES

List all ACME External Account Binding Keys:
'''
$ step ca acme eab list my_acme_provisioner
'''

Show ACME External Account Binding Key with specific reference:
'''
$ step ca acme eab list my_acme_provisioner my_reference
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

	var out io.WriteCloser
	var cmd *exec.Cmd

	usePager := true
	if ctx.IsSet("no-pager") {
		usePager = !ctx.Bool("no-pager")
	}

	// the pipeSignalHandler goroutine ensures that the parent process is closed
	// whenever one of its children is killed.
	go pipeSignalHandler()

	// prepare the $PAGER command to run when not disabled and when available
	pager := os.Getenv("PAGER")
	if usePager && pager != "" {
		cmd = exec.Command(pager)
		var err error
		out, err = cmd.StdinPipe()
		if err != nil {
			return errors.Wrap(err, "error setting stdin")
		}
		defer out.Close()
		cmd.Stdout = os.Stdout
	} else {
		out = os.Stdout
	}

	// default to API paging per 100 entities
	limit := uint(0)
	if ctx.IsSet("limit") {
		limit = ctx.Uint("limit")
	}

	cursor := ""
	format := "%-36s%-28s%-16s%-30s%-30s%-40s%s\n"
	firstIteration := true
	startedPager := false

	for {
		options := []ca.AdminOption{ca.WithAdminCursor(cursor), ca.WithAdminLimit(int(limit))}
		eaksResponse, err := client.GetExternalAccountKeysPaginate(provisioner, reference, options...)
		if err != nil {
			return errors.Wrap(notImplemented(err), "error retrieving ACME EAB keys")
		}
		if firstIteration && len(eaksResponse.EAKs) == 0 {
			fmt.Printf("No ACME EAB keys stored for provisioner %s\n", provisioner)
			break
		}
		if shouldStartPager := (firstIteration && cmd != nil); shouldStartPager {
			if err := cmd.Start(); err != nil {
				return errors.Wrap(err, "unable to start $PAGER")
			}
			startedPager = true
		}
		if firstIteration {
			fmt.Fprintf(out, format, "Key ID", "Provisioner", "Key (masked)", "Created At", "Bound At", "Account", "Reference")
			firstIteration = false
		}
		for _, k := range eaksResponse.EAKs {
			cliEAK := toCLI(ctx, client, k)
			_, err = fmt.Fprintf(out, format, cliEAK.id, cliEAK.provisioner, "*****", cliEAK.createdAt, cliEAK.boundAt, cliEAK.account, cliEAK.reference)
			if err != nil {
				return errors.Wrap(err, "error writing ACME EAB key to output")
			}
		}
		if eaksResponse.NextCursor == "" {
			break
		}
		cursor = eaksResponse.NextCursor
	}

	// ensure closing the output when at the end of what needs to be output
	out.Close()

	if startedPager {
		if err := cmd.Wait(); err != nil {
			return errors.Wrap(err, "error waiting for $PAGER")
		}
	}

	return nil
}
