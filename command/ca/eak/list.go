package eak

import (
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(listAction),
		Usage:     "list all ACME External Account Keys",
		UsageText: `**step beta ca eak list** [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca eak list** lists all ACME External Account Keys.

## EXAMPLES

List all ACME External Account Keys:
'''
$ step beta ca eak list
'''
`,
	}
}

func listAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	// TODO: implementation for listing keys

	return nil
}
