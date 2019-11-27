package ssh

import (
	"fmt"
	"os"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func checkHostCommand() cli.Command {
	return cli.Command{
		Name:   "check-host",
		Action: command.ActionFunc(checkHostAction),
		Usage:  "checks if a certificate has been issued for a host",
		UsageText: `**step ssh check-host** <hostname>
		[**--ca-url**=<uri>] [**--root**=<file>]
		[**--offline**] [**--ca-config**=<path>]`,
		Description: `**step ssh check-host** checks if a certificate has been issued for a host.

This command returns a zero exit status then the server exists, it will return 1
otherwise.

## POSITIONAL ARGUMENTS

<hostname>
:  The hostname of the server to check.

## EXAMPLES

Check that internal.example.com exists:
'''
$ step ssh check-host internal.smallstep.com
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

func checkHostAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx, ca.WithRetryFunc(retryFunc))
	if err != nil {
		return err
	}

	resp, err := client.SSHCheckHost(ctx.Args().First())
	if err != nil {
		return err
	}

	fmt.Println(resp.Exists)
	if !resp.Exists {
		os.Exit(1)
	}
	return nil
}
