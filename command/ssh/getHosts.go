package ssh

import (
	"fmt"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func getHostsCommand() cli.Command {
	return cli.Command{
		Name:      "get-hosts",
		Action:    command.ActionFunc(getHostsAction),
		Usage:     "returns a list of all valid hosts",
		UsageText: `**step ssh get-hosts**`,
		Description: `**step ssh get-hosts** returns a list of valid hosts for SSH.

This command returns a zero exit status then the server exists, it will return 1
otherwise.

## POSITIONAL ARGUMENTS

## EXAMPLES

Get a list of valid hosts for SSH:
'''
$ step ssh get-hosts
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

func getHostsAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return err
	}

	resp, err := client.SSHGetHosts()
	if err != nil {
		return err
	}

	fmt.Println(resp.Hosts)
	return nil
}
