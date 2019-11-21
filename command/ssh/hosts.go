package ssh

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func hostsCommand() cli.Command {
	return cli.Command{
		Name:      "hosts",
		Action:    command.ActionFunc(hostsAction),
		Usage:     "returns a list of all valid hosts",
		UsageText: `**step ssh hosts**`,
		Description: `**step ssh hosts** returns a list of valid hosts for SSH.

This command returns a zero exit status then the server exists, it will return 1
otherwise.

## POSITIONAL ARGUMENTS

## EXAMPLES

Get a list of valid hosts for SSH:
'''
$ step ssh hosts
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

func hostsAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	// Initialize CA client with login if needed.
	client, err := cautils.NewClient(ctx, ca.WithRetryFunc(retryFunc))
	if err != nil {
		return err
	}

	resp, err := client.SSHGetHosts()
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)

	fmt.Fprintln(w, "HOSTNAME\tID\tGROUPS")
	for _, h := range resp.Hosts {
		groups := ""
		for i, hg := range h.HostGroups {
			if i > 0 {
				groups += ","
			}
			groups += hg.Name
		}
		fmt.Fprintln(w, fmt.Sprintf("%s\t%s\t%s", h.Hostname, h.HostID, groups))
	}
	w.Flush()
	return nil
}
