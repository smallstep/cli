package ssh

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

func hostsCommand() cli.Command {
	return cli.Command{
		Name:   "hosts",
		Action: command.ActionFunc(hostsAction),
		Usage:  "returns a list of all valid hosts",
		UsageText: `**step ssh hosts** [**--set**=<key=value>] [**--set-file**=<file>]
[**--console**] [**--offline**] [**--ca-config**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step ssh hosts** returns a list of valid hosts for SSH.

This command returns a zero exit status then the server exists, it will return 1
otherwise.

## EXAMPLES

Get a list of valid hosts for SSH:
'''
$ step ssh hosts
'''`,
		Flags: []cli.Flag{
			flags.TemplateSet,
			flags.TemplateSetFile,
			flags.Console,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
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
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "HOSTNAME\tID\tTAGS")
	for _, h := range resp.Hosts {
		tags := ""
		for i, ht := range h.HostTags {
			if i > 0 {
				tags += ","
			}
			tags += ht.Name + "=" + ht.Value
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", h.Hostname, h.HostID, tags)
	}
	w.Flush()
	return nil
}
