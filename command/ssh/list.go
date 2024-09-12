package ssh

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	libsshutil "go.step.sm/crypto/sshutil"

	"github.com/smallstep/cli/internal/sshutil"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    command.ActionFunc(listAction),
		Usage:     "list public keys known to the ssh agent",
		UsageText: `**step ssh list** [<subject>] [**--raw**]`,
		Description: `**step ssh list** list public key identities known to the ssh agent.

By default it prints key fingerprints, to list the raw key use the flag **--raw**.

## POSITIONAL ARGUMENTS

<subject>
:  Optional subject or comment to filter keys by.

## EXAMPLES

List all key fingerprints known to the agent:
'''
$ step ssh list
'''

List all the key fingerprints with the comment joe@work:
'''
$ step ssh list joe@work
'''

List all keys known to the agent:
'''
$ step ssh list --raw
'''

List all the keys with the comment joe@work:
'''
$ step ssh list --raw joe@work
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "List public keys instead of fingerprints.",
			},
		},
	}
}

func listAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var subject string
	if ctx.NArg() > 0 {
		subject = ctx.Args().First()
	}

	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}

	keys, err := agent.List()
	if err != nil {
		return errors.Wrap(err, "error listing identities")
	}

	if len(keys) == 0 {
		fmt.Println("The agent has no identities.")
		return nil
	}

	if ctx.Bool("raw") {
		for _, k := range keys {
			if ctx.NArg() == 0 || k.Comment == subject {
				fmt.Println(k.String())
			}
		}
	} else {
		for _, k := range keys {
			if ctx.NArg() == 0 || k.Comment == subject {
				s, err := libsshutil.FormatFingerprint([]byte(k.String()), libsshutil.DefaultFingerprint)
				if err != nil {
					return err
				}
				fmt.Println(s)
			}
		}
	}

	return nil
}
