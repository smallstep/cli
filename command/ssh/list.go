package ssh

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    command.ActionFunc(listAction),
		Usage:     "list public keys known to the ssh agent",
		UsageText: `**step ssh list** [<subject>]`,
		Description: `**step ssh list** list public key identities known to the ssh agent.

## POSITIONAL ARGUMENTS

<ubject>
:  Optional subject or comment to filter keys by.

## EXAMPLES

List all keys known to the agent:
'''
$ step ssh list
'''

List all the keys with the comment joe@work
'''
$ step ssh list joe@work
'''`,
	}
}

func listAction(ctx *cli.Context) error {
	var subject string
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

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

	for _, k := range keys {
		if subject == "" || k.Comment == subject {
			fmt.Println(k.String())
		}
	}

	return nil
}
