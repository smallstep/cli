package ssh

import (
	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func logoutCommand() cli.Command {
	return cli.Command{
		Name:      "logout",
		Action:    command.ActionFunc(logoutAction),
		Usage:     "removes a private key from the ssh-agent and revoke",
		UsageText: `**step ssh logout** <subject>`,
		Description: `**step ssh logout** commands removes a key from the ssh-agent and optionally
revokes the key creating a Key Revocation List file.

## POSITIONAL ARGUMENTS

<subject>
:  The SSH subject or comment in the key.

## EXAMPLES

Remove the key mariano@work from the SSH agent:
'''
$ step ssh logout mariano@work
'''

Remove the key mariano@work from the agent listening in /tmp/ssh/agent:
'''
$ SSH_AUTH_SOCK=/tmp/ssh/agent step ssh logout mariano@work
'''

Remove all the keys stored in the SSH agent:
'''
$ step ssh logout --all
'''

Remove and revoke the key mariano@work:
'''
$ step ssh logout --revoke /etc/ssh/revoked_keys mariano@work
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "all",
				Usage: "Removes all the keys stored in the SSH agent.",
			},
			cli.StringFlag{
				Name:  "revoke",
				Usage: "Removes the key and updates a Key Revocation List <file> or KRL.",
			},
		},
	}
}

func logoutAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	subject := ctx.Args().First()
	// Flags
	all := ctx.Bool("all")
	revoke := ctx.String("revoke")

	_, _ = subject, all

	switch {
	case revoke != "":
		return errs.UnsupportedFlag(ctx, "revoke")
	}

	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}
	defer agent.Close()

	// Remove all
	if all {
		if err := agent.RemoveAll(); err != nil {
			return errors.Wrap(err, "error removing all keys")
		}
	}

	// Remove if comment == subject
	keys, err := agent.List()
	if err != nil {
		return errors.Wrap(err, "error listing keys")
	}
	for _, key := range keys {
		if key.Comment == subject {
			if err := agent.Remove(key); err != nil {
				return errors.Wrap(err, "error removing key")
			}
		}
	}

	return nil
}
