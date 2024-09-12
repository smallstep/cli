package ssh

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils/cautils"
)

func logoutCommand() cli.Command {
	return cli.Command{
		Name:   "logout",
		Action: command.ActionFunc(logoutAction),
		Usage:  "removes a private key from the ssh-agent",
		UsageText: `**step ssh logout** [<identity>] [**--all**]
[**--identity**=<identity>] [**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,

		Description: `**step ssh logout** commands removes a key from the ssh-agent.

By default it only removes certificate keys signed by step-certificates, but the
flag **--all** can be used to remove all keys with a given subject or all keys.

## POSITIONAL ARGUMENTS

<identity>
:  The certificate identity or comment in the key.

## EXAMPLES

Remove all identities signed by your SSH CA:
'''
$ step ssh logout
'''

Remove the certificate mariano@work from the SSH agent:
'''
$ step ssh logout mariano@work
'''

Remove the all the keys and certificates for mariano@work from the SSH agent:
'''
$ step ssh logout --all mariano@work
'''

Remove the key mariano@work from the agent listening in /tmp/ssh/agent:
'''
$ SSH_AUTH_SOCK=/tmp/ssh/agent step ssh logout mariano@work
'''

Remove all the keys stored in the SSH agent:
'''
$ step ssh logout --all
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "all",
				Usage: "Removes all the keys stored in the SSH agent.",
			},
			flags.Identity,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func logoutAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	all := ctx.Bool("all")
	subject := ctx.Args().First()
	if subject == "" {
		subject = ctx.String("identity")
	}

	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}
	defer agent.Close()

	// Remove all
	if all && ctx.NArg() == 0 {
		if err := agent.RemoveAll(); err != nil {
			return errors.Wrap(err, "error removing all keys")
		}
		fmt.Println("All identities removed.")
		return nil
	}

	var opts []sshutil.AgentOption
	if !all {
		// Remove only keys signed by the CA. If we cannot get the list of
		// roots, remove only the ssh certificates.
		client, err := cautils.NewClient(ctx)
		if err != nil {
			return err
		}
		if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
			userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
			for i, uk := range roots.UserKeys {
				userKeys[i] = uk.PublicKey
			}
			opts = append(opts, sshutil.WithSignatureKey(userKeys))
		} else {
			opts = append(opts, sshutil.WithCertsOnly())
		}
	}

	found, err := removeSSHKeys(agent, subject, opts...)
	if err != nil {
		return err
	}

	switch {
	case !found:
		fmt.Printf("Identity not found")
	case all:
		fmt.Printf("All identities removed")
	default:
		fmt.Printf("Identity removed")
	}
	if subject == "" {
		fmt.Println(".")
	} else {
		fmt.Println(":", subject)
	}

	return nil
}

func removeSSHKeys(agent *sshutil.Agent, subject string, opts ...sshutil.AgentOption) (bool, error) {
	if subject != "" {
		// Remove if comment == subject
		return agent.RemoveKeys(subject, opts...)
	}
	return agent.RemoveAllKeys(opts...)
}
