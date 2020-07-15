package ssh

import (
	"fmt"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func fingerPrintCommand() cli.Command {
	return cli.Command{
		Name:      "fingerprint",
		Action:    command.ActionFunc(fingerprint),
		Usage:     "print the fingerprint of an SSH public key or certificate",
		UsageText: `**step ssh fingerprint** <file>`,
		Description: `**step ssh fingerprint** prints the fingerprint of an ssh public key or
certificate.

## POSITIONAL ARGUMENTS

<file>
:  The path to an SSH public key or certificate.

## EXAMPLES

Print the fingerprint for a certificate:
'''
$ step ssh fingerprint id_ecdsa-cert.pub
'''

Print the fingerprint for an SSH public key:
'''
$ step ssh fingerprint id_ecdsa.pub
'''`,
	}
}

func fingerprint(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	name := ctx.Args().First()
	if name == "" {
		name = "-"
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	s, err := sshutil.Fingerprint(b)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}
