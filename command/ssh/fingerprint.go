package ssh

import (
	"fmt"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/crypto/sshutil"
)

func fingerPrintCommand() cli.Command {
	return cli.Command{
		Name:      "fingerprint",
		Action:    cli.ActionFunc(fingerprint),
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
		Flags: []cli.Flag{
			flags.FingerprintFormatFlag("base64-raw"),
		},
	}
}

func fingerprint(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	format, err := flags.ParseFingerprintFormat(ctx.String("format"))
	if err != nil {
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

	s, err := sshutil.FormatFingerprint(b, format)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}
