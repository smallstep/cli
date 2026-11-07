package ssh

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/sshutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
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

Print the fingerprint for the public key in 
an SSH certificate:
'''
$ step ssh fingerprint id_ecdsa-cert.pub
'''

Print the fingerprint for an SSH public key:
'''
$ step ssh fingerprint id_ecdsa.pub
'''

Print the fingerprint for the full contents of 
an SSH certificate:
'''
$ step ssh fingerprint id_ecdsa-cert.pub --certificate
'''`,
		Flags: []cli.Flag{
			flags.FingerprintFormatFlag("base64-raw"),
			flags.FingerprintCertificateModeFlag(),
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

	certificateMode := ctx.Bool("certificate")

	name := ctx.Args().First()
	if name == "" {
		name = "-"
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	var fingerprint string
	if certificateMode {
		fingerprint, err = sshutil.FormatCertificateFingerprint(b, format)
	} else {
		fingerprint, err = sshutil.FormatFingerprint(b, format)
	}
	if err != nil {
		return err
	}

	fmt.Println(fingerprint)
	return nil
}
