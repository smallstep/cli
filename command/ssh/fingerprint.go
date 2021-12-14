package ssh

import (
	"fmt"

	"github.com/smallstep/cli/command"
	libfingerprint "github.com/smallstep/cli/crypto/fingerprint"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	libcommand "go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
)

func fingerPrintCommand() cli.Command {
	return cli.Command{
		Name:      "fingerprint",
		Action:    libcommand.ActionFunc(fingerprint),
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
			command.FingerprintFormatFlag("base64-raw"),
		},
	}
}

func fingerprint(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var (
		format = ctx.String("format")

		opts []libfingerprint.Option
	)

	if format != "" {
		encoding, err := command.GetFingerprintEncoding(format)
		if err != nil {
			return err
		}
		opts = []libfingerprint.Option{
			libfingerprint.WithPrefix("SHA256:"),
			libfingerprint.WithEncoding(encoding),
		}
	}

	name := ctx.Args().First()
	if name == "" {
		name = "-"
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	s, err := sshutil.Fingerprint(b, sshutil.WithFingerprintOptions(opts...))
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}
