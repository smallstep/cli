package key

import (
	"encoding/pem"
	"os"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func publicCommand() cli.Command {
	return cli.Command{
		Name:   "public",
		Action: command.ActionFunc(publicAction),
		Usage:  `print the public key from a private key or certificate`,
		UsageText: `**step crypto key public** <key-file> [**--out**=<file>]
[**--password-file**=<file>]`,
		Description: `**step crypto key public** outputs the public key, in PEM format, corresponding to
the input <file>.

## POSITIONAL ARGUMENTS

<key-file>
:  Path to a private key.

## EXAMPLES

Print the corresponding public key:
'''
$ step crypto key public priv.pem
'''

Print the public key of an x509 certificate:
'''
$ step crypto key public foo.crt
'''

Write the corresponding public key to a file:
'''
$ step crypto key public --out pub.pem key.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out",
				Usage: "The <file> to write the public key.",
			},
			flags.PasswordFile,
			flags.Force,
		},
	}
}

func publicAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var name string
	switch ctx.NArg() {
	case 0:
		name = "-"
	case 1:
		name = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	var b, err = utils.ReadFile(name)
	if err != nil {
		return errs.FileError(err, name)
	}

	opts := []pemutil.Options{pemutil.WithFilename(name), pemutil.WithFirstBlock()}
	if ctx.IsSet("password-file") {
		opts = append(opts, pemutil.WithPasswordFile(ctx.String("password-file")))
	}
	k, err := pemutil.ParseKey(b, opts...)
	if err != nil {
		return err
	}

	pub, err := keyutil.PublicKey(k)
	if err != nil {
		return err
	}

	block, err := pemutil.Serialize(pub)
	if err != nil {
		return err
	}

	if out := ctx.String("out"); out != "" {
		if err := utils.WriteFile(out, pem.EncodeToMemory(block), 0600); err != nil {
			return err
		}
		ui.Printf("The public key has been saved in %s.\n", out)
		return nil
	}
	os.Stdout.Write(pem.EncodeToMemory(block))
	return nil
}
