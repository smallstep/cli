package key

import (
	"crypto"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func publicCommand() cli.Command {
	return cli.Command{
		Name:      "public",
		Action:    command.ActionFunc(publicAction),
		Usage:     `print the public key from a private key`,
		UsageText: `**step crypto key public** <key-file> [**--out**=<path>]`,
		Description: `**step crypto key public** prints or writes in a PEM format
the public key corresponding to the given <key-file>.

## POSITIONAL ARGUMENTS

<key-file>
:  Path to a private key.

## EXAMPLES

Print the corresponding public key:
'''
$ step crypto key public priv.pem
'''

Write the corresponding public key to a file:
'''
$ step crypto key public --out pub.pem key.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out",
				Usage: "Path to write the public key.",
			},
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

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	priv, err := pemutil.Parse(b)
	if err != nil {
		return err
	}

	pub, ok := priv.(interface{ Public() crypto.PublicKey })
	if !ok {
		return errors.Errorf("cannot get a public key from %s", name)
	}

	if out := ctx.String("out"); out == "" {
		block, err := pemutil.Serialize(pub.Public())
		if err != nil {
			return err
		}
		os.Stdout.Write(pem.EncodeToMemory(block))
	} else {
		_, err = pemutil.Serialize(pub.Public(), pemutil.ToFile(out, 0600))
		if err != nil {
			return err
		}
		ui.Printf("Your key has been saved in %s.\n", out)
	}

	return nil
}
