package certificate

import (
	"encoding/pem"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func keyCommand() cli.Command {
	return cli.Command{
		Name:      "key",
		Action:    command.ActionFunc(keyAction),
		Usage:     "print public key embedded in a certificate",
		UsageText: "**step certificate key** <crt-file> [**--out**=<file>]",
		Description: `**step certificate key** prints the public key embedded in a certificate or
a certificate signing request. If <crt-file> is a certificate bundle, only the
first block will be taken into account.

The command will print a public or a decrypted private key if <crt-file>
contains only a key.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or certificate signing request (CSR).

## EXAMPLES

Get the public key of a certificate:
'''
$ step certificate key certificate.crt
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEio9DLyuglMxakS3w00DUKdGbeXXB
2Mfg6tVofeXYan9RbvftZufiypIAVqGZqO7CR9EbkoyHb/7GcKQa5HZ9rA==
-----END PUBLIC KEY-----
'''

Get the public key of a CSR and save it to a file:
'''
$ step certificate key certificate.csr --out key.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The destination <file> of the public key.",
			},
			flags.Force,
		},
	}
}

func keyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	b, err := utils.ReadFile(filename)
	if err != nil {
		return err
	}

	// Look only at the first block
	key, err := pemutil.ParseKey(b, pemutil.WithFirstBlock())
	if err != nil {
		return err
	}
	block, err := pemutil.Serialize(key)
	if err != nil {
		return err
	}

	if outputFile := ctx.String("output-file"); outputFile != "" {
		if err := utils.WriteFile(outputFile, pem.EncodeToMemory(block), 0600); err != nil {
			return err
		}
		ui.Printf("The public key has been saved in %s.\n", outputFile)
		return nil
	}

	fmt.Print(string(pem.EncodeToMemory(block)))
	return nil
}
