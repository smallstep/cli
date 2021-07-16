package ca

import (
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func rekeyCertificateCommand() cli.Command {
	return cli.Command{
		Name:      "rekey",
		Action:    command.ActionFunc(rekeyCertificateAction),
		Usage:     "rekey a valid certificate",
		UsageText: `**step ca renew** <crt-file> <key-file> 
					[**--out**=<file>]`,
Description:
		`**step ca rekey** command rekeys the given certificate (with a request to the
		certificate authority) and writes the new certificate to disk - either overwriting
		<crt-file> or using a new file when the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to renew.

<key-file>
:  They private key file of the certificate.

## EXAMPLES

Rekey a certificate
'''
$ step ca rekey
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
			},
		},
	}
}

func rekeyCertificateAction(ctx *cli.Context) error {
	err := errs.NumberOfArguments(ctx, 2)
	if err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)

	outFile := ctx.String("out")
	if len(outFile) == 0 {
		outFile = certFile
	}




	return nil
}