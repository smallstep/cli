package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Action:    command.ActionFunc(formatAction),
		Usage:     `reformat certificate`,
		UsageText: `**step certificate format** <crt_file> [**--out**=<path>]`,
		Description: `**step certificate format** prints the certificate in
a different format.

Only 2 formats are currently supported; PEM and ASN.1 DER. This tool will convert
a certificate in one format to the other.

## POSITIONAL ARGUMENTS

<crt_file>
:  Path to a certificate file.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Convert PEM format to DER.
'''
$ step certificate format foo.pem
'''

Convert DER format to PEM.
'''
$ step certificate format foo.der
'''

Convert PEM format to DER and write to disk.
'''
$ step certificate format foo.pem --out foo.der
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out",
				Usage: `Path to write the reformatted result.`,
			},
			flags.Force,
		},
	}
}

func formatAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile = ctx.Args().Get(0)
		out     = ctx.String("out")
		ob      []byte
	)

	crtBytes, err := utils.ReadFile(crtFile)
	if err != nil {
		return errs.FileError(err, crtFile)
	}

	switch {
	case bytes.HasPrefix(crtBytes, []byte("-----BEGIN ")): // PEM format
		var (
			blocks []*pem.Block
			block  *pem.Block
		)
		for len(crtBytes) > 0 {
			block, crtBytes = pem.Decode(crtBytes)
			if block == nil {
				return errors.Errorf("%s contains an invalid PEM block", crtFile)
			}
			if block.Type != "CERTIFICATE" {
				return errors.Errorf("certificate bundle %s contains an "+
					"unexpected PEM block of type %s\n\n  expected type: "+
					"CERTIFICATE", crtFile, block.Type)
			}
			blocks = append(blocks, block)
		}
		// Only format the first certificate in the chain.
		crt, err := x509.ParseCertificate(blocks[0].Bytes)
		if err != nil {
			return err
		}
		ob = crt.Raw
	default: // assuming DER format
		p := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crtBytes,
		}
		ob = pem.EncodeToMemory(p)
	}

	if out == "" {
		os.Stdout.Write(ob)
	} else {
		info, err := os.Stat(crtFile)
		if err != nil {
			return err
		}
		if err := utils.WriteFile(out, ob, info.Mode()); err != nil {
			return err
		}
		ui.Printf("Your certificate has been saved in %s.\n", out)
	}

	return nil
}
