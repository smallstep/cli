package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Action:    command.ActionFunc(formatAction),
		Usage:     `reformat certificate`,
		UsageText: `**step certificate format** <crt-file> [**--out**=<file>]`,
		Description: `**step certificate format** prints the certificate or CSR in a different format.

Only 2 formats are currently supported; PEM and ASN.1 DER. This tool will convert
a certificate or CSR in one format to the other.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or CSR file.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Convert PEM format to DER:
'''
$ step certificate format foo.pem
'''

Convert DER format to PEM:
'''
$ step certificate format foo.der
'''

Convert PEM format to DER and write to disk:
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
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var (
		out = ctx.String("out")
		ob  []byte
	)

	var crtFile string
	if ctx.NArg() == 1 {
		crtFile = ctx.Args().First()
	} else {
		crtFile = "-"
	}

	crtBytes, err := utils.ReadFile(crtFile)
	if err != nil {
		return errs.FileError(err, crtFile)
	}

	switch {
	case bytes.Contains(crtBytes, []byte("-----BEGIN ")): // PEM format
		ob, err = decodeCertificatePem(crtBytes)
		if err != nil {
			return err
		}
	default: // assuming DER format
		if crt, err := x509.ParseCertificate(crtBytes); err == nil {
			ob = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt.Raw,
			})
		} else if csr, err := x509.ParseCertificateRequest(crtBytes); err == nil {
			ob = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: csr.Raw,
			})
		} else {
			return errors.Errorf("error parsing DER format certificate or certificate request")
		}
	}

	if out == "" {
		os.Stdout.Write(ob)
	} else {
		var mode = os.FileMode(0600)
		if crtFile != "-" {
			if info, err := os.Stat(crtFile); err == nil {
				mode = info.Mode()
			}
		}
		if err := utils.WriteFile(out, ob, mode); err != nil {
			return err
		}
		ui.Printf("Your certificate has been saved in %s\n", out)
	}

	return nil
}

func decodeCertificatePem(b []byte) ([]byte, error) {
	var block *pem.Block
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			return nil, errors.Errorf("error decoding certificate: invalid PEM block")
		}
		switch block.Type {
		case "CERTIFICATE":
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing certificate")
			}
			return crt.Raw, nil
		case "CERTIFICATE REQUEST":
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing certificate request")
			}
			return csr.Raw, nil
		default:
			continue
		}
	}

	return nil, errors.Errorf("error decoding certificate: invalid PEM block")
}
