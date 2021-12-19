package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"

	"go.step.sm/crypto/pemutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"

	"software.sslmate.com/src/go-pkcs12"
)

func formatCommand() cli.Command {
	return cli.Command{
		Name:   "format",
		Action: command.ActionFunc(formatAction),
		Usage:  `reformat certificate`,
		UsageText: `**step certificate format** <crt-file> [**--crt**=<file>] [**--key**=<file>]
[**--ca**=<file>] [**--out**=<file>] [**--format**=<format>]`,
		Description: `**step certificate format** prints the certificate or CSR in a different format.

If either PEM or ASN.1 DER is provided as a positional argument, this command
will convert a certificate or CSR in one format to the other.

If PFX / PKCS12 file is provided as a positional argument, and the format is
specified as "pem"/"der", this command extracts a certificate and private key
from the input.

If either PEM or ASN.1 DER is provided in "--crt" | "--key" | "--ca", and the
format is specified as "p12", this command creates a PFX / PKCS12 file from the input .

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate, CSR, or .p12 file.
<crt-file>

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

Convert a .p12 file to a certificate and private key:

'''
$ step certificate format foo.p12 --crt foo.crt --key foo.key --format pem
'''

Convert a .p12 file to a certificate, private key and intermediate certificates:

'''
$ step certificate format foo.p12 --crt foo.crt --key foo.key --ca intermediate.crt --format pem
'''

Convert a certificate and private key to a .p12 file:

'''
$ step certificate format foo.crt --crt foo.p12 --key foo.key --format p12
'''

Convert a certificate, a private key, and intermediate certificates(s) to a .p12 file:

'''
$ step certificate format foo.crt --crt foo.p12 --key foo.key \
  --ca intermediate-1.crt --ca intermediate-2 --format p12
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "format",
				Usage: `The desired output <format> for the input. The default behavior is to
convert between DER and PEM format. Acceptable formats are 'pem', 'der', and 'p12'.`,
			},
			cli.StringFlag{
				Name: "crt",
				Usage: `The path to a certificate <file>. If --format is 'p12' then this flag
must be a PEM or DER encoded certificate. If the positional argument is a P12
encoded file then this flag contains the name for the PEM or DER encoded leaf
certificate extracted from the p12 file.`,
			},
			cli.StringFlag{
				Name: "key",
				Usage: `The path to a key <file>. If --format is 'p12' then this flag
must be a PEM or DER encoded private key. If the positional argument is a P12
encoded file then this flag contains the name for the PEM or DER encoded private
key extracted from the p12 file.`,
			},
			cli.StringSliceFlag{
				Name: "ca",
				Usage: `The path to a root or intermediate certificate <file>. If --format is 'p12'
then this flag can be used to submit one or more CA files encoded as PEM or DER.
Additional CA certificates can be added by using the --ca flag multiple times.
If the positional argument is a p12 encoded file then this flag contains the
name for the PEM or DER encoded certificate chain extracted from the p12 file.`,
			},
			cli.StringFlag{
				Name: "out",
				Usage: `The <file> to write the reformatted result. Only use this flag
for conversions between PEM and DER. Conversions to P12 should use --crt, --key,
and --ca.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to encrypt/decrypt the .p12 file.`,
			},
			flags.NoPassword,
			flags.Insecure,
			flags.Force,
		},
	}
}

func formatAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	sourceFile := ctx.Args().First()
	format := ctx.String("format")
	crtFile := ctx.String("crt")
	keyFile := ctx.String("key")
	caFiles := ctx.StringSlice("ca")
	out := ctx.String("out")
	passwordFile := ctx.String("password-file")
	noPassword := ctx.Bool("no-password")
	insecure := ctx.Bool("insecure")

	if out != "" {
		if crtFile != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "crt")
		}
		if keyFile != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "key")
		}
		if format != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "format")
		}
	}

	if passwordFile != "" && noPassword {
		return errs.IncompatibleFlagWithFlag(ctx, "no-password", "password-file")
	}

	var (
		err  error
		pass = ""
	)
	if passwordFile != "" {
		pass, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return errs.FileError(err, passwordFile)
		}
	}

	if sourceFile != "" {
		srcBytes, err := os.ReadFile(sourceFile)
		if err != nil {
			return errs.FileError(err, sourceFile)
		}

		// First check if P12 input.
		if keyFrom, crtFrom, caFrom, err := pkcs12.DecodeChain(srcBytes, pass); err == nil {
			if format == "p12" {
				return errors.Errorf("invalid flag --format with value 'p12'; cannot from P12 format to P12 format")
			}
			if len(caFrom) > 1 {
				return errors.Errorf("flag --ca cannot be used multiple times when converting from P12 format")
			}
			caFile := ""
			if len(caFiles) == 1 {
				caFile = caFiles[0]
			}
			if err := write(crtFile, format, crtFrom); err != nil {
				return err
			}

			if err := writeCerts(caFile, format, caFrom); err != nil {
				return err
			}

			if err := write(keyFile, format, keyFrom); err != nil {
				return err
			}
		}

		// Now we know input is not P12 format. Check if we're converting to P12.
		if format == "p12" {
			if noPassword && !insecure {
				return errs.RequiredInsecureFlag(ctx, "no-password")
			}
			return ToP12(out, crtFile, keyFile, caFiles, passwordFile, noPassword, insecure)
		}

		// Otherwise interconvert between PEM and DER.
		return interconvertPemAndDer(sourceFile, out)
	}

	// If format is PEM or DER (not P12) then an input certificate file is required.
	if format != "p12" {
		return errors.Errorf("flag --format with value '%s' requires a certificate file as positional argument", format)
	}
	return ToP12(out, crtFile, keyFile, caFiles, passwordFile, noPassword, insecure)
}

func interconvertPemAndDer(crtFile, out string) error {
	var ob []byte

	if crtFile == "" {
		crtFile = "-"
	}

	crtBytes, err := utils.ReadFile(crtFile)
	if err != nil {
		return errs.FileError(err, crtFile)
	}

	switch {
	case bytes.HasPrefix(crtBytes, []byte("-----BEGIN ")): // PEM format
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
			return errs.FileError(err, out)
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
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, errors.Wrap(err, "error parsing certificate")
			}
			return block.Bytes, nil
		case "CERTIFICATE REQUEST":
			if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
				return nil, errors.Wrap(err, "error parsing certificate request")
			}
			return block.Bytes, nil
		case "RSA PRIVATE KEY":
			if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				return nil, errors.Wrap(err, "error parsing RSA private key")
			}
			return block.Bytes, nil
		case "EC PRIVATE KEY":
			if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, errors.Wrap(err, "error parsing EC private key")
			}
			return block.Bytes, nil
		case "PRIVATE KEY":
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, errors.Wrap(err, "error parsing private key")
			}

			return block.Bytes, nil
		default:
			continue
		}
	}

	return nil, errors.Errorf("error decoding certificate: invalid PEM block")
}

func writeCerts(filename, format string, certs []*x509.Certificate) error {
	if len(certs) > 1 && format == "der" {
		return errors.Errorf("der format does not support a certificate bundle")
	}
	var data []byte
	for _, cert := range certs {
		b, err := toByte(cert, format)
		if err != nil {
			return err
		}
		data = append(data, b...)
	}
	if err := maybeWrite(filename, data); err != nil {
		return err
	}
	return nil
}

func write(filename, format string, in interface{}) error {
	b, err := toByte(in, format)
	if err != nil {
		return err
	}
	if err := maybeWrite(filename, b); err != nil {
		return err
	}
	return nil
}

func maybeWrite(filename string, out []byte) error {
	if filename == "" {
		os.Stdout.Write(out)
	} else {
		if err := utils.WriteFile(filename, out, 0600); err != nil {
			return errs.FileError(err, filename)
		}
	}
	return nil
}

func toByte(in interface{}, format string) ([]byte, error) {
	pemblk, err := pemutil.Serialize(in)
	if err != nil {
		return nil, err
	}
	pemByte := pem.EncodeToMemory(pemblk)
	switch format {
	case "der":
		derByte, err := decodeCertificatePem(pemByte)
		if err != nil {
			return nil, err
		}
		return derByte, nil
	case "pem", "":
		return pemByte, nil
	default:
		return nil, errors.Errorf("unsupported format: %s", format)
	}
}
