package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"github.com/smallstep/cli/crypto/pemutil"
	"os"

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

If either PEM or ASN.1 DER is provided as a positional argument, this tool will convert
a certificate or CSR in one format to the other.

If PFX / PKCS12 file is provided as a positional argument, and the format is specified as "pem"/"der", 
it extracts a certificate and private key from the input.

If either PEM or ASN.1 DER is provided in "--crt", "--key" and "--ca", and the format is specified as "p12", 
it creates PFX / PKCS12 file from the input .

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or CSR file, or .p12 file when you specify --crt/--ca option.

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

Convert a certificate, a private key, and intermediate certificates to a .p12 file:

'''
$ step certificate format foo.crt --crt foo.p12 --key foo.key --ca intermediate.crt --format p12
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Usage: `Target format.`,
			},
			cli.StringFlag{
				Name:  "crt",
				Usage: `The path to a certificate.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: `The path to a private key.`,
			},
			cli.StringSliceFlag{
				Name: "ca",
				Usage: `The path a CA or intermediate certificate. When converting certificates
to p12 file, Use the '--ca' flag multiple times to add
multiple CAs or intermediates.`,
			},
			cli.StringFlag{
				Name:  "out",
				Usage: `Path to write the reformatted result.`,
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
	crt := ctx.String("crt")
	key := ctx.String("key")
	ca := ctx.StringSlice("ca")
	out := ctx.String("out")
	passwordFile := ctx.String("password-file")
	noPassword := ctx.Bool("no-password")
	insecure := ctx.Bool("insecure")

	if out != "" {
		if crt != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "crt")
		}
		if key != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "key")
		}
		if len(ca) != 0 {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "ca")
		}
		if format != "" {
			return errs.IncompatibleFlagWithFlag(ctx, "out", "format")
		}
	}

	if passwordFile != "" && noPassword {
		return errs.IncompatibleFlagWithFlag(ctx, "no-password", "password-file")
	}

	switch {
	case format == "pem" || format == "der":
		if len(ca) > 1 {
			return errors.Errorf("--ca option specified for multiple times when the target format is pem/der")
		}
		caFile := ""
		if len(ca) == 1 {
			caFile = ca[0]
		}
		if err := fromP12(sourceFile, crt, key, caFile, passwordFile, noPassword, format); err != nil {
			return err
		}
	case format == "p12":
		if noPassword && !insecure {
			return errs.RequiredInsecureFlag(ctx, "no-password")
		}
		if err := ToP12(crt, sourceFile, key, ca, passwordFile, noPassword, insecure); err != nil {
			return err
		}
	case format == "":
		if err := interconvertPemAndDer(sourceFile, out); err != nil {
			return err
		}
	default:
		return errors.Errorf("unrecognized argument: --format %s", format)
	}
	return nil
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
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing RSA private key")
			}
			keyBytes := x509.MarshalPKCS1PrivateKey(key)
			return keyBytes, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing EC private key")
			}
			keyBytes, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, errors.Wrap(err, "error converting EC private key to DER format")
			}
			return keyBytes, nil
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing private key")
			}
			keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, errors.Wrap(err, "error converting private key to DER format")
			}
			return keyBytes, nil
		default:
			continue
		}
	}

	return nil, errors.Errorf("error decoding certificate: invalid PEM block")
}

func fromP12(p12File, crtFile, keyFile, caFile, passwordFile string, noPassword bool, format string) error {
	var err error
	var password string
	if passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	if password == "" && !noPassword {
		pass, err := ui.PromptPassword("Please enter a password to decrypt the .p12 file")
		if err != nil {
			return errs.Wrap(err, "error reading password")
		}
		password = string(pass)
	}

	p12Data, err := utils.ReadFile(p12File)
	if err != nil {
		return errs.Wrap(err, "error reading file %s", p12File)
	}

	key, crt, ca, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return errs.Wrap(err, "failed to decode PKCS12 data")
	}

	if err := write(crtFile, format, crt); err != nil {
		return err
	}

	if err := writeCerts(caFile, format, ca); err != nil {
		return err
	}

	if err := write(keyFile, format, key); err != nil {
		return err
	}

	return nil
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
			return err
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
