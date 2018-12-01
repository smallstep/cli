package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
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

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Action:    command.ActionFunc(formatAction),
		Usage:     `reformat certificate`,
		UsageText: `**step crypto key format** <key_file> [**--out**=<path>]`,
		Description: `**step crypto key format** prints the key in
a different format.

Only a few formats are currently supported. PEM formatted private keys
are converted to DER encoded PKCS8 format, while PEM formatted public keys
are converted to DER encoded PKIX format. DER encoded public and private keys
are converted to PEM format.

## POSITIONAL ARGUMENTS

<crt_file>
:  Path to a certificate file.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Convert PEM format to PKCS8.
'''
$ step crypto key format foo-key.pem
'''

Convert DER format to PEM.
'''
$ step crypto key format foo-key.der
'''

Convert PEM format to DER and write to disk.
'''
$ step crypto key format foo-key.pem --out foo-key.der
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out",
				Usage: `Path to write the reformatted result.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `location of file containing passphrase to decrypt private key`,
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
		keyFile  = ctx.Args().Get(0)
		out      = ctx.String("out")
		passFile = ctx.String("password-file")
		ob       []byte
	)

	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	}

	switch {
	case bytes.HasPrefix(b, []byte("-----BEGIN ")): // PEM format
		opts := []pemutil.Options{pemutil.WithFilename(keyFile)}
		if passFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passFile))
		}
		key, err := pemutil.Parse(b, opts...)
		if err != nil {
			return err
		}
		switch key.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey: // convert to DER-encoded PKCS1 format.
			ob, err = x509.MarshalPKCS8PrivateKey(key)
		case *ecdsa.PublicKey, *rsa.PublicKey: // convert to DER-encoded PKIX format.
			ob, err = x509.MarshalPKIXPublicKey(key)
		default:
			return errors.Errorf("Unsupoorted key type %T", key)
		}
		if err != nil {
			return err
		}
	default: // assuming DER format
		// Attempt to parse first as a PKCS8 formatted private key.
		key, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			var err2 error
			// Try parsing as PKIX formatted public key.
			key, err2 = x509.ParsePKIXPublicKey(b)
			if err2 != nil {
				return errors.Errorf("Failed to parse key %s; bad format", keyFile)
			}
		}

		p, err := pemutil.Serialize(key)
		if err != nil {
			return err
		}
		ob = pem.EncodeToMemory(p)
	}

	if out == "" {
		os.Stdout.Write(ob)
	} else {
		info, err := os.Stat(keyFile)
		if err != nil {
			return err
		}
		if err := utils.WriteFile(out, ob, info.Mode()); err != nil {
			return err
		}
		ui.Printf("Your key has been saved in %s.\n", out)
	}

	return nil
}
