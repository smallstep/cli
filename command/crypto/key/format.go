package key

import (
	"bytes"
	"crypto"
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
	"golang.org/x/crypto/ed25519"
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
			cli.BoolFlag{
				Name:  "pkcs8",
				Usage: "Convert RSA and ECDSA private keys to PKCS#8 PEM/DER format.",
			},
			cli.StringFlag{
				Name:  "out",
				Usage: "Path to write the reformatted result.",
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: "Location of file containing passphrase to decrypt private key.",
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt a private key with PEM format. Sensitive
key material will be written to disk unencrypted. This is not recommended.
Requires **--insecure** flag.`,
			},
			flags.Insecure,
			flags.Force,
		},
	}
}

func formatAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		keyFile    = ctx.Args().Get(0)
		out        = ctx.String("out")
		passFile   = ctx.String("password-file")
		pkcs8      = ctx.Bool("pkcs8")
		noPassword = ctx.Bool("no-password")
		insecure   = ctx.Bool("insecure")
		ob         []byte
	)

	if noPassword && !insecure {
		return errs.RequiredInsecureFlag(ctx, "no-password")
	}

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
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if pkcs8 {
				ob, err = pemutil.MarshalPKCS8PrivateKey(key)
			} else {
				ob = x509.MarshalPKCS1PrivateKey(k)
			}
		case *ecdsa.PrivateKey:
			if pkcs8 {
				ob, err = pemutil.MarshalPKCS8PrivateKey(key)
			} else {
				ob, err = x509.MarshalECPrivateKey(k)
			}
		case ed25519.PrivateKey:
			ob, err = pemutil.MarshalPKCS8PrivateKey(key)
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
			ob, err = pemutil.MarshalPKIXPublicKey(key)
		default:
			return errors.Errorf("Unsupoorted key type %T", key)
		}
		if err != nil {
			return err
		}
	default: // assuming DER format
		// Attempt with private keys
		key, err := pemutil.ParsePKCS8PrivateKey(b)
		if err != nil {
			if key, err = x509.ParsePKCS1PrivateKey(b); err != nil {
				key, err = x509.ParseECPrivateKey(b)
			}
		}
		// Attempt with public key
		if err != nil {
			if key, err = x509.ParsePKIXPublicKey(b); err != nil {
				return errors.Errorf("Failed to parse key %s; bad format", keyFile)
			}
		}

		var opts []pemutil.SerializeOption
		if _, ok := key.(crypto.PrivateKey); ok && !noPassword {
			var pass []byte
			if passFile != "" {
				pass, err = utils.ReadPasswordFromFile(passFile)
				if err != nil {
					return err
				}
			} else {
				pass, err = ui.PromptPassword("Please enter the password to encrypt the private key")
				if err != nil {
					return err
				}
			}
			opts = append(opts, pemutil.WithEncryption(pass))
		}

		p, err := pemutil.Serialize(key, opts...)
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
			return errs.FileError(err, keyFile)
		}
		if err := utils.WriteFile(out, ob, info.Mode()); err != nil {
			return err
		}
		ui.Printf("Your key has been saved in %s.\n", out)
	}

	return nil
}
