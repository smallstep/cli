package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"golang.org/x/crypto/ssh"
)

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Action:    command.ActionFunc(formatAction),
		Usage:     `reformat a public or private key`,
		UsageText: `**step crypto key format** <key-file> [**--out**=<path>]`,
		Description: `**step crypto key format** prints or writes the key in
a different format.

By default PEM formated keys will be converted to DER with the following rules:

 * ECDSA, RSA, AND Ed25519 public keys will use the DER-encoded PKIX format.
 * ECDSA, AND RSA private keys will use the ASN.1, DER format.
 * Ed25519 private keys will use the DER-encoded PKCS8 encoded form.

And DER encoded keys will be converted to PEM with the following rules:

 * ECDSA, RSA, AND Ed25519 public keys will use the PEM-encoded PKIX format.
 * ECDSA private keys will use the PEM-encoded format defined in RFC 5915 and
   SEC1.
 * RSA private keys will use the PEM-encoded PKCS#1 format.
 * Ed25519 private keys will use the PEM-encoded PKCS#8 format.

The flags **--pkcs8**, **--pem**, **--der**, and **--ssh** can be use to change
the previous defaults. For example we can use **--pkcs8** to save a PKCS#1 RSA
key to the PKCS#8 form. Or we can combine **--pem** and **--pkcs8** to convert
to PKCS#8 a PEM file.

## POSITIONAL ARGUMENTS

<key-file>
:  Path to a file with a public or private key, or the public key of an
   X.509 certificate.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Convert a PEM file to DER:
'''
$ step crypto key format key.pem
'''

Convert DER file to PEM:
'''
$ step crypto key format key.der
'''

Convert a PEM file to OpenSSH:
'''
$ step crypto key format --ssh key.pem
'''

Convert PEM file to DER and write to disk:
'''
$ step crypto key format key.pem --out key.der
'''

Convert a PKCS#1 RSA private key to PKCS#8 using the PEM format:
'''
$ step crypto key format --pem --pkcs8 rsa.pem --out rsa-pkcs8.pem
'''

Convert PKCS#8 RSA private key to the PKCS#1 format:
'''
$ step crypto key format --pem rsa-pkcs8.pem --out rsa.pem
'''

Convert an ASN.1 DER format to the PEM-encoded PKCS#8 format:
'''
$ step crypto key format --pkcs8 key.der --out key-pkcs8.der
'''

Convert an ASN.1 DER format to the DER-encoded PKCS#8 format:
'''
$ step crypto key format --der --pkcs8 key.der --out key-pkcs8.der
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "pkcs8",
				Usage: "Convert RSA and ECDSA private keys to PKCS#8 PEM/DER format.",
			},
			cli.BoolFlag{
				Name: "pem",
				Usage: `Uses PEM as the result encoding format. If neither **--pem** nor **--der** nor
**--ssh** are set it will always switch to the DER format.`,
			},
			cli.BoolFlag{
				Name: "der",
				Usage: `Uses DER as the result enconfig format. If neither **--pem** nor **--der** nor
**--ssh** are set it will always switch to the PEM format.`,
			},
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Uses OpenSSH as the result encoding format on public keys.`,
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
		toPEM      = ctx.Bool("pem")
		toDER      = ctx.Bool("der")
		toSSH      = ctx.Bool("ssh")
		noPassword = ctx.Bool("no-password")
		insecure   = ctx.Bool("insecure")
		key        interface{}
		ob         []byte
	)

	// --pem and --der cannot be used at the same time
	if toPEM && toDER {
		return errs.IncompatibleFlagWithFlag(ctx, "pem", "der")
	}

	// --no-password requires --insecure
	if noPassword && !insecure {
		return errs.RequiredInsecureFlag(ctx, "no-password")
	}

	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	}

	switch {
	case bytes.HasPrefix(b, []byte("-----BEGIN ")): // PEM format:
		opts := []pemutil.Options{pemutil.WithFilename(keyFile)}
		if passFile := ctx.String("password-file"); passFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passFile))
		}
		if key, err = pemutil.Parse(b, opts...); err != nil {
			return err
		}
		// convert to DER if not specified
		if !toPEM && !toDER && !toSSH {
			toDER = true
		}
	case isSSHPublicKey(b):
		if key, err = pemutil.ParseSSH(b); err != nil {
			return err
		}
		// convert to PEM if not specified
		if !toPEM && !toDER && !toSSH {
			toPEM = true
		}
	default: // assuming DER format
		if key, err = pemutil.ParseDER(b); err != nil {
			return err
		}
		// convert to PEM if not specified
		if !toPEM && !toDER && !toSSH {
			toPEM = true
		}
	}

	// If it's a certificate grab it's public key
	if cert, ok := key.(*x509.Certificate); ok {
		key = cert.PublicKey
	}

	switch {
	case toPEM:
		if ob, err = convertToPEM(ctx, key); err != nil {
			return err
		}
	case toDER:
		if ob, err = convertToDER(ctx, key); err != nil {
			return err
		}
	case toSSH:
		if ob, err = convertToSSH(ctx, key); err != nil {
			return err
		}
	default:
		return errors.New("error formatting key: it should not get here")
	}

	if out == "" {
		os.Stdout.Write(ob)
	} else {
		info, err := os.Stat(keyFile)
		if err != nil {
			return errs.FileError(err, keyFile)
		}
		if err := utils.WriteFile(out, ob, info.Mode()); err != nil {
			return errs.FileError(err, out)
		}
		ui.Printf("Your key has been saved in %s.\n", out)
	}

	return nil
}

func isSSHPublicKey(in []byte) bool {
	switch {
	case bytes.HasPrefix(in, []byte(ssh.KeyAlgoRSA)),
		bytes.HasPrefix(in, []byte(ssh.KeyAlgoDSA)),
		bytes.HasPrefix(in, []byte(ssh.KeyAlgoECDSA256)),
		bytes.HasPrefix(in, []byte(ssh.KeyAlgoECDSA384)),
		bytes.HasPrefix(in, []byte(ssh.KeyAlgoECDSA521)),
		bytes.HasPrefix(in, []byte(ssh.KeyAlgoED25519)):
		return true
	default:
		return false
	}
}

func convertToPEM(ctx *cli.Context, key interface{}) (b []byte, err error) {
	opts := []pemutil.Options{
		pemutil.WithPKCS8(ctx.Bool("pkcs8")),
	}

	if !ctx.Bool("no-password") {
		switch key.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			if passFile := ctx.String("password-file"); passFile != "" {
				opts = append(opts, pemutil.WithPasswordFile(passFile))
			} else {
				opts = append(opts, pemutil.WithPasswordPrompt("Please enter the password to encrypt the private key"))
			}
		default:
			return nil, errors.Errorf("unsupported key type %T", key)
		}
	}

	block, err := pemutil.Serialize(key, opts...)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func convertToDER(ctx *cli.Context, key interface{}) (b []byte, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if ctx.Bool("pkcs8") {
			b, err = pemutil.MarshalPKCS8PrivateKey(key)
		} else {
			b = x509.MarshalPKCS1PrivateKey(k)
		}
	case *ecdsa.PrivateKey:
		if ctx.Bool("pkcs8") {
			b, err = pemutil.MarshalPKCS8PrivateKey(key)
		} else {
			b, err = x509.MarshalECPrivateKey(k)
		}
	case ed25519.PrivateKey: // always PKCS#8
		b, err = pemutil.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey: // always PKIX
		b, err = pemutil.MarshalPKIXPublicKey(key)
	default:
		return nil, errors.Errorf("unsupported key type %T", key)
	}
	return
}

func convertToSSH(ctx *cli.Context, key interface{}) ([]byte, error) {
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		k, err := ssh.NewPublicKey(key)
		if err != nil {
			return nil, errors.Wrap(err, "error converting public key")
		}
		return ssh.MarshalAuthorizedKey(k), nil
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return nil, errors.New("ssh format is only supported on public keys")
	default:
		return nil, errors.Errorf("unsupported key type %T", key)
	}
}
