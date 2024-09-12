package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Action:    cli.ActionFunc(formatAction),
		Usage:     `reformat a public or private key`,
		UsageText: `**step crypto key format** <key-file> [**--out**=<file>]`,
		Description: `**step crypto key format** prints or writes the key in
a different format.

By default PEM formatted keys will be converted to DER with the following rules:

 * ECDSA, RSA, AND Ed25519 public keys will use the DER-encoded PKIX format.
 * ECDSA, AND RSA private keys will use the ASN.1, DER format.
 * Ed25519 private keys will use the DER-encoded PKCS8 encoded form.

And DER encoded keys will be converted to PEM with the following rules:

 * ECDSA, RSA, AND Ed25519 public keys will use the PEM-encoded PKIX format.
 * ECDSA private keys will use the PEM-encoded format defined in RFC 5915 and
   SEC1.
 * RSA private keys will use the PEM-encoded PKCS#1 format.
 * Ed25519 private keys will use the PEM-encoded PKCS#8 format.

The flags **--pkcs8**, **--pem**, **--der**, **--ssh**, and **--jwk** can be use
to change the previous defaults. For example we can use **--pkcs8** to save a
PKCS#1 RSA key to the PKCS#8 form. Or we can combine **--pem** and **--pkcs8**
to convert to PKCS#8 a PEM file.

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

Convert a PEM file to JWK:
'''
$ step crypto key format --jwk key.pem
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
**--ssh** nor **--jwk** are set it will always switch to the DER format.`,
			},
			cli.BoolFlag{
				Name: "der",
				Usage: `Uses DER as the result enconfig format. If neither **--pem** nor **--der** nor
**--ssh** nor **--jwk** are set it will always switch to the PEM format.`,
			},
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Uses OpenSSH as the result encoding format.`,
			},
			cli.BoolFlag{
				Name:  "jwk",
				Usage: `Uses JSON Web Key as the result encoding format.`,
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
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var keyFile string
	switch ctx.NArg() {
	case 0:
		keyFile = "-"
	case 1:
		keyFile = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	var (
		out        = ctx.String("out")
		toPEM      = ctx.Bool("pem")
		toDER      = ctx.Bool("der")
		toSSH      = ctx.Bool("ssh")
		toJWK      = ctx.Bool("jwk")
		noPassword = ctx.Bool("no-password")
		insecure   = ctx.Bool("insecure")
		key        interface{}
		ob         []byte
	)

	switch {
	case toPEM && toDER:
		return errs.IncompatibleFlagWithFlag(ctx, "pem", "der")
	case toPEM && toSSH:
		return errs.IncompatibleFlagWithFlag(ctx, "pem", "ssh")
	case toPEM && toJWK:
		return errs.IncompatibleFlagWithFlag(ctx, "pem", "jwk")
	case toDER && toSSH:
		return errs.IncompatibleFlagWithFlag(ctx, "der", "ssh")
	case toDER && toJWK:
		return errs.IncompatibleFlagWithFlag(ctx, "der", "jwk")
	case toSSH && toJWK:
		return errs.IncompatibleFlagWithFlag(ctx, "ssh", "jwk")
	}

	// --no-password requires --insecure
	if noPassword && !insecure {
		return errs.RequiredInsecureFlag(ctx, "no-password")
	}

	b, err := utils.ReadFile(keyFile)
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
		if !toPEM && !toDER && !toSSH && !toJWK {
			toDER = true
		}
	case isSSHPublicKey(b):
		if key, err = pemutil.ParseSSH(b); err != nil {
			return err
		}
		// convert to PEM if not specified
		if !toPEM && !toDER && !toSSH && !toJWK {
			toPEM = true
		}
	case isJWK(b):
		if key, err = parseJWK(ctx, b); err != nil {
			return err
		}
		// convert to PEM if not specified
		if !toPEM && !toDER && !toSSH && !toJWK {
			toPEM = true
		}
	default: // assuming DER format
		if key, err = pemutil.ParseDER(b); err != nil {
			return err
		}
		// convert to PEM if not specified
		if !toPEM && !toDER && !toSSH && !toJWK {
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
	case toJWK:
		if ob, err = convertToJWK(ctx, key); err != nil {
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

func isJWK(in []byte) bool {
	if bytes.HasPrefix(in, []byte("{")) {
		return true
	}
	if _, err := jose.ParseEncrypted(string(in)); err == nil {
		return true
	}
	return false
}

func parseJWK(ctx *cli.Context, b []byte) (interface{}, error) {
	// Decrypt key if encrypted.
	if _, err := jose.ParseEncrypted(string(b)); err == nil {
		opts := []jose.Option{
			jose.WithPasswordPrompter("Please enter the password to decrypt the key", func(s string) ([]byte, error) {
				return ui.PromptPassword(s)
			}),
		}
		if passFile := ctx.String("password-file"); passFile != "" {
			opts = append(opts, jose.WithPasswordFile(passFile))
		}
		b, err = jose.Decrypt(b, opts...)
		if err != nil {
			return nil, err
		}
	}

	// Parse decrypted key
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling key")
	}
	if jwk.Key == nil {
		return nil, errors.New("error parsing key: not found")
	}

	return jwk.Key, nil
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
				opts = append(opts, pemutil.WithPasswordPrompt("Please enter the password to encrypt the private key", func(s string) ([]byte, error) {
					return ui.PromptPassword(s, ui.WithValidateNotEmpty())
				}))
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
			b, err = x509.MarshalPKCS8PrivateKey(key)
		} else {
			b = x509.MarshalPKCS1PrivateKey(k)
		}
	case *ecdsa.PrivateKey:
		if ctx.Bool("pkcs8") {
			b, err = x509.MarshalPKCS8PrivateKey(key)
		} else {
			b, err = x509.MarshalECPrivateKey(k)
		}
	case ed25519.PrivateKey: // always PKCS#8
		b, err = x509.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey: // always PKIX
		b, err = x509.MarshalPKIXPublicKey(key)
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
		opts := []pemutil.Options{
			pemutil.WithOpenSSH(true),
		}
		if !ctx.Bool("no-password") {
			if passFile := ctx.String("password-file"); passFile != "" {
				opts = append(opts, pemutil.WithPasswordFile(passFile))
			} else {
				opts = append(opts, pemutil.WithPasswordPrompt("Please enter the password to encrypt the private key", func(s string) ([]byte, error) {
					return ui.PromptPassword(s, ui.WithValidateNotEmpty())
				}))
			}
		}
		block, err := pemutil.Serialize(key, opts...)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, errors.Errorf("unsupported key type %T", key)
	}
}

func convertToJWK(ctx *cli.Context, key interface{}) ([]byte, error) {
	b, err := json.Marshal(&jose.JSONWebKey{Key: key})
	if err != nil {
		return nil, err
	}

	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return b, nil
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		if ctx.Bool("no-password") {
			return b, nil
		}

		opts := []jose.Option{
			jose.WithContentType("jwk+json"),
		}
		if passFile := ctx.String("password-file"); passFile != "" {
			opts = append(opts, jose.WithPasswordFile(passFile))
		}
		jwe, err := jose.Encrypt(b, opts...)
		if err != nil {
			return nil, err
		}
		return []byte(jwe.FullSerialize()), nil
	default:
		return nil, errors.Errorf("unsupported key type %T", key)
	}
}
