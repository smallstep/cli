package crypto

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	spem "github.com/smallstep/cli/crypto/pem"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils/reader"
	"github.com/urfave/cli"
)

func createKeyPairCommand() cli.Command {
	return cli.Command{
		Name:   "keypair",
		Action: cli.ActionFunc(createAction),
		Usage:  "generate a public /private keypair in PEM format.",
		UsageText: `**step crypto keypair** <pub_file> <priv_file>
[**--curve**=<curve>] [**--no-password**] [**--size**=<size>]
[**--type**=<type>]`,
		Description: `**step crypto keypair** generates a raw public /
private keypair in PEM format. These keys can be used by other operations
to sign and encrypt data, and the public key can be bound to an identity
in a CSR and signed by a CA to produce a certificate.

Private keys are encrypted using a password. You'll be prompted for this
password automatically when the key is used.

## POSITIONAL ARGUMENTS

<pub_file>
: The path to write the public key.

<priv_file>
: The path to write the private key.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Create an RSA public / private key pair with 4096 bits:

'''
$ step crypto keypair foo.pub foo.key --type RSA --size 4096
'''

Create an RSA public / private key with fewer than the recommended number of
bits (recommended >= 2048 bits):

'''
$ step crypto keypair foo.pub foo.key --type RSA --size 1024 --insecure
'''

Create an EC public / private key pair with curve P-521:

'''
$ step crypto keypair foo.pub foo.key --type EC --curve "P-521"
'''

Create an EC public / private key pair but do not encrypt the private key file:

'''
$ step crypto keypair foo.pub foo.key --type EC --curve "P-256" \
--no-password --insecure
'''

Create an Octet Key Pair with curve Ed25519:

'''
$ step crypto keypair foo.pub foo.key --type OKP --curve Ed25519
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "type",
				Value: "EC",
				Usage: `The <type> of key to create.
If unset, default is EC.

: <type> is a case-sensitive string and must be one of:

    **EC**
    :  Create an **elliptic curve** keypair

    **OKP**
    :  Create an octet key pair (for **"Ed25519"** curve)

    **RSA**
    :  Create an **RSA** keypair
`,
			},
			cli.IntFlag{
				Name: "size",
				Usage: `The <size> (in bits) of the key for RSA and oct key types. RSA keys require a
minimum key size of 2048 bits. If unset, default is 2048 bits for RSA keys and 128 bits for oct keys.`,
			},
			cli.StringFlag{
				Name: "crv, curve",
				Usage: `The elliptic <curve> to use for EC and OKP key types. Corresponds
to the **"crv"** JWK parameter. Valid curves are defined in JWA [RFC7518]. If
unset, default is P-256 for EC keys and Ed25519 for OKP keys.

: <curve> is a case-sensitive string and must be one of:

    **P-256**
    :  NIST P-256 Curve

    **P-384**
    :  NIST P-384 Curve

    **P-521**
    :  NIST P-521 Curve

    **Ed25519**
    :  Ed25519 Curve
`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
		},
	}
}

func createAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	pubFile := ctx.Args().Get(0)
	privFile := ctx.Args().Get(1)
	if pubFile == privFile {
		return errs.EqualArguments(ctx, "PUB_FILE", "PRIV_FILE")
	}

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
	}

	var (
		crv  = ctx.String("curve")
		size = ctx.Int("size")
		typ  = ctx.String("type")
	)
	switch typ {
	case "RSA":
		if size < 2048 && !insecure {
			return errs.MinSizeInsecureFlag(ctx, "size", "2048")
		}
		if size <= 0 {
			return errs.MinSizeFlag(ctx, "size", "0")
		}
		if ctx.IsSet("curve") {
			return errs.IncompatibleFlagValue(ctx, "curve", "type", typ)
		}
	case "EC":
		if ctx.IsSet("size") {
			return errs.IncompatibleFlagValue(ctx, "size", "type", typ)
		}
		if !ctx.IsSet("curve") {
			return errs.RequiredWithFlagValue(ctx, "type", typ, "curve")
		}
		switch crv {
		case "P-256", "P-384", "P-521": //ok
		default:
			return errs.IncompatibleFlagValues(ctx, "curve", crv, "type", typ)
		}
	case "OKP":
		if ctx.IsSet("size") {
			return errs.IncompatibleFlagValue(ctx, "size", "type", typ)
		}
		if !ctx.IsSet("curve") {
			return errs.RequiredWithFlagValue(ctx, "type", typ, "curve")
		}
		switch crv {
		case "Ed25519": //ok
		default:
			return errs.IncompatibleFlagValues(ctx, "curve", crv, "type", typ)
		}
	default:
		return errs.InvalidFlagValue(ctx, "--type", typ, "RSA, EC, OKP")
	}

	pub, priv, err := keys.GenerateKeyPair(typ, crv, size)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = spem.Serialize(pub, spem.ToFile(pubFile, 0600))
	if err != nil {
		return errors.WithStack(err)
	}

	if noPass {
		_, err = spem.Serialize(priv, spem.ToFile(privFile, 0600))
	} else {
		var pass string
		if err := reader.ReadPasswordSubtle(
			fmt.Sprintf("Password with which to encrypt private key file `%s`: ", privFile),
			&pass, "Password", reader.RetryOnEmpty); err != nil {
			return errors.WithStack(err)
		}
		_, err = spem.Serialize(priv, spem.WithEncryption(pass),
			spem.ToFile(privFile, 0600))
	}
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
