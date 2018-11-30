package crypto

import (
	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func createKeyPairCommand() cli.Command {
	return cli.Command{
		Name:   "keypair",
		Action: command.ActionFunc(createAction),
		Usage:  "generate a public / private keypair in PEM format",
		UsageText: `**step crypto keypair** <pub_file> <priv_file>
[**--curve**=<curve>] [**--no-password**] [**--size**=<size>]
[**--kty**=<key-type>]`,
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
$ step crypto keypair foo.pub foo.key --kty RSA --size 4096
'''

Create an RSA public / private key with fewer than the recommended number of
bits (recommended >= 2048 bits):

'''
$ step crypto keypair foo.pub foo.key --kty RSA --size 1024 --insecure
'''

Create an EC public / private key pair with curve P-521:

'''
$ step crypto keypair foo.pub foo.key --kty EC --curve "P-521"
'''

Create an EC public / private key pair but do not encrypt the private key file:

'''
$ step crypto keypair foo.pub foo.key --kty EC --curve "P-256" \
--no-password --insecure
'''

Create an Octet Key Pair with curve Ed25519:

'''
$ step crypto keypair foo.pub foo.key --kty OKP --curve Ed25519
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "kty",
				Value: "EC",
				Usage: `The <kty> (key type) to create.
If unset, default is EC.

: <kty> is a case-sensitive string and must be one of:

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
			cli.StringFlag{
				Name: "from-jwk",
				Usage: `Create a PEM representing the key encoded in an
existing <jwk-file> instead of creating a new key.`,
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
			flags.Force,
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

	var err error
	var pub, priv interface{}
	fromJWK := ctx.String("from-jwk")
	if len(fromJWK) > 0 {
		switch {
		case ctx.IsSet("kty"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "kty")
		case ctx.IsSet("curve"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "curve")
		case ctx.IsSet("size"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "size")
		}

		jwk, err := jose.ParseKey(fromJWK)
		if err != nil {
			return err
		}

		if jwk.IsPublic() {
			pub = jwk.Key
		} else {
			pub = jwk.Public().Key
			priv = jwk.Key
		}
	} else {
		kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, insecure, "kty",
			"curve", "size")
		if err != nil {
			return err
		}

		pub, priv, err = keys.GenerateKeyPair(kty, crv, size)
		if err != nil {
			return err
		}
	}

	_, err = pemutil.Serialize(pub, pemutil.ToFile(pubFile, 0600))
	if err != nil {
		return err
	}

	if priv == nil {
		ui.Printf("Your public key has been saved in %s.\n", pubFile)
		ui.Println("Only the public PEM was generated.")
		ui.Println("Cannot retrieve a private key from a public one.")
		return nil
	}

	if noPass {
		_, err = pemutil.Serialize(priv, pemutil.ToFile(privFile, 0600))
		if err != nil {
			return err
		}
	} else {
		pass, err := ui.PromptPassword("Please enter the password to encrypt the private key")
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		_, err = pemutil.Serialize(priv, pemutil.WithEncryption(pass),
			pemutil.ToFile(privFile, 0600))
		if err != nil {
			return err
		}
	}

	ui.Printf("Your public key has been saved in %s.\n", pubFile)
	ui.Printf("Your private key has been saved in %s.\n", privFile)
	return nil
}
