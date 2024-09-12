package crypto

import (
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func createKeyPairCommand() cli.Command {
	return cli.Command{
		Name:   "keypair",
		Action: command.ActionFunc(createAction),
		Usage:  "generate a public / private keypair in PEM format",
		UsageText: `**step crypto keypair** <pub_file> <priv_file>
[**--kty**=<key-type>] [**--curve**=<curve>] [**--size**=<size>]
[**--password-file**=<file>] [**--no-password**] [**--insecure**]`,
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
			flags.KTY,
			flags.Size,
			flags.Curve,
			cli.StringFlag{
				Name: "from-jwk",
				Usage: `Create a PEM representing the key encoded in an
existing <jwk-file> instead of creating a new key.`,
			},
			flags.PasswordFile,
			flags.NoPassword,
			flags.Insecure,
			flags.Force,
		},
	}
}

func createAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	pubFile := ctx.Args().Get(0)
	privFile := ctx.Args().Get(1)
	if pubFile == privFile {
		return errs.EqualArguments(ctx, "PUB_FILE", "PRIV_FILE")
	}

	insecureMode := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	passwordFile := ctx.String("password-file")
	if noPass && passwordFile != "" {
		return errs.IncompatibleFlag(ctx, "no-password", "password-file")
	}
	if noPass && !insecureMode {
		return errs.RequiredWithFlag(ctx, "no-password", "insecure")
	}

	// Read password if necessary
	var password string
	if passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	var pub, priv interface{}
	fromJWK := ctx.String("from-jwk")
	if fromJWK != "" {
		switch {
		case ctx.IsSet("kty"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "kty")
		case ctx.IsSet("curve"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "curve")
		case ctx.IsSet("size"):
			return errs.IncompatibleFlagWithFlag(ctx, "from-jwk", "size")
		}

		var jwk *jose.JSONWebKey
		jwk, err = jose.ReadKey(fromJWK)
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
		var (
			kty, crv string
			size     int
		)
		kty, crv, size, err = utils.GetKeyDetailsFromCLI(ctx, insecureMode, "kty",
			"curve", "size")
		if err != nil {
			return err
		}
		if insecureMode { // put keyutil in insecure mode, allowing RSA keys shorter than 2048 bits
			undoInsecure := keyutil.Insecure()
			defer undoInsecure()
		}
		pub, priv, err = keyutil.GenerateKeyPair(kty, crv, size)
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
		var pass []byte
		pass, err = ui.PromptPassword("Please enter the password to encrypt the private key", ui.WithValue(password), ui.WithValidateNotEmpty())
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass),
			pemutil.ToFile(privFile, 0600))
		if err != nil {
			return err
		}
	}

	ui.Printf("Your public key has been saved in %s.\n", pubFile)
	ui.Printf("Your private key has been saved in %s.\n", privFile)
	return nil
}
