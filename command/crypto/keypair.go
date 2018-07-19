package crypto

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/reader"
	"github.com/urfave/cli"
)

func createKeyPairCommand() cli.Command {
	return cli.Command{
		Name:      "keypair",
		Action:    cli.ActionFunc(createAction),
		Usage:     "generate a public /private keypair in PEM format.",
		UsageText: `step crypto keypair PUB_FILE PRIV_FILE [--type=TYPE] [--size=SIZE] [--curve=CURVE]`,
		Description: `The 'step crypto keypair' command generates a raw public / private keypair
  in PEM format. These keys can be used by other operations to sign
  and encrypt data, and the public key can be bound to an identity in a CSR and
  signed by a CA to produce a certificate.

  Private keys are encrypted using a password. You'll be prompted for this password
  automatically when the key is used.

POSITIONAL ARGUMENTS:
  PUB_FILE
    The path to write the public key.

  PRIV_FILE
    The path to write the private key.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "type",
				Value: "EC",
				Usage: `The type of key to generate.

    TYPE is a case-sensitive string and must be one of:
      EC
        Generate an asymmetric Elliptic Curve Key Pair.
      RSA
        Generate an asymmetric RSA (Rivest–Shamir–Adleman) Key Pair.
      OKP
        Generate an asymmetric Octet Key Pair.`,
			},
			cli.IntFlag{
				Name: "size",
				Usage: `The size (in bits) of the key for RSA and oct key types. RSA keys require a
  minimum key size of 2048 bits.`,
				Value: 2048,
			},
			cli.StringFlag{
				Name:  "crv, curve",
				Value: "P-256",
				Usage: `The elliptic curve to use for this keypair for EC and OKP key types.

    CURVE is a case-sensitive string and must be one of:
      P-256
        NIST P-256 Curve; compatible with 'EC' key type only
      P-384
        NIST P-384 Curve; compatible with 'EC' key type only
      P-521
        NIST P-521 Curve; compatible with 'EC' key type only
      Ed25519
        EdDSA Curve 25519; compatible with 'OKP' key type only`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
			cli.BoolFlag{
				Name:  "no-password",
				Usage: `The directive to leave the private key unencrypted. This is not recommended.`,
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

	typ := ctx.String("type")
	crv := ctx.String("crv")
	if ctx.IsSet("crv") {
		switch typ {
		case "EC", "OKP":
		default:
			return errors.Errorf("key type '%s' is not compatible with flag '--crv'", typ)
		}
	} else {
		switch typ {
		// If crv not set and the key type is OKP then set cruve Ed25519.
		// The cli assumes a default curve for EC key type.
		case "OKP":
			crv = "Ed25519"
		}
	}
	if ctx.IsSet("size") && typ != "RSA" {
		return errors.Errorf("key type '%s' is not compatible with flag '--size'", typ)
	}
	size := ctx.Int("size")
	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")

	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
	}
	if size < 2048 && !insecure {
		return errs.MinSizeInsecureFlag(ctx, "size", "2048")
	}
	if size <= 0 {
		return errs.MinSizeFlag(ctx, "size", "0")
	}

	pub, priv, err := keys.GenerateKeyPair(typ, crv, size)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := utils.WritePublicKey(pub, pubFile); err != nil {
		return errors.WithStack(err)
	}

	var pass string
	if !noPass {
		reader.ReadPasswordSubtle(
			fmt.Sprintf("Password with which to encrypt private key file `%s`: ", privFile),
			&pass, "Password", reader.RetryOnEmpty)

	}
	if err := utils.WritePrivateKey(priv, pass, privFile); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
