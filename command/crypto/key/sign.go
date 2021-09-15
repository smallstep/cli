package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:        "sign",
		Action:      command.ActionFunc(signAction),
		Usage:       `todo`,
		UsageText:   `**step crypto key sign** -key <key-file> [<file>]`,
		Description: `**step crypto key sign** `,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "key",
				Usage: "The path to the <file> containing the private key.",
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: "The path to the <file> containing passphrase to decrypt a private key.",
			},
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Print the raw bytes instead of the base64 format.",
			},
		},
	}
}

func verifyCommand() cli.Command {
	return cli.Command{
		Name:        "verify",
		Action:      command.ActionFunc(verifyAction),
		Usage:       `todo`,
		UsageText:   `**step crypto key verify** -key <key-file> [<file>] <sig>`,
		Description: `**step crypto key verify** `,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "key",
				Usage: "The path to the <file> containing the public key.",
			},
			cli.StringFlag{
				Name:  "signature",
				Usage: "The <base64> version of the signature.",
			},
		},
	}
}

func signAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var input string
	switch ctx.NArg() {
	case 0:
		input = "-"
	case 1:
		input = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	b, err := utils.ReadFile(input)
	if err != nil {
		return errs.FileError(err, input)
	}

	keyFile := ctx.String("key")
	key, err := pemutil.Read(keyFile)
	if err != nil {
		return err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.Errorf("key %s is not a signer", keyFile)
	}

	var digest []byte
	var opts crypto.SignerOpts
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P224():
			digest = crypto.SHA224.New().Sum(b)
		case elliptic.P256():
			digest = crypto.SHA256.New().Sum(b)
		case elliptic.P384():
			digest = crypto.SHA384.New().Sum(b)
		case elliptic.P521():
			digest = crypto.SHA512.New().Sum(b)
		default:
			return errors.Errorf("unsupported elliptic curve %s", k.Params().Name)
		}
		opts = crypto.Hash(0)
	case *rsa.PrivateKey:
		digest = crypto.SHA256.New().Sum(b)
		opts = crypto.SHA256
	case ed25519.PrivateKey:
		digest = b
		opts = crypto.Hash(0)
	default:
		return errors.Errorf("unsupported key type %T", k)
	}

	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return errors.Wrap(err, "error signing message")
	}

	if ctx.Bool("raw") {
		os.Stdout.Write(sig)
	} else {
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
	}

	return nil
}

func verifyAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var input string
	switch ctx.NArg() {
	case 0:
		input = "-"
	case 1:
		input = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	b, err := utils.ReadFile(input)
	if err != nil {
		return errs.FileError(err, input)
	}

	sig, err := base64.StdEncoding.DecodeString(ctx.String("signature"))
	if err != nil {
		return errors.Wrap(err, "error decoding base64 signature")
	}

	keyFile := ctx.String("key")
	key, err := pemutil.Read(keyFile)
	if err != nil {
		return err
	}

	var digest []byte
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P224():
			digest = crypto.SHA224.New().Sum(b)
		case elliptic.P256():
			digest = crypto.SHA256.New().Sum(b)
		case elliptic.P384():
			digest = crypto.SHA384.New().Sum(b)
		case elliptic.P521():
			digest = crypto.SHA512.New().Sum(b)
		default:
			return errors.Errorf("unsupported elliptic curve %s", k.Params().Name)
		}
		fmt.Println(ecdsa.VerifyASN1(k, digest, sig))
	case *rsa.PublicKey:
		digest = crypto.SHA256.New().Sum(b)
		fmt.Println(rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig))
	case ed25519.PublicKey:
		fmt.Println(ed25519.Verify(k, b, sig))
	default:
		return errors.Errorf("unsupported public key %s", keyFile)
	}

	return nil
}
