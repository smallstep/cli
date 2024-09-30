package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/utils"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: command.ActionFunc(verifyAction),
		Usage:  `verify a signed message`,
		UsageText: `**step crypto key verify** [<file>] **--key**=<key-file> **--signature**=<base64>
[**--alg**=<algorithm>] [**--pss**]`,
		Description: `**step crypto key verify** verifies the signature of a file or a message.

## POSITIONAL ARGUMENTS

<file>
:  File to verify.

## EXAMPLES

Verify a file with its signature:
'''
s step crypto key verify --key pub.key --sig "base64...=" file.txt
true
'''

Verify a file using the PKCS #1 v1.5:
'''
$ step crypto key verify --key rsa.pub --sig "base64...=" file.txt
'''

Verify a file using the PKCS #1 v1.5 and SHA512:
'''
$ step crypto key verify --key rsa.pub --alg sha512 --sig "base64...=" file.txt
'''

Verify a file using the RSA-PSS scheme:
'''
$ step crypto key verify --key rsa.pub --pss --sig "base64...=" file.txt
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "key",
				Usage: "The path to the <file> containing the public key.",
			},
			cli.StringFlag{
				Name:  "signature,sig",
				Usage: "The <base64> version of the signature.",
			},
			hashAlgFlag,
			cli.BoolFlag{
				Name:  "pss",
				Usage: "Verify using the RSA-PSS signature scheme.",
			},
		},
	}
}

// TODO(mariano): try to guess the hash algorithm for RSA and RSA-PSS signatures
// looking at the length of the signature.
func verifyAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	keyFile := ctx.String("key")
	if keyFile == "" {
		return errs.RequiredFlag(ctx, "key")
	}

	signature := ctx.String("signature")
	if signature == "" {
		return errs.RequiredFlag(ctx, "signature")
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

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errors.Wrap(err, "error decoding base64 signature")
	}

	key, err := pemutil.Read(keyFile)
	if err != nil {
		return err
	}

	printAndReturn := func(b bool) error {
		if b {
			fmt.Println(b)
			return nil
		}
		return errors.Errorf("%v", b)
	}

	var digest []byte
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P224():
			digest = hash(crypto.SHA224, b)
		case elliptic.P256():
			digest = hash(crypto.SHA256, b)
		case elliptic.P384():
			digest = hash(crypto.SHA384, b)
		case elliptic.P521():
			digest = hash(crypto.SHA512, b)
		default:
			return errors.Errorf("unsupported elliptic curve %s", k.Params().Name)
		}
		return printAndReturn(ecdsa.VerifyASN1(k, digest, sig))
	case *rsa.PublicKey:
		opts, err := rsaHash(ctx)
		if err != nil {
			return err
		}
		digest = hash(opts.HashFunc(), b)
		if pssOptions, ok := opts.(*rsa.PSSOptions); ok {
			return printAndReturn(rsa.VerifyPSS(k, opts.HashFunc(), digest, sig, pssOptions) == nil)
		}
		return printAndReturn(rsa.VerifyPKCS1v15(k, opts.HashFunc(), digest, sig) == nil)
	case ed25519.PublicKey:
		return printAndReturn(ed25519.Verify(k, b, sig))
	default:
		return errors.Errorf("unsupported public key %s", keyFile)
	}
}
