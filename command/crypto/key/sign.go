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
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
)

var hashAlgFlag = cli.StringFlag{
	Name:  "alg",
	Value: "sha256",
	Usage: `The hash algorithm to use on RSA PKCS #1 1.5 and RSA-PSS signatures.

: <algorithm> must be one of:

**sha1** (or sha)
:  SHA-1 produces a 160-bit hash value

**sha224**
:  SHA-224 produces a 224-bit hash value

**sha256** (default)
:  SHA-256 produces a 256-bit hash value

**sha384**
:  SHA-384 produces a 384-bit hash value

**sha512**
:  SHA-512 produces a 512-bit hash value

**sha512-224**
:  SHA-512/224 uses SHA-512 and truncates the output to 224 bits

**sha512-256**
:  SHA-512/256 uses SHA-512 and truncates the output to 256 bits

**md5** (requires --insecure)
:  MD5 produces a 128-bit hash value
`,
}

func signCommand() cli.Command {
	return cli.Command{
		Name:      "sign",
		Action:    command.ActionFunc(signAction),
		Usage:     `sign a message using an asymmetric key`,
		UsageText: `**step crypto key sign** -key <key-file> [<file>]`,
		Description: `**step crypto key sign** generates a signature of the digest of a file or a message
using an asymmetric key.

For an RSA key, the resulting signature is either a PKCS #1 v1.5 or PSS
signature. For an (EC)DSA key, it is a DER-serialized, ASN.1 signature
structure.

## POSITIONAL ARGUMENTS

<file>
:  File to sign

## EXAMPLES

Sign a file using the default options:
'''
$ step crypto key sign --key priv.key file.txt
'''

Sign a message using the default options:
'''
$ echo "message to be signed" | step crypto key sign --key priv.key
'''

Sign a file using SHA512 as a digest algorithm:
'''
$ step crypto key sign --key priv.key --alg sha512 file.txt
'''

Sign a file using the PKCS #1 v1.5:
'''
$ step crypto key sign --key rsa.key file.txt
'''

Sign a file using the RSA-PSS scheme:
'''
$ step crypto key sign --key rsa.key --pss file.txt
'''`,
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
			cli.BoolFlag{
				Name:  "pss",
				Usage: "Use RSA-PSS signature scheme.",
			},
			hashAlgFlag,
		},
	}
}

func verifyCommand() cli.Command {
	return cli.Command{
		Name:      "verify",
		Action:    command.ActionFunc(verifyAction),
		Usage:     `verify a signed message`,
		UsageText: `**step crypto key verify** -key <key-file> [<file>]`,
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
$ step crypto key verify --key  --sig "base64...=" file.txt
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
			cli.BoolFlag{
				Name:  "pss",
				Usage: "Verify using the RSA-PSS signature scheme.",
			},
			hashAlgFlag,
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
		opts = crypto.Hash(0)
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
	case *rsa.PrivateKey:
		opts, err = rsaHash(ctx)
		if err != nil {
			return err
		}
		digest = hash(opts.HashFunc(), b)
	case ed25519.PrivateKey:
		opts = crypto.Hash(0)
		digest = b
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

// TODO(mariano): try to guess the hash algorithm for RSA and RSA-PSS signatures
// looking at the length of the signature.
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

func hash(h crypto.Hash, data []byte) []byte {
	v := h.New()
	v.Write(data)
	return v.Sum(nil)
}

func rsaHash(ctx *cli.Context) (crypto.SignerOpts, error) {
	var h crypto.Hash
	switch strings.ToLower(ctx.String("alg")) {
	case "sha1":
		h = crypto.SHA1
	case "sha224":
		h = crypto.SHA224
	case "sha256", "":
		h = crypto.SHA256
	case "sha384":
		h = crypto.SHA384
	case "sha512":
		h = crypto.SHA512
	case "sha512-224":
		h = crypto.SHA512_224
	case "sha512-256":
		h = crypto.SHA512_256
	case "md5":
		h = crypto.MD5
	default:
		return nil, errors.Errorf("unsupported algorithm %s", ctx.String("alg"))
	}

	if ctx.Bool("pss") {
		return &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       h,
		}, nil
	}

	return h, nil
}
