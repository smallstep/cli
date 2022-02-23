package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
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

		**md5**
		:  MD5 produces a 128-bit hash value

		**es256k**
		:  ECDSA with the secp256k1 curve and the SHA-256 cryptographic hash function
`,
}

func signCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: command.ActionFunc(signAction),
		Usage:  `sign a message using an asymmetric key`,
		UsageText: `**step crypto key sign** [<file>] **--key**=<key-file>
[**--alg**=<algorithm>] [**--pss**] [**--raw**] [**--password-file**=<file>]`,
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
			hashAlgFlag,
			cli.BoolFlag{
				Name:  "pss",
				Usage: "Use RSA-PSS signature scheme.",
			},
			cli.StringFlag{
				Name:  "format",
				Value: "hex",
				Usage: "Format the output: hex/b64/raw. Default is hex",
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: "The path to the <file> containing passphrase to decrypt the private key.",
			},
		},
	}
}

// make it easy to unit-test
var output io.Writer = os.Stdout

func signAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	keyFile := ctx.String("key")
	if keyFile == "" {
		return errs.RequiredFlag(ctx, "key")
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

	key, err := readKey(keyFile, false, ctx)
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
		case secp256k1.S256(): // using SHA-256
			digest = hash(crypto.SHA256, b)
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

	var outputValue interface{}
	switch v := ctx.String("format"); v {
	case "raw":
		outputValue = sig
	case "hex":
		outputValue = hex.EncodeToString(sig)
	case "b64":
		outputValue = base64.StdEncoding.EncodeToString(sig)
	default:
		return errors.Errorf("unsupported output format %T", v)
	}
	_, err = fmt.Fprintln(output, outputValue)

	return err
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

func readKey(keyFile string, isPubKey bool, ctx *cli.Context) (interface{}, error) {
	if strings.ToLower(ctx.String("alg")) == "es256k" {
		hexRaw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, errors.Wrap(err, "read file error")
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(hexRaw)), "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "file content is not in hex")
		}
		if isPubKey {
			secp256k1Pk, err := secp256k1.ParsePubKey(raw)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse public key")
			}
			return secp256k1Pk.ToECDSA(), nil
		}
		secp256k1Pk := secp256k1.PrivKeyFromBytes(raw)
		return secp256k1Pk.ToECDSA(), nil
	}
	return pemutil.Read(keyFile)
}
