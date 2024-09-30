package jwe

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func encryptCommand() cli.Command {
	return cli.Command{
		Name:   "encrypt",
		Action: cli.ActionFunc(encryptAction),
		Usage:  "encrypt a payload using JSON Web Encryption (JWE)",
		UsageText: `**step crypto jwe encrypt**
[**--alg**=<key-enc-algorithm>] [**--enc**=<content-enc-algorithm>]
[**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>]`,
		Description: `**step crypto jwe encrypt** encrypts a payload using JSON Web Encryption
(JWE). By default, the payload to encrypt is read from STDIN and the JWE data
structure will be written to STDOUT.

For examples, see **step help crypto jwe**.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `The cryptographic algorithm used to encrypt or determine the value of the
content encryption key (CEK). Algorithms are case-sensitive strings defined in
RFC7518. The selected algorithm must be compatible with the key type. This
flag is optional. If not specified, the **"alg"** member of the JWK is used. If
the JWK has no **"alg"** member then a default is selected depending on the JWK
key type. If the JWK has an **"alg"** member and the **--alg** flag is passed the two
options must match unless the **--subtle** flag is also passed.

: <key-enc-algorithm> is a case-sensitive string and must be one of:

    **RSA1_5**
    :  RSAES-PKCS1-v1_5

    **RSA-OAEP**
    :  RSAES OAEP using default parameters

    **RSA-OAEP-256** (default for RSA keys)
    :  RSAES OAEP using SHA-256 and MGF1 with SHA-256

    **A128KW**
    :  AES Key Wrap with default initial value using 128-bit key

    **A192KW**
    :  AES Key Wrap with default initial value using 192-bit key

    **A256KW**
    :  AES Key Wrap with default initial value using 256-bit key

    **dir**
    :  Direct use of a shared symmetric key as the content encryption key (CEK)

    **ECDH-ES** (default for EC keys)
    :  Elliptic Curve Diffie-Hellman Ephemeral Static key agreement

    **ECDH-ES+A128KW**
    :  ECDH-ES using Concat KDF and CEK wrapped with "A128KW

    **ECDH-ES+A192KW**
    :  ECDH-ES using Concat KDF and CEK wrapped with "A192KW

    **ECDH-ES+A256KW**
    :  ECDH-ES using Concat KDF and CEK wrapped with "A256KW

    **A128GCMKW**
    :  Key wrapping with AES GCM using 128-bit key

    **A192GCMKW**
    :  Key wrapping with AES GCM using 192-bit key

    **A256GCMKW** (default for oct keys)
    :  Key wrapping with AES GCM using 256-bit key

    **PBES2-HS256+A128KW**
    :  PBES2 with HMAC SHA-256 and "A128KW" wrapping

    **PBES2-HS384+A192KW**
    :  PBES2 with HMAC SHA-256 and "A192KW" wrapping

    **PBES2-HS512+A256KW**
	:  PBES2 with HMAC SHA-256 and "A256KW" wrapping`,
			},
			cli.StringFlag{
				Name:  "enc, encryption-algorithm",
				Value: "A256GCM",
				Usage: `The cryptographic content encryption algorithm used to perform authenticated
encryption on the plaintext payload (the content) to produce ciphertext and
the authentication tag.

: <content-enc-algorithm> is a case-sensitive string and must be one of:

    **A128CBC-HS256**
    :  AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm

    **A192CBC-HS384**
    :  AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm

    **A256CBC-HS512**
    :  AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm

    **A128GCM**
    :  AES GCM using 128-bit key

    **A192GCM**
    :  AES GCM using 192-bit key

    **A256GCM** (default)
	:  AES GCM using 256-bit key`,
			},
			cli.StringFlag{
				Name: "key",
				Usage: `The <file> containing the JWE recipient's public key.
JWEs can be encrypted for a recipient using a public JWK or a PEM encoded public key.`,
			},
			cli.StringFlag{
				Name: "jwks",
				Usage: `The JWK Set containing the recipient's public key. The <jwks> argument should
be the name of a file. The file contents should be a JWK Set. The **--jwks**
flag requires the use of the **--kid** flag to specify which key to use.`,
			},
			cli.StringFlag{
				Name: "kid",
				Usage: `The ID of the recipient's public key. <kid> is a case-sensitive string. When
used with **--key** the <kid> value must match the **"kid"** member of the JWK. When
used with **--jwks** (a JWK Set) the <kid> value must match the **"kid"** member of
one of the JWKs in the JWK Set.`,
			},
			cli.StringFlag{
				Name: "typ, type",
				Usage: `The media type of the JWE, used for disambiguation in applications where
more than one type of JWE may be processed. While this parameter might be
useful to applications, it is ignored by JWE implementations.`,
			},
			cli.StringFlag{
				Name: "cty, content-type",
				Usage: `The media type of the JWE payload, used for disambiguation of JWE objects in
applications where more than one JWE payload type may be present. This
parameter is ignored by JWE implementations, but may be processed by
applications that use JWE.`,
			},
			flags.SubtleHidden,
		},
	}
}

func encryptAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	data, err := utils.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	// Validate parameters
	alg, err := getRecipientAlg(ctx, ctx.String("alg"))
	if err != nil {
		return err
	}

	enc, err := getContentEncryptionAlg(ctx, ctx.String("enc"))
	if err != nil {
		return err
	}

	var isPBES2 bool
	switch alg {
	case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
		isPBES2 = true
	}

	key := ctx.String("key")
	jwks := ctx.String("jwks")
	kid := ctx.String("kid")
	typ := ctx.String("typ")
	cty := ctx.String("cty")
	isSubtle := ctx.Bool("subtle")

	switch {
	case isPBES2 && key != "":
		return errs.MutuallyExclusiveFlags(ctx, "alg "+ctx.String("alg"), "key")
	case isPBES2 && jwks != "":
		return errs.MutuallyExclusiveFlags(ctx, "alg "+ctx.String("alg"), "jwks")
	case !isPBES2 && key == "" && jwks == "":
		return errs.RequiredOrFlag(ctx, "key", "jwk")
	case key != "" && jwks != "":
		return errs.MutuallyExclusiveFlags(ctx, "key", "jwks")
	case jwks != "" && kid == "":
		return errs.RequiredWithFlag(ctx, "kid", "jwks")
	}

	// Add parse options
	var options []jose.Option
	options = append(options, jose.WithUse("enc"))
	if len(alg) > 0 {
		options = append(options, jose.WithAlg(string(alg)))
	}
	if kid != "" {
		options = append(options, jose.WithKid(kid))
	}
	if isSubtle {
		options = append(options, jose.WithSubtle(true))
	}

	// Read key from --key, --jwks, or a user provided
	var pbes2Key []byte
	var jwk *jose.JSONWebKey
	switch {
	case key != "":
		jwk, err = jose.ReadKey(key, options...)
	case jwks != "":
		jwk, err = jose.ReadKeySet(jwks, options...)
	case isPBES2:
		pbes2Key, err = ui.PromptPassword("Please enter the password to encrypt the content encryption key")
	default:
		return errs.RequiredOrFlag(ctx, "key", "jwks")
	}
	if err != nil {
		return err
	}

	var recipient jose.Recipient
	if isPBES2 {
		recipient = jose.Recipient{
			Algorithm: alg,
			Key:       pbes2Key,
			KeyID:     kid,
		}
	} else {
		// Public keys are used for encryption
		jwkPub := jwk.Public()
		jwk = &jwkPub

		if jwk.Use == "sig" {
			return errors.New("invalid jwk use: found 'sig' (signature), expecting 'enc' (encryption)")
		}

		// Validate jwk
		if err := jose.ValidateJWK(jwk); err != nil {
			return err
		}

		// Prepare recipient
		if alg == "" {
			alg, err = getRecipientAlg(ctx, jwk.Algorithm)
			if err != nil {
				return err
			}
		}

		recipient = jose.Recipient{
			Algorithm: alg,
			Key:       jwk,
			KeyID:     kid,
		}
	}

	// Add extra headers
	opts := new(jose.EncrypterOptions)
	if typ != "" {
		opts.WithType(jose.ContentType(typ))
	}
	if cty != "" {
		opts.WithContentType(jose.ContentType(cty))
	}

	// Encrypt
	encrypter, err := jose.NewEncrypter(enc, recipient, opts)
	if err != nil {
		return errs.Wrap(err, "error creating cipher")
	}

	obj, err := encrypter.Encrypt(data)
	if err != nil {
		return errs.Wrap(err, "error encrypting data")
	}

	fmt.Println(obj.FullSerialize())
	return nil
}

func getContentEncryptionAlg(ctx *cli.Context, enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "":
		return jose.A256GCM, nil
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	default:
		return "", errs.InvalidFlagValue(ctx, "enc", enc, "")
	}
}

func getRecipientAlg(ctx *cli.Context, alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "":
		return "", nil
	case "RSA1_5":
		return jose.RSA1_5, nil
	case "RSA-OAEP":
		return jose.RSA_OAEP, nil
	case "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	case "A128KW":
		return jose.A128KW, nil
	case "A192KW":
		return jose.A192KW, nil
	case "A256KW":
		return jose.A256KW, nil
	case "dir":
		return jose.DIRECT, nil
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	case "A128GCMKW":
		return jose.A128GCMKW, nil
	case "A192GCMKW":
		return jose.A192GCMKW, nil
	case "A256GCMKW":
		return jose.A256GCMKW, nil
	case "PBES2-HS256+A128KW":
		return jose.PBES2_HS256_A128KW, nil
	case "PBES2-HS384+A192KW":
		return jose.PBES2_HS384_A192KW, nil
	case "PBES2-HS512+A256KW":
		return jose.PBES2_HS512_A256KW, nil
	default:
		return "", errs.InvalidFlagValue(ctx, "alg", alg, "")
	}
}
