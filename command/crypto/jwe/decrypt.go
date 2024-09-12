package jwe

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/utils"
)

func decryptCommand() cli.Command {
	return cli.Command{
		Name:   "decrypt",
		Action: cli.ActionFunc(decryptAction),
		Usage:  "verify a JWE and decrypt ciphertext",
		UsageText: `**step crypto jwe decrypt**
[**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>]`,
		Description: `**step crypto jwe decrypt** verifies a JWE read from STDIN and decrypts the
ciphertext printing it to STDOUT. If verification fails a non-zero failure
code is returned. If verification succeeds the command returns 0.

For examples, see **step help crypto jwe**.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "key",
				Usage: `The argument should be the name of a <file>
containing a private JWK (or a JWK encrypted as a JWE payload) or a PEM encoded
private key (or a private key encrypted using the modes described on RFC 1423 or
with PBES2+PBKDF2 described in RFC 2898).`,
			},
			cli.StringFlag{
				Name: "jwks",
				Usage: `The JWK Set containing the recipient's private key. The <jwks> argument should
be the name of a file. The file contents should be a JWK Set or a JWE with a
JWK Set payload. The **--jwks** flag requires the use of the **--kid** flag to
specify which key to use.`,
			},
			cli.StringFlag{
				Name: "kid",
				Usage: `The ID of the recipient's private key. <kid> is a case-sensitive string. When
used with **--key** the <kid> value must match the **"kid"** member of the JWK. When
used with **--jwks** (a JWK Set) the KID value must match the **"kid"** member of
one of the JWKs in the JWK Set.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to encrypt the keys.`,
			},
		},
	}
}

func decryptAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	data, err := utils.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	key := ctx.String("key")
	jwks := ctx.String("jwks")
	kid := ctx.String("kid")
	passwordFile := ctx.String("password-file")

	obj, err := jose.ParseEncrypted(string(data))
	if err != nil {
		return errors.Wrap(err, "error parsing data")
	}

	alg := jose.KeyAlgorithm(obj.Header.Algorithm)

	var isPBES2 bool
	switch alg {
	case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
		isPBES2 = true
	}

	switch {
	case isPBES2 && key != "":
		return errors.Errorf("flag '--key' cannot be used with JWE algorithm '%s'", alg)
	case isPBES2 && jwks != "":
		return errors.Errorf("flag '--jwks' cannot be used with JWE algorithm '%s'", alg)
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
	if kid != "" {
		options = append(options, jose.WithKid(kid))
	}

	// Read key from --key or --jwks
	var pbes2Key []byte
	var jwk *jose.JSONWebKey
	switch {
	case key != "":
		jwk, err = jose.ReadKey(key, options...)
	case jwks != "":
		jwk, err = jose.ReadKeySet(jwks, options...)
	case isPBES2:
		var password string
		if passwordFile != "" {
			password, err = utils.ReadStringPasswordFromFile(passwordFile)
			if err != nil {
				return err
			}
		}
		pbes2Key, err =
			ui.PromptPassword(
				"Please enter the password to decrypt the content encryption key",
				ui.WithValue(password))
	default:
		return errs.RequiredOrFlag(ctx, "key", "jwk")
	}
	if err != nil {
		return err
	}

	var decryptKey interface{}
	if isPBES2 {
		decryptKey = pbes2Key
	} else {
		// Private keys are used for decryption
		if jwk.IsPublic() {
			return errors.New("cannot use a public key for decryption")
		}

		if jwk.Use == "sig" {
			return errors.New("invalid jwk use: found 'sig' (signature), expecting 'enc' (encryption)")
		}

		// Validate jwk
		if err := jose.ValidateJWK(jwk); err != nil {
			return err
		}

		decryptKey = jwk.Key
	}

	decrypted, err := obj.Decrypt(decryptKey)
	if err != nil {
		return errors.Wrap(err, "error decrypting data")
	}

	fmt.Print(string(decrypted))

	return nil
}
