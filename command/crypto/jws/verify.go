package jws

import (
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  "verify a signed JWS data structure and return the payload",
		UsageText: `**step crypto jws verify**
[**--alg**=<algorithm>] [**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>]`,
		Description: `**step crypto jws verify** reads a JWS data structure from STDIN; checks that
the algorithm are in agreement with expectations; verifies the digital
signature or message authentication code as appropriate; and outputs the
decoded payload of the JWS on STDOUT. If verification fails a non-zero failure
code is returned. If verification succeeds the command returns 0.

For a JWS to be verified successfully:

  * The JWS must be well formed (no errors during deserialization)
  * The <algorithm> must match the **"alg"** member in the JWS header
  * The <kid> must match the **"kid"** member in the JWS header (if both are
    present) and must match the **"kid"** in the JWK or the **"kid"** of one of the
    JWKs in JWKS
  * The JWS signature must be successfully verified

For examples, see **step help crypto jws**.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `The signature or MAC <algorithm> to use. Algorithms are case-sensitive strings
defined in RFC7518. If the key used do verify the JWS is not a JWK, or if it
is a JWK but does not have an **"alg"** member indicating its the intended
algorithm for use with the key, then the **--alg** flag is required to prevent
algorithm downgrade attacks. To disable this protection you can pass the
**--insecure** flag and omit the **--alg** flag.`,
			},
			cli.StringFlag{
				Name: "key",
				Usage: `The <file> containing the key with which to verify the JWS.
The contents of the file can be a public or private JWK (or a JWK
encrypted as a JWE payload) or a public or private PEM (or a private key
encrypted using the modes described on RFC 1423 or with PBES2+PBKDF2 described
in RFC 2898).`,
			},
			cli.StringFlag{
				Name: "jwks",
				Usage: `The JWK Set containing the key to use to verify the JWS. The <jwks> argument
should be the name of a file. The file contents should be a JWK Set or a JWE
with a JWK Set payload. The JWS being verified should have a "kid" member that
matches the "kid" of one of the JWKs in the JWK Set. If the JWS does not have
a "kid" member the '--kid' flag can be used.`,
			},
			cli.StringFlag{
				Name: "kid",
				Usage: `The ID of the key used to sign the JWK, used to select a JWK from a JWK Set.
The KID argument is a case-sensitive string. If the input JWS has a "kid"
member its value must match <kid> or verification will fail.`,
			},
			cli.BoolFlag{
				Name: "json",
				Usage: `Displays the header, payload and signature as a JSON object. The payload will
be encoded using Base64.`,
			},
			flags.SubtleHidden,
			flags.InsecureHidden,
		},
	}
}

// Get the public key for a JWK.
func publicKey(jwk *jose.JSONWebKey) interface{} {
	if jose.IsSymmetric(jwk) {
		return jwk.Key
	}
	return jwk.Public().Key
}

func verifyAction(ctx *cli.Context) error {
	token, err := utils.ReadString(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "error reading token")
	}

	tok, err := jose.ParseJWS(token)
	if err != nil {
		return errors.Errorf("error parsing token: %s", jose.TrimPrefix(err))
	}

	// We don't support multiple signatures
	if len(tok.Signatures) > 1 {
		return errors.New("validation failed: multiple signatures are not supported")
	}

	// Validate key, jwks and kid
	key := ctx.String("key")
	jwks := ctx.String("jwks")
	kid := ctx.String("kid")
	alg := ctx.String("alg")
	switch {
	case key == "" && jwks == "":
		return errs.RequiredOrFlag(ctx, "key", "jwks")
	case key != "" && jwks != "":
		return errs.MutuallyExclusiveFlags(ctx, "key", "jwks")
	case jwks != "" && kid == "":
		if tok.Signatures[0].Header.KeyID == "" {
			return errs.RequiredWithFlag(ctx, "kid", "jwks")
		}
		kid = tok.Signatures[0].Header.KeyID
	}

	// Add parse options
	var options []jose.Option
	options = append(options, jose.WithUse("sig"))
	if alg != "" {
		options = append(options, jose.WithAlg(alg))
	}
	if kid != "" {
		options = append(options, jose.WithKid(kid))
	}
	if !ctx.Bool("insecure") {
		options = append(options, jose.WithNoDefaults(true))
	}

	// Read key from --key or --jwks
	var jwk *jose.JSONWebKey
	switch {
	case key != "":
		jwk, err = jose.ReadKey(key, options...)
	case jwks != "":
		jwk, err = jose.ReadKeySet(jwks, options...)
	default:
		return errs.RequiredOrFlag(ctx, "key", "jwks")
	}
	if err != nil {
		return err
	}

	// At this moment jwk.Algorithm should have an alg from:
	//  * alg parameter
	//  * jwk or jwkset
	//  * guessed for ecdsa and ed25519 keys
	if jwk.Algorithm == "" {
		return errors.New("flag '--alg' is required with the given key")
	}
	if err := jose.ValidateJWK(jwk); err != nil {
		return err
	}

	// We don't support any critical headers
	if _, ok := tok.Signatures[0].Header.ExtraHeaders["crit"]; ok {
		return errors.New("validation failed: unrecognized critical headers (crit)")
	}
	if alg != "" && tok.Signatures[0].Header.Algorithm != "" && alg != tok.Signatures[0].Header.Algorithm {
		return errors.Errorf("alg %s does not match the alg on JWS (%s)", alg, tok.Signatures[0].Header.Algorithm)
	}

	payload, err := tok.Verify(publicKey(jwk))
	if err != nil {
		return errors.New("validation failed: invalid signature")
	}

	if ctx.Bool("json") {
		return printToken(tok)
	}

	os.Stdout.Write(payload)
	return nil
}
