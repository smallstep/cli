package jwt

import (
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  "verify a signed JWT data structure and return the payload",
		UsageText: `**step crypto jwt verify**
		[**--aud**=<audience>] [**--iss**=<issuer>] [**--alg**=<algorithm>]
		[**--key**=<key>] [**--jwks**=<jwks>] [**--kid**=<kid>]`,
		Description: `**step crypto jwt verify** reads a JWT data structure from STDIN; checks that
the audience, issuer, and algorithm are in agreement with expectations;
verifies the digital signature or message authentication code as appropriate;
and outputs the decoded payload of the JWT on STDOUT. If verification fails a
non-zero failure code is returned. If verification succeeds the command
returns 0.

For a JWT to be verified successfully:

  * The JWT must be well formed (no errors during deserialization)
  * The <algorithm> must match the **"alg"** member in the JWT header
  * The <issuer> and <audience> must match the **"iss"** and **"aud"** claims in the JWT,
    respectively
  * The <kid> must match the **"kid"** member in the JWT header (if both are
    present) and must match the **"kid"** in the JWK or the **"kid"** of one of the
    JWKs in JWKS
  * The JWT signature must be successfully verified`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "iss, issuer",
				Usage: `The issuer of this JWT. The <issuer> must match the value of the **"iss"** claim in
the JWT. <issuer> is a case-sensitive string.`,
			},
			cli.StringFlag{
				Name: "aud, audience",
				Usage: `The identity of the principal running this command. The <audience> specified
must match one of the values in the **"aud"** claim, indicating the intended
recipient(s) of the JWT. <audience> is a case-sensitive string.`,
			},
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `The signature or MAC <algorithm> to use. Algorithms are case-sensitive strings
defined in RFC7518. If the key used do verify the JWT is not a JWK, or if it
is a JWK but does not have an **"alg"** member indicating its the intended
algorithm for use with the key, then the **--alg** flag is required to prevent
algorithm downgrade attacks. To disable this protection you can pass the
**--insecure** flag and omit the **--alg** flag.`,
			},
			cli.StringFlag{
				Name: "key",
				Usage: `The key to use to verify the JWS. The <key> argument should be the name of a
file. The contents of the file can be a public or private JWK (or a JWK
encrypted as a JWE payload) or a public or private PEM (or a private key
encrypted using [TODO: insert private key encryption mechanism]).`,
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
				Name:   "subtle",
				Hidden: true,
			},
			cli.BoolFlag{
				Name:   "no-exp-check",
				Hidden: true,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
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

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Errorf("error parsing token: %s", strings.TrimPrefix(err.Error(), "square/go-jose: "))
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
		if tok.Headers[0].KeyID == "" {
			return errs.RequiredWithFlag(ctx, "kid", "jwks")
		}
		kid = tok.Headers[0].KeyID
	}

	// Validate subtled
	isSubtle := ctx.Bool("subtle")
	iss := ctx.String("iss")
	aud := ctx.String("aud")
	if !isSubtle {
		switch {
		case len(iss) == 0:
			return errs.RequiredSubtleFlag(ctx, "iss")
		case len(aud) == 0:
			return errs.RequiredSubtleFlag(ctx, "aud")
		}
	}

	// Add parse options
	var options []jose.Option
	options = append(options, jose.WithUse("sig"))
	if len(alg) > 0 {
		options = append(options, jose.WithAlg(alg))
	}
	if len(kid) > 0 {
		options = append(options, jose.WithKid(kid))
	}
	if isSubtle {
		options = append(options, jose.WithSubtle(true))
	}
	if !ctx.Bool("insecure") {
		options = append(options, jose.WithNoDefaults(true))
	}

	// Read key from --key or --jwks
	var jwk *jose.JSONWebKey
	switch {
	case key != "":
		jwk, err = jose.ParseKey(key, options...)
	case jwks != "":
		jwk, err = jose.ParseKeySet(jwks, options...)
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

	// We don't support multiple signatures or any critical headers
	if len(tok.Headers) > 1 {
		return errors.New("validation failed: multiple signatures are not supported")
	}
	if _, ok := tok.Headers[0].ExtraHeaders["crit"]; ok {
		return errors.New("validation failed: unrecognized critical headers (crit)")
	}
	if !isSubtle && alg != "" && tok.Headers[0].Algorithm != "" && alg != tok.Headers[0].Algorithm {
		return errors.Errorf("alg %s does not match the alg on JWT (%s)", alg, tok.Headers[0].Algorithm)
	}

	claims := jose.Claims{}
	if err := tok.Claims(publicKey(jwk), &claims); err != nil {
		switch err {
		case jose.ErrCryptoFailure:
			return errors.New("validation failed: invalid signature")
		default:
			return errors.Wrap(err, "claim verify failed")
		}
	}

	expected := jose.Expected{Issuer: iss}
	if aud != "" {
		expected.Audience = jose.Audience{aud}
	}
	if !ctx.Bool("no-exp-check") {
		// TODO: The `go-jose` library makes it hard for us to differentiate
		// between a JWT that has no "exp" paramater and one that has an "exp"
		// paramater set to 0. We conflate the two cases here. This is
		// definitely not correct as an explicit 0 should be rejected.
		if claims.Expiry == 0 {
			if !ctx.Bool("subtle") {
				return errors.New(`jwt must have "exp" property unless '--subtle' is used`)
			}
		} else {
			expected.Time = time.Now()
		}
	} else {
		if !ctx.Bool("insecure") {
			return errs.RequiredInsecureFlag(ctx, "no-exp-check")
		}
	}

	if err := claims.ValidateWithLeeway(expected, 0); err != nil {
		switch err {
		case jose.ErrInvalidIssuer:
			return errors.New("validation failed: invalid issuer claim (iss)")
		case jose.ErrInvalidAudience:
			return errors.New("validation failed: invalid audience claim (aud)")
		case jose.ErrNotValidYet:
			return errors.New("validation failed: token not valid yet (nbf)")
		case jose.ErrExpired:
			return errors.Errorf("validation failed: token is expired by %s (exp)", expected.Time.Sub(claims.Expiry.Time()).Round(time.Millisecond))
		case jose.ErrInvalidSubject: // we're not currently checking the subject
			return errors.New("validation failed: invalid subject subject (sub)")
		case jose.ErrInvalidID: // we're not currently checking the id
			return errors.New("validation failed: invalid ID claim (jti)")
		default:
			return errors.Wrap(err, "validation failed")
		}
	}

	return printToken(token)
}
