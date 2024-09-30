package jwt

import (
	"fmt"
	"os"
	"strings"
	"time"

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
		Usage:  "verify a signed JWT data structure and return the payload",
		UsageText: `**step crypto jwt verify**
[**--aud**=<audience>] [**--iss**=<issuer>] [**--alg**=<algorithm>]
[**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>]`,
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
  * The JWT signature must be successfully verified
  * The JWT must not be expired

For examples, see **step help crypto jwt**.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "iss, issuer",
				Usage: `The issuer of this JWT. The <issuer> must match the value of the **"iss"** claim in
the JWT. <issuer> is a case-sensitive string. Required unless disabled with the **--subtle** flag.`,
			},
			cli.StringFlag{
				Name: "aud, audience",
				Usage: `The identity of the principal running this command. The <audience> specified
must match one of the values in the **"aud"** claim, indicating the intended
recipient(s) of the JWT. <audience> is a case-sensitive string. Required unless disabled with the
**--subtle** flag.`,
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
				Usage: `The <file> containing the key to use to verify the JWT.
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
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to decrypt the key.`,
			},
			cli.BoolFlag{
				Name:   "no-exp-check",
				Hidden: true,
			},
			flags.SubtleHidden,
			flags.InsecureHidden,
		},
	}
}

type timeClaims struct {
	Expiry    *int64 `json:"exp,omitempty"`
	NotBefore *int64 `json:"nbf,omitempty"`
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
		return errors.Errorf("error parsing token: %s", jose.TrimPrefix(err))
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

	// Validate subtle
	isSubtle := ctx.Bool("subtle")
	iss := ctx.String("iss")
	aud := ctx.String("aud")
	if !isSubtle {
		switch {
		case iss == "":
			return errs.RequiredUnlessSubtleFlag(ctx, "iss")
		case aud == "":
			return errs.RequiredUnlessSubtleFlag(ctx, "aud")
		}
	}

	// Validate no-exp-check with insecure
	if ctx.Bool("no-exp-check") && !ctx.Bool("insecure") {
		return errs.RequiredInsecureFlag(ctx, "no-exp-check")
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
	if isSubtle {
		options = append(options, jose.WithSubtle(true))
	}
	if !ctx.Bool("insecure") {
		options = append(options, jose.WithNoDefaults(true))
	}
	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		options = append(options, jose.WithPasswordFile(passwordFile))
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
		if errors.Is(err, jose.ErrCryptoFailure) {
			return errors.New("validation failed: invalid signature")
		}
		return errors.Wrap(err, "claim verify failed")
	}

	// Check exp and nbf presence
	// There's no need to do the verification again.
	var tClaims timeClaims
	if err := tok.UnsafeClaimsWithoutVerification(&tClaims); err != nil {
		if errors.Is(err, jose.ErrCryptoFailure) {
			return errors.New("validation failed: invalid signature")
		}
		return errors.Wrap(err, "claim verify failed")
	}

	expected := jose.Expected{Issuer: iss}
	if aud != "" {
		expected.Audience = jose.Audience{aud}
	}
	if tClaims.Expiry != nil || tClaims.NotBefore != nil {
		expected.Time = time.Now()
	}

	if err := validateClaimsWithLeeway(ctx, claims, expected, tClaims, 0); err != nil {
		return err
	}

	return printToken(token)
}

// validateClaimsWithLeeway is a custom implementation of go-jose
// jwt.Claims.ValidateWithLeeway that returns all the errors found.
func validateClaimsWithLeeway(ctx *cli.Context, c jose.Claims, e jose.Expected, t timeClaims, leeway time.Duration) error {
	var ers []string

	if e.Issuer != "" && e.Issuer != c.Issuer {
		ers = append(ers, "invalid issuer claim (iss)")
	}

	// we're not currently checking the subject
	if e.Subject != "" && e.Subject != c.Subject {
		ers = append(ers, "invalid subject (sub)")
	}

	// we're not currently checking the id
	if e.ID != "" && e.ID != c.ID {
		ers = append(ers, "invalid ID claim (jti)")
	}

	for _, v := range e.Audience {
		if !c.Audience.Contains(v) {
			ers = append(ers, "invalid audience claim (aud)")
			break
		}
	}

	// Only if nbf is defined, just in case is tested in time <0 :)
	if t.NotBefore != nil {
		if !e.Time.IsZero() && e.Time.Add(leeway).Before(c.NotBefore.Time()) {
			ers = append(ers, "token not valid yet (nbf)")
		}
	}

	// Only if exp is defined and no-exp-check is not used
	if t.Expiry != nil && !ctx.Bool("no-exp-check") {
		if !e.Time.IsZero() && e.Time.Add(-leeway).After(c.Expiry.Time()) {
			ers = append(ers, fmt.Sprintf("token is expired by %s (exp)", e.Time.Sub(c.Expiry.Time()).Round(time.Millisecond)))
		}
	}

	if len(ers) > 0 {
		return errors.Errorf("validation failed: %s", strings.Join(ers, ", "))
	}

	return nil
}
