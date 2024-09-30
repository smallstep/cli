package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/cli/flags"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signAction),
		Usage:  "create a signed JWT data structure",
		UsageText: `**step crypto jwt sign** [- | <filename>]
[**--alg**=<algorithm>] [**--aud**=<audience>] [**--iss**=<issuer>] [**--sub**=<sub>]
[**--exp**=<expiration>] [**--iat**=<issued_at>] [**--nbf**=<not-before>]
[**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>] [**--jti**=<jti>]
[**--header=<key=value>**] [**--password-file**=<file>]
[**--x5c-cert**=<file>] [**--x5c-key**=<file>] [**--x5c-insecure**]
[**--x5t-cert**=<file>] [**--x5t-key**=<file>]`,
		Description: `**step crypto jwt sign** command generates a signed JSON Web Token (JWT) by
computing a digital signature or message authentication code for a JSON
payload. By default, the payload to sign is read from STDIN and the JWT will
be written to STDOUT. The suggested pronunciation of JWT is the same as the
English word "jot".

A JWT is a compact data structure used to represent some JSON encoded "claims"
that are passed as the payload of a JWS or JWE structure, enabling the claims
to be digitally signed and/or encrypted. The "claims" (or "claim set") are
represented as an ordinary JSON object. JWTs are represented using a compact
format that's URL safe and can be used in space-constrained environments. JWTs
can be passed in HTTP Authorization headers and as URI query parameters.

A "claim" is a piece of information asserted about a subject, represented as a
key/value pair. Logically a verified JWT should be interpreted as "<issuer> says
to <audience> that <subject>'s <claim-name> is <claim-value>" for each claim.

Some optional arguments introduce subtle security considerations if omitted.
These considerations should be carefully analyzed. Therefore, omitting <subtle>
arguments requires the use of the **--subtle** flag as a misuse prevention
mechanism.

A JWT signed using JWS has three parts:

    1. A base64 encoded JSON object representing the JOSE (JSON Object Signing
       and Encryption) header that describes the cryptographic operations
       applied to the JWT Claims Set
    2. A base64 encoded JSON object representing the JWT Claims Set
    3. A base64 encoded digital signature of message authentication code

For examples, see **step help crypto jwt**.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `The signature or MAC algorithm to use. Algorithms are case-sensitive strings
defined in RFC7518. The selected algorithm must be compatible with the key
type. This flag is optional. If not specified, the "alg" member of the JWK is
used. If the JWK has no "alg" member then a default is selected depending on
the JWK key type. If the JWK has an "alg" member and the "alg" flag is passed
the two options must match unless the '--subtle' flag is also passed.

: <algorithm> is a case-sensitive string and must be one of:

    **HS256**
    :  HMAC using SHA-256 (default for "oct" key type)

    **HS384**
    :  HMAC using SHA-384

    **HS512**
    :  HMAC using SHA-512

    **RS256**
    :  RSASSA-PKCS1-v1_5 using SHA-256 (default for "RSA" key type)

    **RS384**
    :  RSASSA-PKCS1-v1_5 using SHA-384

    **RS512**
    :  RSASSA-PKCS1-v1_5 using SHA-512

    **ES256**
    :  ECDSA using P-256 and SHA-256 (default for "EC" key type)

    **ES384**
    :  ECDSA using P-384 and SHA-384

    **ES512**
    :  ECDSA using P-521 and SHA-512

    **PS256**
    :  RSASSA-PSS using SHA-256 and MGF1 with SHA-256

    **PS384**
    :  RSASSA-PSS using SHA-384 and MGF1 with SHA-384

    **PS512**
    :  RSASSA-PSS using SHA-512 and MGF1 with SHA-512

    **EdDSA**
    :  EdDSA signature algorithm`,
			},
			cli.StringFlag{
				Name: "iss, issuer",
				Usage: `The issuer of this JWT. The processing of this claim is generally
application specific. Typically, the issuer must match the name of some
trusted entity (e.g., an identity provider like "https://accounts.google.com")
and identify which key(s) to use for JWT verification and/or decryption (e.g.,
the keys at "https://www.googleapis.com/oauth2/v3/certs").

: <issuer> is a case-sensitive string.`,
			},
			cli.StringSliceFlag{
				Name: "aud, audience",
				Usage: `The intended recipient(s) of the JWT, encoded as the **"aud"** claim in the
JWT. Recipient(s) must identify themselves with one or more of the values in
the **"aud"** claim. The **"aud"** claim can be a string (indicating a single
recipient) or an array (indicating multiple potential recipients). This flag
can be used multiple times to generate a JWK with multiple intended
recipients.

: Each <audience> is a case-sensitive string.`,
			},
			cli.StringFlag{
				Name: "sub, subject",
				Usage: `The subject of this JWT. The "claims" are normally interpreted as statements
about this subject. The subject must either be locally unique in the context
of the issuer or globally unique. The processing of this claim is generally
application specific.

: <subject> is a case-sensitive string.`,
			},
			cli.Int64Flag{
				Name: "exp, expiration",
				Usage: `The expiration time on or after which the JWT must not be accepted.
<expiration> must be a numeric value representing a Unix timestamp.`,
			},
			cli.Int64Flag{
				Name: "nbf, not-before",
				Usage: `The time before which the JWT must not be accepted. <not-before> must be a
numeric value representing a Unix timestamp. If not provided, the current time
is used.`,
			},
			cli.Int64Flag{
				Name: "iat, issued-at",
				Usage: `The time at which the JWT was issued, used to determine the age of the JWT.
ISSUED_AT must be a numeric value representing a Unix timestamp. If not
provided, the current time is used.`,
			},
			cli.StringFlag{
				Name: "jti, jwt-id",
				Usage: `A unique identifier for the JWT. The identifier must be assigned in a manner
that ensures that there is a negligible probability that the same value will
be accidentally assigned to multiple JWTs. The JTI claim can be used to
prevent a JWT from being replayed (i.e., recipient(s) can use <jti> to make a
JWT one-time-use). The <jti> argument is a case-sensitive string. If the
**--jti** flag is used without an argument a <jti> will be generated randomly
with sufficient entropy to satisfy the collision-resistance criteria.`,
			},
			cli.StringSliceFlag{
				Name: "header",
				Usage: `The <key=value> used as a header in the JWT token. Use the flag multiple
times to set multiple headers.`,
			},
			cli.StringFlag{
				Name: "key, x5c-key, x5t-key",
				Usage: `The <file> containing the key with which to sign the JWT.
JWTs can be signed using a private JWK (or a JWK encrypted as a JWE payload) or
a PEM encoded private key (or a private key encrypted using the modes described
on RFC 1423 or with PBES2+PBKDF2 described in RFC 2898).`,
			},
			cli.StringFlag{
				Name: "jwks",
				Usage: `The JWK Set containing the key to use to sign the JWT. The <jwks> argument
should be the name of a file. The file contents should be a JWK Set or a JWE
with a JWK Set payload. The **--jwks** flag requires the use of the **--kid**
flag to specify which key to use.`,
			},
			cli.StringFlag{
				Name: "kid",
				Usage: `The ID of the key used to sign the JWT. The <kid> argument is a case-sensitive
string. When used with '--jwk' the <kid> value must match the **"kid"** member
of the JWK. When used with **--jwks** (a JWK Set) the <kid> value must match
the **"kid"** member of one of the JWKs in the JWK Set.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to decrypt the key.`,
			},
			cli.BoolFlag{
				Name:   "no-kid",
				Hidden: true,
			},
			flags.X5cCert,
			flags.X5tCert,
			flags.X5cInsecure,
			flags.SubtleHidden,
		},
	}
}

func signAction(ctx *cli.Context) error {
	var err error
	var payload interface{}

	// Read payload if provided
	args := ctx.Args()
	switch len(args) {
	case 0:
		// read payload from stdin if there is data
		if payload, err = readPayload(""); err != nil {
			return err
		}
	case 1:
		// read payload from file or stdin (-)
		if payload, err = readPayload(args[0]); err != nil {
			return err
		}
	default:
		return errs.TooManyArguments(ctx)
	}

	x5cCertFile, x5cKeyFile := ctx.String("x5c-cert"), ctx.String("x5c-key")
	x5tCertFile, x5tKeyFile := ctx.String("x5t-cert"), ctx.String("x5t-key")

	key := ctx.String("key")
	jwks := ctx.String("jwks")
	kid := ctx.String("kid")
	var isX5C bool
	if x5cCertFile != "" {
		if x5cKeyFile == "" {
			return errs.RequiredWithOrFlag(ctx, "x5c-cert", "key", "x5c-key")
		}
		if x5tCertFile != "" {
			return errs.MutuallyExclusiveFlags(ctx, "x5c-cert", "x5t-cert")
		}
		if ctx.IsSet("jwk") {
			return errs.MutuallyExclusiveFlags(ctx, "x5c-cert", "jwk")
		}
		if jwks != "" {
			return errs.MutuallyExclusiveFlags(ctx, "x5c-cert", "jwks")
		}
		isX5C = true
	}

	var isX5T bool
	if x5tCertFile != "" {
		if x5tKeyFile == "" {
			return errs.RequiredWithOrFlag(ctx, "x5t-cert", "key", "x5t-key")
		}
		if x5cCertFile != "" {
			return errs.MutuallyExclusiveFlags(ctx, "x5t-cert", "x5c-cert")
		}
		if ctx.IsSet("jwk") {
			return errs.MutuallyExclusiveFlags(ctx, "x5t-cert", "jwk")
		}
		if jwks != "" {
			return errs.MutuallyExclusiveFlags(ctx, "x5t-cert", "jwks")
		}
		isX5T = true
	}

	if !isX5C && !isX5T {
		// Validate key, jwks and kid
		switch {
		case key == "" && jwks == "":
			return errs.RequiredOrFlag(ctx, "key", "jwks")
		case key != "" && jwks != "":
			return errs.MutuallyExclusiveFlags(ctx, "key", "jwks")
		case jwks != "" && kid == "":
			return errs.RequiredWithFlag(ctx, "kid", "jwks")
		}
	}

	alg := ctx.String("alg")
	isSubtle := ctx.Bool("subtle")
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
	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		options = append(options, jose.WithPasswordFile(passwordFile))
	}

	// Read key from --key or --jwks or --x5c-key or --x5t-key
	var jwk *jose.JSONWebKey
	switch {
	case isX5T:
		jwk, err = jose.ReadKey(x5tKeyFile, options...)
	case isX5C:
		jwk, err = jose.ReadKey(x5cKeyFile, options...)
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

	// Public keys cannot be used for signing
	if jwk.IsPublic() {
		return errors.New("cannot use a public key for signing")
	}

	// Key "use" must be "sig" to use for signing
	if jwk.Use != "sig" && jwk.Use != "" {
		return errors.Errorf("invalid jwk use: found '%s', expecting 'sig' (signature)", jwk.Use)
	}

	// At this moment jwk.Algorithm should have an alg from:
	//  * alg parameter
	//  * jwk or jwkset
	//  * guessed for ecdsa and Ed25519 keys
	if jwk.Algorithm == "" {
		return errors.New("flag '--alg' is required with the given key")
	}
	if err := jose.ValidateJWK(jwk); err != nil {
		return err
	}

	// Validate exp
	if !isSubtle && ctx.IsSet("exp") && jose.UnixNumericDate(ctx.Int64("exp")).Time().Before(time.Now()) {
		return errors.New("flag '--exp' must be in the future unless the '--subtle' flag is provided")
	}

	jti := ctx.String("jti")
	if !ctx.IsSet("jti") {
		if jti, err = randutil.Hex(64); err != nil { // 256 bits
			return errors.Wrap(err, "error generating random JWT ID")
		}
	}

	// Add claims
	c := &jose.Claims{
		Issuer:    ctx.String("iss"),
		Subject:   ctx.String("sub"),
		Audience:  ctx.StringSlice("aud"),
		Expiry:    jose.UnixNumericDate(ctx.Int64("exp")),
		NotBefore: jose.UnixNumericDate(ctx.Int64("nbf")),
		IssuedAt:  jose.UnixNumericDate(ctx.Int64("iat")),
		ID:        jti,
	}

	now := time.Now()
	if c.NotBefore == nil {
		c.NotBefore = jose.NewNumericDate(now)
	}
	if c.IssuedAt == nil {
		c.IssuedAt = jose.NewNumericDate(now)
	}
	if c.ID == "" && ctx.IsSet("jti") {
		if c.ID, err = randutil.Hex(40); err != nil {
			return errors.Wrap(err, "error creating random jti")
		}
	}

	// Validate recommended claims
	if !isSubtle {
		switch {
		case c.Issuer == "":
			return errors.New("flag '--iss' is required unless '--subtle' is used")
		case len(c.Audience) == 0:
			return errors.New("flag '--aud' is required unless '--subtle' is used")
		case c.Subject == "":
			return errors.New("flag '--sub' is required unless '--subtle' is used")
		case c.Expiry == nil:
			return errors.New("flag '--exp' is required unless '--subtle' is used")
		case c.Expiry.Time().Before(time.Now()):
			return errors.New("flag '--exp' must be in the future unless '--subtle' is used")
		}
	}

	// Sign
	so := new(jose.SignerOptions)
	so.WithType("JWT")
	if !ctx.Bool("no-kid") && jwk.KeyID != "" {
		so.WithHeader("kid", jwk.KeyID)
	}

	// Add extra headers. Currently only string headers are supported.
	for _, s := range ctx.StringSlice("header") {
		i := strings.Index(s, "=")
		if i == -1 {
			return errs.InvalidFlagValue(ctx, "header", s, "")
		}
		so.WithHeader(jose.HeaderKey(s[:i]), s[i+1:])
	}

	if isX5C {
		certs, err := pemutil.ReadCertificateBundle(x5cCertFile)
		if err != nil {
			return err
		}
		certStrs, err := jose.ValidateX5C(certs, jwk.Key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}
		if ctx.Bool("x5c-insecure") {
			so.WithHeader("x5cInsecure", certStrs)
		} else {
			so.WithHeader("x5c", certStrs)
		}
	}

	if isX5T {
		certs, err := pemutil.ReadCertificateBundle(x5tCertFile)
		if err != nil {
			return err
		}
		fingerprint, err := jose.ValidateX5T(certs, jwk.Key)
		if err != nil {
			return errors.Wrap(err, "error validating x5t certificate and key for use in x5t header")
		}
		so.WithHeader("x5t", fingerprint)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk.Key,
	}, so)
	if err != nil {
		return errors.Wrapf(err, "error creating JWT signer")
	}

	// Some implementations only accept "aud" as a string.
	// Using claim overwriting for this special case.
	aud := make(map[string]interface{})
	if len(c.Audience) == 1 {
		aud["aud"] = c.Audience[0]
	}

	raw, err := jose.Signed(signer).Claims(c).Claims(aud).Claims(payload).CompactSerialize()
	if err != nil {
		return errors.Wrapf(err, "error serializing JWT")
	}

	fmt.Println(raw)
	return nil
}

func readPayload(filename string) (interface{}, error) {
	var r io.Reader
	switch filename {
	case "":
		st, err := os.Stdin.Stat()
		if err != nil {
			return nil, errors.Wrap(err, "error reading data")
		}
		if st.Size() == 0 && st.Mode()&os.ModeNamedPipe == 0 {
			return make(map[string]interface{}), nil
		}
		r = os.Stdin
	case "-":
		r = os.Stdin
	default:
		b, err := os.ReadFile(filename)
		if err != nil {
			return nil, errs.FileError(err, filename)
		}
		r = bytes.NewReader(b)
	}

	v := make(map[string]interface{})
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		// Some CI platforms will feed an empty pipe as STDIN.
		// In that case we should treat it as a valid empty JSON.
		if filename == "" && errors.Is(err, io.EOF) {
			return v, nil
		}
		if filename == "" || filename == "-" {
			return nil, errors.Wrap(err, "error decoding JSON from STDIN")
		}
		return nil, errors.Wrapf(err, "error decoding JSON from %s", filename)
	}
	return v, nil
}
