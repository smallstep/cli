package jws

import (
	"fmt"
	"os"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signAction),
		Usage:  "create a signed JWS data structure",
		UsageText: `**step crypto jws sign** [- | <filename>]
[**--alg**=<algorithm>] [**--jku**=<jwk-url>] [**--jwk**] [**--typ**=<type>]
[**--cty**=<content-type>] [**--key**=<file>] [**--jwks**=<jwks>] [**--kid**=<kid>]
[**--password-file**=<file>] [**--x5c-cert**=<file>] [**--x5c-key**=<file>]
[**--x5t-cert**=<file>] [**--x5t-key**=<file>]`,
		// others: x5u, x5c, x5t, x5t#S256, and crit
		Description: `**step crypto jws sign** generates a signed JSON Web Signature (JWS) by
computing a digital signature or message authentication code for an arbitrary
payload. By default, the payload to sign is read from STDIN and the JWS will
be written to STDOUT.

For examples, see **step help crypto jws**.`,
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
				Name: "jku",
				Usage: `The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource
for a set of JSON-encoded public keys, one of which corresponds to the key
used to digitally sign the JWS. The keys MUST be encoded as a JWK Set (JWK).
The protocol used to acquire the resource MUST provide integrity protection;
an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security
(TLS); and the identity of the server MUST be validated. Use of <jwk-url> is
optional.`,
			},
			cli.BoolFlag{
				Name: "jwk",
				Usage: `The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds
to the key used to digitally sign the JWS. This key is represented as a JSON
Web Key (JWK). Use of <jwk> is optional.`,
			},
			cli.StringFlag{
				Name: "typ, type",
				Usage: `The "typ" (type) Header Parameter is used by JWS applications to declare the
media type of this complete JWS. This is intended for use by the application
when more than one kind of object could be present in an application data
structure that can contain a JWS; the application can use this value to
disambiguate among the different kinds of objects that might be present. It
will typically not be used by applications when the kind of object is already
known. This parameter is ignored by JWS implementations; any processing of
this parameter is performed by the JWS application. Use of <type> is
optional.

The "typ" value "JOSE" can be used by applications to indicate that this
object is a JWS or JWE using the JWS Compact Serialization or the JWE Compact
Serialization. The "typ" value "JOSE+JSON" can be used by applications to
indicate that this object is a JWS or JWE using the JWS JSON Serialization or
the JWE JSON Serialization. Other type values can also be used by
applications.`,
			},
			cli.StringFlag{
				Name: "cty",
				Usage: `The "cty" (content type) Header Parameter is used by JWS applications to
declare the media type of the secured content (the payload). This is intended
for use by the application when more than one kind of object could be present
in the JWS Payload; the application can use this value to disambiguate among
the different kinds of objects that might be present. It will typically not be
used by applications when the kind of object is already known. This parameter
is ignored by JWS implementations; any processing of this parameter is
performed by the JWS application. Use of <content-type> is optional.`,
			},
			cli.StringFlag{
				Name: "key, x5c-key, x5t-key",
				Usage: `The <file> containing the key with which to sign the JWS.
JWSs can be signed using a private JWK (or a JWK encrypted as a JWE payload) or
a PEM encoded private key (or a private key encrypted using the modes described
on RFC 1423 or with PBES2+PBKDF2 described in RFC 2898).`,
			},
			cli.StringFlag{
				Name: "jwks",
				Usage: `The JWK Set containing the key to use to sign the JWS. The <jwks> argument
should be the name of a file. The file contents should be a JWK Set or a JWE
with a JWK Set payload. The **--jwks** flag requires the use of the **--kid**
flag to specify which key to use.`,
			},
			cli.StringFlag{
				Name: "kid",
				Usage: `The ID of the key used to sign the JWS. The <kid> argument is a case-sensitive
string. When used with '--jwk' the <kid> value must match the **"kid"** member
of the JWK. When used with **--jwks** (a JWK Set) the <kid> value must match
the **"kid"** member of one of the JWKs in the JWK Set.`,
			},
			cli.BoolFlag{
				Name:   "no-kid",
				Hidden: true,
			},
			flags.PasswordFile,
			flags.X5cCert,
			flags.X5tCert,
			flags.SubtleHidden,
		},
	}
}

func signAction(ctx *cli.Context) error {
	var err error
	var payload []byte

	// Read payload if provided
	args := ctx.Args()
	switch len(args) {
	case 0: // read payload from stdin
		if payload, err = readPayload(""); err != nil {
			return err
		}
	case 1: // read payload from file or stdin (-)
		if payload, err = readPayload(args[0]); err != nil {
			return err
		}
	default:
		return errs.TooManyArguments(ctx)
	}

	isSubtle := ctx.Bool("subtle")
	alg := ctx.String("alg")

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

	// Read key from --key, --jwks, --x5c-key, or --x5t-key
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

	// Sign
	so := new(jose.SignerOptions)
	if ctx.IsSet("typ") {
		so.WithType(jose.ContentType(ctx.String("typ")))
	}
	if ctx.IsSet("cty") {
		so.WithContentType(jose.ContentType(ctx.String("cty")))
	}
	if !ctx.Bool("no-kid") && jwk.KeyID != "" {
		so.WithHeader("kid", jwk.KeyID)
	}
	if ctx.IsSet("jku") {
		so.WithHeader("jku", ctx.String("jku"))
	}
	if ctx.Bool("jwk") {
		so.WithHeader("jwk", jwk.Public())
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
		so.WithHeader("x5c", certStrs)
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
		return errors.Wrap(err, "error creating JWS signer")
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		return errors.Errorf("error signing payload: %s", jose.TrimPrefix(err))
	}

	raw, err := signed.CompactSerialize()
	if err != nil {
		return errors.Wrapf(err, "error serializing JWS")
	}

	fmt.Println(raw)
	return nil
}

func readPayload(filename string) ([]byte, error) {
	switch filename {
	case "":
		st, err := os.Stdin.Stat()
		if err != nil {
			return nil, errors.Wrap(err, "error reading data")
		}
		if st.Size() == 0 && st.Mode()&os.ModeNamedPipe == 0 {
			return []byte{}, nil
		}
		return utils.ReadAll(os.Stdin)
	case "-":
		return utils.ReadAll(os.Stdin)
	default:
		b, err := os.ReadFile(filename)
		if err != nil {
			return nil, errs.FileError(err, filename)
		}
		return b, nil
	}
}
