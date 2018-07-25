package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/crypto/certificates/x509"
	"github.com/smallstep/cli/crypto/keys"
	spem "github.com/smallstep/cli/crypto/pem"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/reader"
	"github.com/urfave/cli"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: cli.ActionFunc(createAction),
		Usage:  "create a certificate or certificate signing request",
		UsageText: `**step certificate create** <subject> <crt_file> <key_file>
		[**ca**=<issuer-cert>] [**ca-key**=<issuer-key>] [**--csr**]
		[**--curve**=<curve] [**no-password**] [**--profile**=<profile>]
		[**--size**=<size>] [**--type**=<type>]`,
		Description: `**step certificate create** generates a certificate or a
certificate signing requests (CSR) that can be signed later using 'step
certificates sign' (or some other tool) to produce a certificate.

This command creates x.509 certificates for use with TLS.

## POSITIONAL ARGUMENTS

<subject>
: The subject of the certificate. Typically this is a hostname for services or an email address for people.

<crt_file>
: File to write CRT or CSR to (PEM format)

<key_file>
: File to write private key to (PEM format)

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Create a CSR and key:

'''
$ step certificate create foo foo.csr foo.key --csr
'''

Create a CSR and key - do not encrypt the key when writing to disk:

'''
$ step certificate create foo foo.csr foo.key --csr --no-password --insecure
'''

Create a leaf certificate and key:

'''
$ step certificate create foo foo.crt foo.key intermediate-ca \
--ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
'''

Create a root certificate and key:

'''
$ step certificate create foo foo.crt foo.key --profile root-ca
'''

Create an intermediate certificate and key:

'''
$ step certificate create foo foo.crt foo.key --profile intermediate-ca \
--ca ./root-ca.crt --ca-key ./root-ca.key
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate authority used to issue the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name:  "ca-key",
				Usage: `The certificate authority private key used to sign the new certificate (PEM file).`,
			},
			cli.BoolFlag{
				Name:  "csr",
				Usage: `Generate a certificate signing request (CSR) instead of a certificate.`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
			cli.StringFlag{
				Name:  "profile",
				Value: "leaf",
				Usage: `The certificate profile sets various certificate details such as
  certificate use and expiration. The default profile is 'leaf' which is suitable
  for a client or server using TLS.

: <profile> is a case-sensitive string and must be one of:

    **leaf**
	:  Generate a leaf x.509 certificate suitable for use with TLs.

    **intermediate-ca**
    :  Generate a certificate that can be used to sign additional leaf or intermediate certificates.

    **root-ca**
    :  Generate a new self-signed root certificate suitable for use as a root CA.`,
			},
			cli.StringFlag{
				Name:  "kty",
				Value: "EC",
				Usage: `The <kty> to build the certificate upon.
If unset, default is EC.

: <kty> is a case-sensitive string and must be one of:

    **EC**
    :  Create an **elliptic curve** keypair

    **OKP**
    :  Create an octet key pair (for **"Ed25519"** curve)

    **RSA**
    :  Create an **RSA** keypair
`,
			},
			cli.IntFlag{
				Name: "size",
				Usage: `The <size> (in bits) of the key for RSA and oct key types. RSA keys require a
minimum key size of 2048 bits. If unset, default is 2048 bits for RSA keys and 128 bits for oct keys.`,
			},
			cli.StringFlag{
				Name: "crv, curve",
				Usage: `The elliptic <curve> to use for EC and OKP key types. Corresponds
to the **"crv"** JWK parameter. Valid curves are defined in JWA [RFC7518]. If
unset, default is P-256 for EC keys and Ed25519 for OKP keys.

: <curve> is a case-sensitive string and must be one of:

    **P-256**
    :  NIST P-256 Curve

    **P-384**
    :  NIST P-384 Curve

    **P-521**
    :  NIST P-521 Curve

    **Ed25519**
    :  Ed25519 Curve
`,
			},
		},
	}
}

func createAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
	}

	var (
		crv  = ctx.String("curve")
		size = ctx.Int("size")
		kty  = ctx.String("kty")
	)

	if ctx.IsSet("kty") {
		switch kty {
		case "RSA":
			if size < 2048 && !insecure {
				return errs.MinSizeInsecureFlag(ctx, "size", "2048")
			}
			if size <= 0 {
				return errs.MinSizeFlag(ctx, "size", "0")
			}
			if ctx.IsSet("curve") {
				return errs.IncompatibleFlagValue(ctx, "curve", "kty", kty)
			}
		case "EC":
			if ctx.IsSet("size") {
				return errs.IncompatibleFlagValue(ctx, "size", "kty", kty)
			}
			if !ctx.IsSet("curve") {
				return errs.RequiredWithFlagValue(ctx, "kty", kty, "curve")
			}
			switch crv {
			case "P-256", "P-384", "P-521": //ok
			default:
				return errs.InvalidFlagValue(ctx, "curve", crv, "P-256, P-384, P-251")
			}
		case "OKP":
			if ctx.IsSet("size") {
				return errs.IncompatibleFlagValue(ctx, "size", "kty", kty)
			}
			if !ctx.IsSet("curve") {
				return errs.RequiredWithFlagValue(ctx, "kty", kty, "curve")
			}
			switch crv {
			case "Ed25519": //ok
			default:
				return errs.IncompatibleFlagValues(ctx, "curve", crv, "kty", kty)
			}
		default:
			return errs.InvalidFlagValue(ctx, "--kty", kty, "RSA, EC, OKP")
		}
	} else {
		if ctx.IsSet("curve") {
			errs.RequiredWithFlag(ctx, "curve", "kty")
		}
		if ctx.IsSet("size") {
			errs.RequiredWithFlag(ctx, "size", "kty")
		}
		// Set default key type | curve | size.
		kty = "EC"
		crv = "P-256"
		size = 0
	}

	subject := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	if crtFile == keyFile {
		return errs.EqualArguments(ctx, "CRT_FILE", "KEY_FILE")
	}

	prof := ctx.String("profile")
	caPath := ctx.String("ca")
	caKeyPath := ctx.String("ca-key")
	if prof != "root-ca" {
		if caPath == "" {
			return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca")
		}
		if caKeyPath == "" {
			return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca-key")
		}
	}
	var typ string
	if ctx.Bool("csr") {
		typ = "x509-csr"
	} else {
		typ = "x509"
	}

	var (
		err    error
		priv   interface{}
		pubPEM *pem.Block
	)
	switch typ {
	case "x509-csr":
		priv, err = keys.GenerateDefaultKey()
		if err != nil {
			return errors.WithStack(err)
		}

		_csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: subject,
			},
		}
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, _csr, priv)
		if err != nil {
			return errors.WithStack(err)
		}

		pubPEM = &pem.Block{
			Type:    "CSR",
			Bytes:   csrBytes,
			Headers: map[string]string{},
		}
	case "x509":
		var (
			err     error
			profile stepx509.Profile
		)
		switch prof {
		case "leaf":
			issIdentity, err := loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
			if err != nil {
				return errors.WithStack(err)
			}
			profile, err = stepx509.NewLeafProfile(subject, issIdentity.Crt,
				issIdentity.Key, stepx509.GenerateKeyPair(kty, crv, size))
			if err != nil {
				return errors.WithStack(err)
			}
		case "intermediate-ca":
			issIdentity, err := loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
			if err != nil {
				return errors.WithStack(err)
			}
			if err != nil {
				return errors.WithStack(err)
			}
			profile, err = stepx509.NewIntermediateProfile(subject,
				issIdentity.Crt, issIdentity.Key,
				stepx509.GenerateKeyPair(kty, crv, size))
			if err != nil {
				return errors.WithStack(err)
			}
		case "root-ca":
			profile, err = stepx509.NewRootProfile(subject,
				stepx509.GenerateKeyPair(kty, crv, size))
			if err != nil {
				return errors.WithStack(err)
			}
		default:
			return errs.InvalidFlagValue(ctx, "profile", prof, "leaf, intermediate-ca, root-ca")
		}
		crtBytes, err := profile.CreateCertificate()
		if err != nil {
			return errors.WithStack(err)
		}
		pubPEM = &pem.Block{
			Type:    "CERTIFICATE",
			Bytes:   crtBytes,
			Headers: map[string]string{},
		}
		priv = profile.SubjectPrivateKey()
	default:
		return errs.NewError("unexpected type: %s", typ)
	}

	if err := utils.WriteFile(crtFile, pem.EncodeToMemory(pubPEM),
		os.FileMode(0600)); err != nil {
		return errs.FileError(err, crtFile)
	}

	if noPass {
		_, err = spem.Serialize(priv, spem.ToFile(keyFile, 0600))
	} else {
		var pass string
		if err := reader.ReadPasswordSubtle(
			fmt.Sprintf("Password with which to encrypt private key file `%s`: ", keyFile),
			&pass, "Password", reader.RetryOnEmpty); err != nil {
			return errors.WithStack(err)
		}
		_, err = spem.Serialize(priv, spem.WithEncryption(pass),
			spem.ToFile(keyFile, 0600))
	}
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func loadIssuerIdentity(ctx *cli.Context, profile, caPath, caKeyPath string) (*stepx509.Identity, error) {
	if caPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca")
	}
	if caKeyPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca-key")
	}
	return stepx509.LoadIdentityFromDisk(caPath, caKeyPath)
}
