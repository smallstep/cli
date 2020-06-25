package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: command.ActionFunc(createAction),
		Usage:  "create a certificate or certificate signing request",
		UsageText: `**step certificate create** <subject> <crt_file> <key_file>
[**ca**=<issuer-cert>] [**ca-key**=<issuer-key>] [**--csr**]
[**no-password**] [**--profile**=<profile>] [**--san**=<SAN>] [**--bundle**]
[**--kty**=<type>] [**--curve**=<curve>] [**--size**=<size>]`,
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

Create a CSR and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.csr foo.key --csr \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a CSR and key - do not encrypt the key when writing to disk:

'''
$ step certificate create foo foo.csr foo.key --csr --no-password --insecure
'''

Create a root certificate and key:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca
'''

Create an intermediate certificate and key:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key
'''

Create an intermediate certificate and key with custom Subject Alternative Names:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a leaf certificate and key:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
'''

Create a leaf certificate and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a leaf certificate and key with custom validity:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --not-before 24h --not-after 2160h
'''

Create a self-signed leaf certificate and key:

'''
$ step certificate create self-signed-leaf.local leaf.crt leaf.key --profile self-signed --subtle
'''

Create a root certificate and key with underlying OKP Ed25519:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca \
  --kty OKP --curve Ed25519
'''

Create an intermeidate certificate and key with underlying EC P-256 key pair:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key --kty EC --curve P-256
'''

Create a leaf certificate and key with underlying RSA 2048 key pair:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key --kty RSA --size 2048
'''

Create a CSR and key with underlying OKP Ed25519:

'''
$ step certificate create foo foo.csr foo.key --csr --kty OKP --curve Ed25519
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
	:  Generate a leaf x.509 certificate suitable for use with TLS.

    **intermediate-ca**
    :  Generate a certificate that can be used to sign additional leaf certificates.

    **root-ca**
    :  Generate a new self-signed root certificate suitable for use as a root CA.

    **self-signed**
    :  Generate a new self-signed leaf certificate suitable for use with TLS.
	This profile requires the **--subtle** flag because the use of self-signed leaf
	certificates is discouraged unless absolutely necessary.`,
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the NotAfter property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS or IP Address Subjective Alternative Names (SANs). Use the '--san'
flag multiple times to configure multiple SANs.`,
			},
			cli.BoolFlag{
				Name: "bundle",
				Usage: `Bundle the new leaf certificate with the signing certificate. This flag requires
the **--ca** flag.`,
			},
			flags.KTY,
			flags.Size,
			flags.Curve,
			flags.Force,
			flags.Subtle,
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

	subject := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	if crtFile == keyFile {
		return errs.EqualArguments(ctx, "CRT_FILE", "KEY_FILE")
	}

	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	if !notAfter.IsZero() && !notBefore.IsZero() && notBefore.After(notAfter) {
		return errs.IncompatibleFlagValues(ctx, "not-before", ctx.String("not-before"), "not-after", ctx.String("not-after"))
	}

	var typ string
	if ctx.Bool("csr") {
		typ = "x509-csr"
	} else {
		typ = "x509"
	}

	kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, insecure, "kty", "curve", "size")
	if err != nil {
		return err
	}

	sans := ctx.StringSlice("san")

	var (
		priv       interface{}
		pubPEMs    []*pem.Block
		outputType string
		bundle     = ctx.Bool("bundle")
	)
	switch typ {
	case "x509-csr":
		if bundle {
			return errs.IncompatibleFlagWithFlag(ctx, "bundle", "csr")
		}
		if ctx.IsSet("profile") {
			return errs.IncompatibleFlagWithFlag(ctx, "profile", "csr")
		}
		priv, err = keys.GenerateKey(kty, crv, size)
		if err != nil {
			return errors.WithStack(err)
		}

		if len(sans) == 0 {
			sans = []string{subject}
		}
		dnsNames, ips, emails, uris := x509util.SplitSANs(sans)

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: subject,
			},
			DNSNames:       dnsNames,
			IPAddresses:    ips,
			EmailAddresses: emails,
			URIs:           uris,
		}
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
		if err != nil {
			return errors.WithStack(err)
		}

		pubPEMs = []*pem.Block{{
			Type:    "CERTIFICATE REQUEST",
			Bytes:   csrBytes,
			Headers: map[string]string{},
		}}
		outputType = "certificate signing request"
	case "x509":
		var (
			prof      = ctx.String("profile")
			caPath    = ctx.String("ca")
			caKeyPath = ctx.String("ca-key")
			profile   x509util.Profile
		)

		// If the certificate is a leaf certificate (applies to self-signed leaf
		// certs) then make sure it gets a default SAN equivalent to the CN if
		// no other SANs were submitted.
		if (len(sans) == 0) && ((prof == "leaf") || (prof == "self-signed")) {
			sans = []string{subject}
		}
		if bundle && prof != "leaf" {
			return errs.IncompatibleFlagValue(ctx, "bundle", "profile", prof)
		}
		switch prof {
		case "leaf", "intermediate-ca":
			if caPath == "" {
				return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca")
			}
			if caKeyPath == "" {
				return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca-key")
			}
			switch prof {
			case "leaf":
				var issIdentity *x509util.Identity
				issIdentity, err = loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
				if err != nil {
					return errors.WithStack(err)
				}
				profile, err = x509util.NewLeafProfile(subject, issIdentity.Crt,
					issIdentity.Key, x509util.GenerateKeyPair(kty, crv, size),
					x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
					x509util.WithSANs(sans))
				if err != nil {
					return errors.WithStack(err)
				}
			case "intermediate-ca":
				var issIdentity *x509util.Identity
				issIdentity, err = loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
				if err != nil {
					return errors.WithStack(err)
				}
				profile, err = x509util.NewIntermediateProfile(subject,
					issIdentity.Crt, issIdentity.Key,
					x509util.GenerateKeyPair(kty, crv, size),
					x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
					x509util.WithSANs(sans))
				if err != nil {
					return errors.WithStack(err)
				}
			}
		case "root-ca":
			profile, err = x509util.NewRootProfile(subject,
				x509util.GenerateKeyPair(kty, crv, size),
				x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
				x509util.WithSANs(sans))
			if err != nil {
				return errors.WithStack(err)
			}
		case "self-signed":
			if !ctx.Bool("subtle") {
				return errs.RequiredWithFlagValue(ctx, "profile", "self-signed", "subtle")
			}
			profile, err = x509util.NewSelfSignedLeafProfile(subject,
				x509util.GenerateKeyPair(kty, crv, size),
				x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
				x509util.WithSANs(sans))
			if err != nil {
				return errors.WithStack(err)
			}
		default:
			return errs.InvalidFlagValue(ctx, "profile", prof, "leaf, intermediate-ca, root-ca, self-signed")
		}
		var crtBytes []byte
		crtBytes, err = profile.CreateCertificate()
		if err != nil {
			return errors.WithStack(err)
		}
		pubPEMs = []*pem.Block{{
			Type:  "CERTIFICATE",
			Bytes: crtBytes,
		}}
		if bundle {
			pubPEMs = append(pubPEMs, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: profile.Issuer().Raw,
			})
		}
		priv = profile.SubjectPrivateKey()
		outputType = "certificate"
	default:
		return errs.NewError("unexpected type: %s", typ)
	}

	pubBytes := []byte{}
	for _, pp := range pubPEMs {
		pubBytes = append(pubBytes, pem.EncodeToMemory(pp)...)
	}
	if err = utils.WriteFile(crtFile, pubBytes, 0600); err != nil {
		return errs.FileError(err, crtFile)
	}

	if noPass {
		_, err = pemutil.Serialize(priv, pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		var pass []byte
		pass, err = ui.PromptPassword("Please enter the password to encrypt the private key")
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass),
			pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errors.WithStack(err)
		}
	}

	ui.Printf("Your %s has been saved in %s.\n", outputType, crtFile)
	ui.Printf("Your private key has been saved in %s.\n", keyFile)

	return nil
}

func loadIssuerIdentity(ctx *cli.Context, profile, caPath, caKeyPath string) (*x509util.Identity, error) {
	if caPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca")
	}
	if caKeyPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca-key")
	}
	return x509util.LoadIdentityFromDisk(caPath, caKeyPath)
}
