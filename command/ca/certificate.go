package ca

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func certificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: command.ActionFunc(certificateAction),
		Usage:  "generate a new private key and certificate signed by the root certificate",
		UsageText: `**step ca certificate** <subject> <crt-file> <key-file>
[**--token**=<token>]  [**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--san**=<SAN>] [**--acme**=<path>] [**--standalone**] [**--webroot**=<path>]
[**--contact**=<email>] [**--http-listen**=<address>] [**--bundle**]
[**--kty**=<type>] [**--curve**=<curve>] [**--size**=<size>] [**--console**]
[**--x5c-cert**=<path>] [**--x5c-key**=<path>] [**--k8ssa-token-path**=<file>`,
		Description: `**step ca certificate** command generates a new certificate pair

## POSITIONAL ARGUMENTS

<subject>
:  The Common Name, DNS Name, or IP address that will be set as the
Subject Common Name for the certificate. If no Subject Alternative Names (SANs)
are configured (via the --san flag) then the <subject> will be set as the only SAN.

<crt-file>
:  File to write the certificate (PEM format)

<key-file>
:  File to write the private key (PEM format)

## EXAMPLES

Request a new certificate for a given domain. There are no additional SANs
configured, therefore (by default) the <subject> will be used as the only
SAN extension: DNS Name internal.example.com:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN internal.example.com internal.crt internal.key
'''

Request a new certificate with multiple Subject Alternative Names. The Subject
Common Name of the certificate will be 'foobar'. However, because additional SANs are
configured using the --san flag and 'foobar' is not one of these, 'foobar' will
not be in the SAN extensions of the certificate. The certificate will have 2
IP Address extensions (1.1.1.1, 10.2.3.4) and 1 DNS Name extension (hello.example.com):
'''
$ step ca certificate --san 1.1.1.1 --san hello.example.com --san 10.2.3.4 foobar internal.crt internal.key
'''

Request a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN --not-after=1h internal.example.com internal.crt internal.key
'''

Request a new certificate using the offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca certificate --offline internal.example.com internal.crt internal.key
'''

Request a new certificate using an OIDC provisioner:
'''
$ step ca certificate --token $(step oauth --oidc --bare) joe@example.com joe.crt joe.key
'''

Request a new certificate using an OIDC provisioner while remaining in the console:
'''
$ step ca certificate joe@example.com joe.crt joe.key --issuer Google --console
'''

Request a new certificate with an RSA public key (default is ECDSA256):
'''
$ step ca certificate foo.internal foo.crt foo.key --kty RSA --size 4096
'''

Request a new certificate with an X5C provisioner:
'''
$ step ca certificate foo.internal foo.crt foo.key --x5c-cert x5c.cert --x5c-key x5c.key
'''

**step CA ACME** - In order to use the step CA ACME protocol you must add a
ACME provisioner to the step CA config. See **step ca provisioner add -h**.

Request a new certificate using the step CA ACME server and a standalone server
to serve the challenges locally (standalone mode is the default):
'''
$ step ca certificate foobar foo.crt foo.key --provisioner my-acme-provisioner --san foo.internal --san bar.internal
'''

Request a new certificate using the step CA ACME server and an existing server
along with webroot mode to serve the challenges locally:
'''
$ step ca certificate foobar foo.crt foo.key --provisioner my-acme-provisioner --webroot "./acme-www" \
--san foo.internal --san bar.internal
'''

Request a new certificate using the ACME protocol not served via the step CA
(e.g. letsencrypt). NOTE: Let's Encrypt requires that the Subject Common Name
of a requested certificate be validated as an Identifier in the ACME order along
with any other SANS. Therefore, the Common Name must be a valid DNS Name. The
step CA does not impose this requirement.
'''
$ step ca certificate foo.internal foo.crt foo.key \
--acme https://acme-staging-v02.api.letsencrypt.org/directory --san bar.internal
'''`,
		Flags: []cli.Flag{
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add <dns|ip|email|uri> Subject Alternative Name(s) (SANs)
that should be authorized. Use the '--san' flag multiple times to configure
multiple SANs. The '--san' flag and the '--token' flag are mutually exclusive.`,
			},
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Token,
			flags.Provisioner,
			cli.StringFlag{
				Name: "provisioner-password-file",
				Usage: `The path to the <file> containing the password to decrypt the one-time token
				generating key.`,
			},
			flags.PasswordFile,
			flags.KTY,
			flags.Curve,
			flags.Size,
			flags.NotAfter,
			flags.NotBefore,
			flags.Force,
			flags.Offline,
			consoleFlag,
			flags.X5cCert,
			flags.X5cKey,
			acmeFlag,
			acmeStandaloneFlag,
			acmeWebrootFlag,
			acmeContactFlag,
			acmeHTTPListenFlag,
			flags.K8sSATokenPathFlag,
		},
	}
}

func certificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	subject := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)

	tok := ctx.String("token")
	offline := ctx.Bool("offline")
	sans := ctx.StringSlice("san")
	provisionerPasswordFile := ctx.String("provisioner-password-file")

	// offline and token are incompatible because the token is generated before
	// the start of the offline CA.
	if offline && len(tok) != 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "offline", "token")
	}

	// Hack to make the flag "password-file" the content of
	// "provisioner-password-file" so the token command works as expected
	ctx.Set("password-file", provisionerPasswordFile)

	// certificate flow unifies online and offline flows on a single api
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	if len(tok) == 0 {
		// Use the ACME protocol with a different certificate authority.
		if ctx.IsSet("acme") {
			return cautils.ACMECreateCertFlow(ctx, "")
		}
		if tok, err = flow.GenerateToken(ctx, subject, sans); err != nil {
			switch k := err.(type) {
			// Use the ACME flow with the step certificate authority.
			case *cautils.ErrACMEToken:
				return cautils.ACMECreateCertFlow(ctx, k.Name)
			default:
				return err
			}
		}
	}

	req, pk, err := flow.CreateSignRequest(ctx, tok, subject, sans)
	if err != nil {
		return err
	}

	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return err
	}

	switch jwt.Payload.Type() {
	case token.JWK: // Validate that subject matches the CSR common name.
		if ctx.String("token") != "" && len(sans) > 0 {
			return errs.MutuallyExclusiveFlags(ctx, "token", "san")
		}
		if !strings.EqualFold(subject, req.CsrPEM.Subject.CommonName) {
			return errors.Errorf("token subject '%s' and argument '%s' do not match", req.CsrPEM.Subject.CommonName, subject)
		}
	case token.OIDC: // Validate that the subject matches an email SAN
		if len(req.CsrPEM.EmailAddresses) == 0 {
			return errors.New("unexpected token: payload does not contain an email claim")
		}
		if email := req.CsrPEM.EmailAddresses[0]; email != subject {
			return errors.Errorf("token email '%s' and argument '%s' do not match", email, subject)
		}
	case token.AWS, token.GCP, token.Azure, token.K8sSA:
		// Common name will be validated on the server side, it depends on
		// server configuration.
	default:
		return errors.New("token is not supported")
	}

	if err = flow.Sign(ctx, tok, req.CsrPEM, crtFile); err != nil {
		return err
	}

	_, err = pemutil.Serialize(pk, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return err
	}

	ui.PrintSelected("Certificate", crtFile)
	ui.PrintSelected("Private Key", keyFile)
	return nil
}
