package ca

import (
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func signCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: command.ActionFunc(signCertificateAction),
		Usage:  "generate a new certificate signing a certificate request",
		UsageText: `**step ca sign** <csr-file> <crt-file>
[**--token**=<token>] [**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<path>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--acme**=<uri>] [**--standalone**] [**--webroot**=<path>]
[**--contact**=<email>] [**--http-listen**=<address>] [**--console**]
[**--x5c-cert**=<path>] [**--x5c-key**=<path>]
[**--k8ssa-token-path**=<path>]`,
		Description: `**step ca sign** command signs the given csr and generates a new certificate.

## POSITIONAL ARGUMENTS

<csr-file>
:  File with the certificate signing request (PEM format)

<crt-file>
:  File to write the certificate (PEM format)

## EXAMPLES

Sign a new certificate for the given CSR:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca sign --token $TOKEN internal.csr internal.crt
'''

Sign a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca sign --token $TOKEN --not-after=1h internal.csr internal.crt
'''

Sign a new certificate using the offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca sign --offline internal internal.csr internal.crt
'''

Sign a new certificate using an X5C provisioner:
NOTE: You must have a X5C provisioner configured (using **step ca provisioner add**).
'''
$ step ca sign foo.internal foo.csr foo.crt --x5c-cert leaf-x5c.crt --x5c-key leaf-x5c.key
'''

**step CA ACME** - In order to use the step CA ACME protocol you must add a
ACME provisioner to the step CA config. See **step ca provisioner add -h**.

Sign a CSR using the step CA ACME server and a standalone server
to serve the challenges locally (standalone mode is the default):
'''
$ step ca sign foo.csr foo.crt --provisioner my-acme-provisioner
'''

Sign a CSR using the step CA ACME server and an existing server
along with webroot mode to serve the challenges locally:
'''
$ step ca sign foo.csr foo.crt \
  --provisioner my-acme-provisioner --webroot "./acme-www" \
'''

Sign a CSR using the ACME protocol served by another online CA (not step CA,
e.g. letsencrypt). NOTE: Let's Encrypt requires that the Subject Common Name
of a requested certificate be validated as an Identifier in the ACME order along
with any other SANS. Therefore, the Common Name must be a valid DNS Name. The
step CA does not impose this requirement.
'''
$ step ca sign foo.csr foo.crt \
--acme https://acme-staging-v02.api.letsencrypt.org/directory
'''`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Token,
			flags.Provisioner,
			flags.NotBefore,
			flags.NotAfter,
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

func signCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	csrFile := args.Get(0)
	crtFile := args.Get(1)
	tok := ctx.String("token")
	offline := ctx.Bool("offline")

	csrInt, err := pemutil.Read(csrFile)
	if err != nil {
		return err
	}
	csr, ok := csrInt.(*x509.CertificateRequest)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a certificate request", csrFile)
	}
	if err = csr.CheckSignature(); err != nil {
		return errors.Wrapf(err, "csr has invalid signature")
	}

	// offline and token are incompatible because the token is generated before
	// the start of the offline CA.
	if offline && len(tok) != 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "offline", "token")
	}

	// certificate flow unifies online and offline flows on a single api
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	if len(tok) == 0 {
		// Use the ACME protocol with a different certificate authority.
		if ctx.IsSet("acme") {
			return cautils.ACMESignCSRFlow(ctx, csr, crtFile, "")
		}
		sans := mergeSans(ctx, csr)
		if tok, err = flow.GenerateToken(ctx, csr.Subject.CommonName, sans); err != nil {
			switch k := err.(type) {
			// Use the ACME flow with the step certificate authority.
			case *cautils.ErrACMEToken:
				return cautils.ACMESignCSRFlow(ctx, csr, crtFile, k.Name)
			default:
				return err
			}
		}
	}

	// Validate common name
	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	switch jwt.Payload.Type() {
	case token.AWS, token.GCP, token.Azure:
		// Common name will be validated on the server side, it depends on
		// server configuration.
	default:
		if !strings.EqualFold(jwt.Payload.Subject, csr.Subject.CommonName) {
			return errors.Errorf("token subject '%s' and CSR CommonName '%s' do not match", jwt.Payload.Subject, csr.Subject.CommonName)
		}
	}

	// Sign
	if err := flow.Sign(ctx, tok, api.NewCertificateRequest(csr), crtFile); err != nil {
		return err
	}

	ui.PrintSelected("Certificate", crtFile)
	return nil
}

func mergeSans(ctx *cli.Context, csr *x509.CertificateRequest) []string {
	uniq := make([]string, 0)
	m := make(map[string]bool)
	for _, s := range ctx.StringSlice("san") {
		if _, ok := m[s]; !ok {
			uniq = append(uniq, s)
			m[s] = true
		}
	}
	for _, s := range csr.DNSNames {
		if _, ok := m[s]; !ok {
			uniq = append(uniq, s)
			m[s] = true
		}
	}
	for _, ip := range csr.IPAddresses {
		s := ip.String()
		if _, ok := m[s]; !ok {
			uniq = append(uniq, s)
			m[s] = true
		}
	}
	for _, s := range csr.EmailAddresses {
		if _, ok := m[s]; !ok {
			uniq = append(uniq, s)
			m[s] = true
		}
	}
	return uniq
}
