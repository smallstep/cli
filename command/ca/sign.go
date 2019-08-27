package ca

import (
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

func signCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: command.ActionFunc(signCertificateAction),
		Usage:  "generate a new certificate signing a certificate request",
		UsageText: `**step ca sign** <csr-file> <crt-file>
[**--token**=<token>] [**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--console**]`,
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
'''`,
		Flags: []cli.Flag{
			tokenFlag,
			provisionerIssuerFlag,
			caURLFlag,
			rootFlag,
			notBeforeFlag,
			notAfterFlag,
			offlineFlag,
			caConfigFlag,
			flags.Force,
			cli.BoolFlag{
				Name:  "console",
				Usage: "Complete the flow while remaining inside the terminal",
			},
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
	token := ctx.String("token")
	offline := ctx.Bool("offline")

	csrInt, err := pemutil.Read(csrFile)
	if err != nil {
		return err
	}
	csr, ok := csrInt.(*x509.CertificateRequest)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a certificate request", csrFile)
	}

	// offline and token are incompatible because the token is generated before
	// the start of the offline CA.
	if offline && len(token) != 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "offline", "token")
	}

	// certificate flow unifies online and offline flows on a single api
	flow, err := newCertificateFlow(ctx)
	if err != nil {
		return err
	}

	if len(token) == 0 {
		sans := mergeSans(ctx, csr)
		if tok, err := flow.GenerateToken(ctx, csr.Subject.CommonName, sans); err == nil {
			token = tok
		} else {
			return err
		}
	} else {
		if len(ctx.StringSlice("san")) > 0 {
			return errs.MutuallyExclusiveFlags(ctx, "token", "san")
		}
	}

	if err := flow.Sign(ctx, token, api.NewCertificateRequest(csr), crtFile); err != nil {
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
