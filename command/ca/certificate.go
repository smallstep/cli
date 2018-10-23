package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/api"
	"github.com/smallstep/ca-component/ca"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func newCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "new-certificate",
		Action: cli.ActionFunc(newCertificateAction),
		Usage:  "generate a new certificate pair signed by the root certificate",
		UsageText: `**step ca new-certificate** <hostname> <crt-file> <key-file>
		[**--ca-url**=<uri>] [**--token**=<token>] [**--root**=<file>] `,
		Description: `**step ca new-certificate** command generates a new certificate pair

## POSITIONAL ARGUMENTS

<hostname>
:  The DNS or IP address that will be set as the subject for the certificate.

<crt-file>
:  File to write the certificate (PEM format)

<key-file>
:  File to write the private key (PEM format)

## EXAMPLES

Request a new certificate for a given domain:
'''
$ TOKEN=$(step ca new-token internal.example.com)
$ step ca new-certificate --token $TOKEN internal.example.com internal.crt internal.key
'''

Request a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca new-token internal.example.com)
$ step ca new-certificate --token $TOKEN --not-after=1h internal.example.com internal.crt internal.key
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "token",
				Usage: `The one-time <token> used to authenticate with the CA in order to create the
certificate.`,
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore (nbf) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the Expiration (exp) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
		},
	}
}

func signCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signCertificateAction),
		Usage:  "generates a new certificate signing a certificate request",
		UsageText: `**step ca sign** <csr-file> <crt-file>
		[**--token**=<token>] [**--ca-url**=<uri>] [**--root**=<file>] `,
		Description: `**step ca sign** command signs the given csr and generates a new certificate

## POSITIONAL ARGUMENTS

<csr-file>
:  File with the certificate signing request (PEM format)

<crt-file>
:  File to write the certificate (PEM format)

## EXAMPLES

Sign a new certificate for the given CSR:
'''
$ TOKEN=$(step ca new-token internal.example.com)
$ step ca new-certificate --token $TOKEN internal.csr internal.crt
'''

Sign a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca new-token internal.example.com)
$ step ca new-certificate --token $TOKEN --not-after=1h internal.csr internal.crt
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "token",
				Usage: `The one-time <token> used to authenticate with the CA in order to create the
certificate.`,
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore (nbf) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the Expiration (exp) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
		},
	}
}

func renewCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: cli.ActionFunc(renewCertificateAction),
		Usage:  "renew a valid certificate",
		UsageText: `**step ca renew** <crt-file> <key-file>
		[**--out**=<file>] [**--ca-url**=<uri>] [**--root**=<file>] `,
		Description: `
**step ca renew** command renews the given certificates on the certificate
authority and writes the new certificate to disk either overwriting <crt-file>
or using a new file if the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to renew.

<key-file>
:  They key file of the certificate.

## EXAMPLES

Renew a certificate with the configured CA:
'''
$ step ca renew internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Renew a certificate without overwriting the previous certificate:
'''
$ step ca renew --out renewed.crt internal.crt internal.key
'''

Renew a certificate providing the <--ca-url> and <--root> flags:
'''
$ step ca renew --ca-url https://ca.smallstep.com:9000 \
  --root /path/to/root_ca.crt internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
		},
	}
}

func newCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	hostname := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	token := ctx.String("token")
	if len(token) == 0 {
		return errs.RequiredFlag(ctx, "token")
	}

	// parse times or durations
	notBefore, ok := parseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := parseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	claims := new(jose.Claims)
	if err := tok.UnsafeClaimsWithoutVerification(claims); err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	if strings.ToLower(hostname) != strings.ToLower(claims.Subject) {
		return errors.Errorf("token subject '%s' and flag '--hostname=%s' do not match", claims.Subject, hostname)
	}

	client, err := ca.NewClient(caURL, ca.WithRootFile(root))
	if err != nil {
		return err
	}

	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return err
	}

	if !notBefore.IsZero() {
		req.NotBefore = notBefore
	}
	if !notAfter.IsZero() {
		req.NotAfter = notAfter
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)
	if err := utils.WriteFile(crtFile, data, 0600); err != nil {
		return err
	}

	_, err = pemutil.Serialize(pk, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return err
	}

	return nil
}

func signCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	csrFile := args.Get(0)
	crtFile := args.Get(1)

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	token := ctx.String("token")
	if len(token) == 0 {
		return errs.RequiredFlag(ctx, "token")
	}

	csrInt, err := pemutil.Read(csrFile)
	if err != nil {
		return err
	}

	csr, ok := csrInt.(*x509.CertificateRequest)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a certificate request", csrFile)
	}

	// parse times or durations
	notBefore, ok := parseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := parseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	claims := new(jose.Claims)
	if err := tok.UnsafeClaimsWithoutVerification(claims); err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	if strings.ToLower(csr.Subject.CommonName) != strings.ToLower(claims.Subject) {
		return errors.Errorf("token subject '%s' and CSR CommonName '%s' do not match", claims.Subject, csr.Subject.CommonName)
	}

	client, err := ca.NewClient(caURL, ca.WithRootFile(root))
	if err != nil {
		return err
	}

	req := &api.SignRequest{
		CsrPEM:    api.NewCertificateRequest(csr),
		OTT:       token,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)
	if err := utils.WriteFile(crtFile, data, 0600); err != nil {
		return err
	}

	return nil
}

func renewCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	crtFile := args.Get(0)
	keyFile := args.Get(1)

	outFile := ctx.String("out")
	if len(outFile) == 0 {
		outFile = crtFile
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return errors.Wrap(err, "error loading certificates")
	}

	rootInt, err := pemutil.Read(root)
	if err != nil {
		return err
	}

	rootCert, ok := rootInt.(*x509.Certificate)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a root certificate", root)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			RootCAs:                  pool,
			PreferServerCipherSuites: true,
		},
	}

	client, err := ca.NewClient(caURL, ca.WithTransport(tr))
	if err != nil {
		return err
	}

	resp, err := client.Renew(tr)
	if err != nil {
		return errors.Wrap(err, "error renewing certificate")
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return err
	}

	return nil
}
