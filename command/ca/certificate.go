package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func newCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: cli.ActionFunc(newCertificateAction),
		Usage:  "generate a new certificate pair signed by the root certificate",
		UsageText: `**step ca certificate** <hostname> <crt-file> <key-file>
		[**--token**=<token>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]`,
		Description: `**step ca certificate** command generates a new certificate pair

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
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN internal.example.com internal.crt internal.key
'''

Request a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN --not-after=1h internal.example.com internal.crt internal.key
'''`,
		Flags: []cli.Flag{
			tokenFlag,
			caURLFlag,
			rootFlag,
			notBeforeFlag,
			notAfterFlag,
		},
	}
}

func signCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signCertificateAction),
		Usage:  "generates a new certificate signing a certificate request",
		UsageText: `**step ca sign** <csr-file> <crt-file>
		[**--token**=<token>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]`,
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
'''`,
		Flags: []cli.Flag{
			tokenFlag,
			caURLFlag,
			rootFlag,
			notBeforeFlag,
			notAfterFlag,
		},
	}
}

func renewCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: cli.ActionFunc(renewCertificateAction),
		Usage:  "renew a valid certificate",
		UsageText: `**step ca renew** <crt-file> <key-file>
		[**--ca-url**=<uri>] [**--root**=<file>]
		[**--out**=<file>] [**--expires-in**=<duration>]`,
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
'''

Renew skipped because it was too early:
'''
$ step ca renew --expires-in 8h internal.crt internal.key
certificate not renewed: expires in 10h52m5s
'''`,
		Flags: []cli.Flag{
			caURLFlag,
			rootFlag,
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
			},
			cli.StringFlag{
				Name: "expires-in",
				Usage: `The <duration> check that will be performed before renewing the certificate. The
certificate renew will be skipped if the time to expiration is greater than the
passed one. A random jitter (duration/20) will be added to avoid multiple
services hitting the renew endpoint at the same time. The <duration> is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h".`,
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

	token := ctx.String("token")
	if len(token) == 0 {
		// Start token flow
		if tok, err := signCertificateTokenFlow(ctx, hostname); err == nil {
			token = tok
		} else {
			return err
		}
	}

	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return err
	}

	if strings.ToLower(hostname) != strings.ToLower(req.CsrPEM.Subject.CommonName) {
		return errors.Errorf("token subject '%s' and hostname '%s' do not match", req.CsrPEM.Subject.CommonName, hostname)
	}

	if err := signCertificateRequest(ctx, token, req.CsrPEM, crtFile); err != nil {
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

	csrInt, err := pemutil.Read(csrFile)
	if err != nil {
		return err
	}

	csr, ok := csrInt.(*x509.CertificateRequest)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a certificate request", csrFile)
	}

	token := ctx.String("token")
	if len(token) == 0 {
		// Start token flow using common name as the hostname
		if tok, err := signCertificateTokenFlow(ctx, csr.Subject.CommonName); err == nil {
			token = tok
		} else {
			return err
		}
	}

	return signCertificateRequest(ctx, token, api.NewCertificateRequest(csr), crtFile)
}

type tokenClaims struct {
	SHA string `json:"sha"`
	jose.Claims
}

func signCertificateTokenFlow(ctx *cli.Context, subject string) (string, error) {
	var err error

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	// parse times or durations
	notBefore, ok := parseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return "", errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := parseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return "", errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	if subject == "" {
		subject, err = ui.Prompt("What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return "", err
		}
	}

	return newTokenFlow(ctx, subject, caURL, root, "", "", "", "", notBefore, notAfter)
}

func signCertificateRequest(ctx *cli.Context, token string, csr api.CertificateRequest, crtFile string) error {
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

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
	var claims tokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	if strings.ToLower(claims.Subject) != strings.ToLower(csr.Subject.CommonName) {
		return errors.Errorf("token subject '%s' and CSR CommonName '%s' do not match", claims.Subject, csr.Subject.CommonName)
	}

	// Prepare client for bootstrap or provisioning tokens
	var options []ca.ClientOption
	if len(claims.SHA) > 0 && len(claims.Audience) > 0 && strings.HasPrefix(strings.ToLower(claims.Audience[0]), "http") {
		caURL = claims.Audience[0]
		options = append(options, ca.WithRootSHA256(claims.SHA))
	} else {
		if len(caURL) == 0 {
			return errs.RequiredFlag(ctx, "ca-url")
		}
		if len(root) == 0 {
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return errs.RequiredFlag(ctx, "root")
			}
		}
		options = append(options, ca.WithRootFile(root))
	}

	ui.PrintSelected("CA", caURL)
	client, err := ca.NewClient(caURL, options...)
	if err != nil {
		return err
	}

	req := &api.SignRequest{
		CsrPEM:    csr,
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
	return utils.WriteFile(crtFile, data, 0600)
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
	if len(cert.Certificate) == 0 {
		return errors.New("error loading certificate: certificate chain is empty")
	}

	// Do not renew if (now - cert.notBefore) > (expiresIn + jitter)
	if s := ctx.String("expires-in"); len(s) > 0 {
		duration, err := time.ParseDuration(s)
		if err != nil {
			return errs.InvalidFlagValue(ctx, "expires-in", s, "")
		}

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return errors.Wrap(err, "error parsing certificate")
		}

		now := time.Now()
		jitter := rand.Int63n(int64(duration / 20))
		if d := leaf.NotAfter.Sub(now); d > duration+time.Duration(jitter) {
			fmt.Printf("certificate not renewed: expires in %s\n", d.Round(time.Second))
			return nil
		}
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

	return utils.WriteFile(outFile, data, 0600)
}
