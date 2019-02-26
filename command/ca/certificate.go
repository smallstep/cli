package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func newCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: command.ActionFunc(newCertificateAction),
		Usage:  "generate a new private key and certificate signed by the root certificate",
		UsageText: `**step ca certificate** <subject> <crt-file> <key-file>
		[**--token**=<token>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
		[**--san**=<SAN>]`,
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
files, certificates and keys created with **step ca init**:
'''
$ step ca certificate --offline internal.example.com internal.crt internal.key
'''`,
		Flags: []cli.Flag{
			tokenFlag,
			caURLFlag,
			rootFlag,
			notBeforeFlag,
			notAfterFlag,
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS or IP Address Subjective Alternative Names (SANs) that the token is
authorized to request. A certificate signing request using this token must match
the complete set of subjective alternative names in the token 1:1. Use the '--san'
flag multiple times to configure multiple SANs. The '--san' flag and the '--token'
flag are mutually exlusive.`,
			},
			offlineFlag,
			caConfigFlag,
			flags.Force,
		},
	}
}

func signCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: command.ActionFunc(signCertificateAction),
		Usage:  "generate a new certificate signing a certificate request",
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
			flags.Force,
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
	offline := ctx.Bool("offline")

	// ofline and token are incompatible because the token is generated before
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
		if tok, err := flow.GenerateToken(ctx, hostname); err == nil {
			token = tok
		} else {
			return err
		}
	} else {
		if len(ctx.StringSlice("san")) > 0 {
			return errs.MutuallyExclusiveFlags(ctx, "token", "san")
		}
	}

	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return err
	}

	if strings.ToLower(hostname) != strings.ToLower(req.CsrPEM.Subject.CommonName) {
		return errors.Errorf("token subject '%s' and hostname '%s' do not match", req.CsrPEM.Subject.CommonName, hostname)
	}

	if err := flow.Sign(ctx, token, req.CsrPEM, crtFile); err != nil {
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

	// ofline and token are incompatible because the token is generated before
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
		// Start token flow using common name as the hostname
		if tok, err := flow.GenerateToken(ctx, csr.Subject.CommonName); err == nil {
			token = tok
		} else {
			return err
		}
	}

	if err := flow.Sign(ctx, token, api.NewCertificateRequest(csr), crtFile); err != nil {
		return err
	}

	ui.PrintSelected("Certificate", crtFile)
	return nil
}

type tokenClaims struct {
	SHA string `json:"sha"`
	jose.Claims
}

type certificateFlow struct {
	offlineCA *offlineCA
	offline   bool
}

func newCertificateFlow(ctx *cli.Context) (*certificateFlow, error) {
	var err error
	var offlineClient *offlineCA

	offline := ctx.Bool("offline")
	if offline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		offlineClient, err = newOfflineCA(caConfig)
		if err != nil {
			return nil, err
		}
	}

	return &certificateFlow{
		offlineCA: offlineClient,
		offline:   offline,
	}, nil
}

func (f *certificateFlow) getClient(ctx *cli.Context, subject, token string) (caClient, error) {
	if f.offline {
		return f.offlineCA, nil
	}

	// Create online client
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing flag '--token'")
	}
	var claims tokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errors.Wrap(err, "error parsing flag '--token'")
	}
	if strings.ToLower(claims.Subject) != strings.ToLower(subject) {
		return nil, errors.Errorf("token subject '%s' and CSR CommonName '%s' do not match", claims.Subject, subject)
	}

	// Prepare client for bootstrap or provisioning tokens
	var options []ca.ClientOption
	if len(claims.SHA) > 0 && len(claims.Audience) > 0 && strings.HasPrefix(strings.ToLower(claims.Audience[0]), "http") {
		caURL = claims.Audience[0]
		options = append(options, ca.WithRootSHA256(claims.SHA))
	} else {
		if len(caURL) == 0 {
			return nil, errs.RequiredFlag(ctx, "ca-url")
		}
		if len(root) == 0 {
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return nil, errs.RequiredFlag(ctx, "root")
			}
		}
		options = append(options, ca.WithRootFile(root))
	}

	ui.PrintSelected("CA", caURL)
	return ca.NewClient(caURL, options...)
}

func (f *certificateFlow) GenerateToken(ctx *cli.Context, subject string) (string, error) {
	// For offline just generate the token
	if f.offline {
		return f.offlineCA.GenerateToken(ctx, subject)
	}

	// Use online CA to get the provisioners and generate the token
	sans := ctx.StringSlice("san")
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
	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return "", errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return "", errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	var err error
	if subject == "" {
		subject, err = ui.Prompt("What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return "", err
		}
	}

	return newTokenFlow(ctx, subject, sans, caURL, root, "", "", "", "", notBefore, notAfter)
}

func (f *certificateFlow) Sign(ctx *cli.Context, token string, csr api.CertificateRequest, crtFile string) error {
	client, err := f.getClient(ctx, csr.Subject.CommonName, token)
	if err != nil {
		return err
	}

	// parse times or durations
	notBefore, notAfter, err := parseValidity(ctx)
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
