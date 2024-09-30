package certificate

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/crlutil"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  `verify a certificate`,
		UsageText: `**step certificate verify** <crt-file> [**--host**=<host>]
[**--roots**=<root-bundle>] [**--servername**=<servername>]
[**--issuing-ca**=<ca-cert-file>] [**--verbose**]
[**--verify-ocsp**]] [**--ocsp-endpoint**]=url
[**--verify-crl**] [**--crl-endpoint**]=url`,
		Description: `**step certificate verify** executes the certificate path
validation algorithm for x.509 certificates defined in RFC 5280. If the
certificate is valid this command will return '0'. If validation fails, or if
an error occurs, this command will produce a non-zero return value.

## POSITIONAL ARGUMENTS

<crt-file>
: The path to a certificate to validate.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Verify a certificate using your operating system's default root certificate bundle:

'''
$ step certificate verify ./certificate.crt
'''

Verify a remote certificate using your operating system's default root certificate bundle:

'''
$ step certificate verify https://smallstep.com
'''

Verify a certificate using a custom root certificate for path validation:

'''
$ step certificate verify ./certificate.crt --roots ./root-certificate.crt
'''

Verify a certificate using a custom list of root certificates for path validation:

'''
$ step certificate verify ./certificate.crt \
--roots "./root-certificate.crt,./root-certificate2.crt,/root-certificate3.crt"
'''

Verify a certificate using a custom directory of root certificates for path validation:

'''
$ step certificate verify ./certificate.crt --roots ./root-certificates/
'''

Verify a certificate including OCSP and CRL using CRL and OCSP defined in the certificate

'''
$ step certificate verify ./certificate.crt --verify-crl --verify-ocsp
'''

Verify a certificate including OCSP and specifying an OCSP server

'''
$ step certificate verify ./certificate.crt --verify-ocsp --ocsp-endpoint http://acme.com/ocsp
'''

Verify a certificate including CRL and specificing a CRL server and providing the issuing CA certificate

'''
$ step certificate verify ./certificate.crt --issuing-ca ./issuing_ca.pem  --verify-crl --crl-endpoint http://acme.com/crl
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "host",
				Usage: `Check whether the certificate is for the specified host.`,
			},
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) that will be used to verify the
authenticity of the remote server.

: <roots> is a case-sensitive string and may be one of:

    **file**
	:  Relative or full path to a file. All certificates in the file will be used for path validation.

    **list of files**
	:  Comma-separated list of relative or full file paths. Every PEM encoded certificate from each file will be used for path validation.

    **directory**
	:  Relative or full path to a directory. Every PEM encoded certificate from each file in the directory will be used for path validation.`,
			},
			cli.StringFlag{
				Name:  "issuing-ca",
				Usage: `The certificate issuer CA <file> needed to communicate with OCSP and verify a CRL. By default the issuing CA will be taken from the cert Issuing Certificate URL extension.`,
			},
			cli.BoolFlag{
				Name:  "verify-ocsp",
				Usage: "Verify the certificate against it's OCSP.",
			},
			cli.StringFlag{
				Name:  "ocsp-endpoint",
				Usage: `The OCSP endpoint to use. If not provided step will attempt to check it against the certificate's OCSPServer AIA extension endpoints.`,
			},
			cli.BoolFlag{
				Name:  "verify-crl",
				Usage: "Verify the certificate against it's CRL.",
			},
			cli.StringFlag{
				Name:  "crl-endpoint",
				Usage: "The CRL endpoint to use. If not provided step will attempt to check it against the certificate's CRLDistributionPoints extension endpoints.",
			},
			cli.BoolFlag{
				Name:  "verbose, v",
				Usage: "Print result of certificate verification to stdout on success",
			},
			flags.ServerName,
			flags.Insecure,
		},
	}
}

func verifyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile          = ctx.Args().Get(0)
		host             = ctx.String("host")
		serverName       = ctx.String("servername")
		roots            = ctx.String("roots")
		verifyOCSP       = ctx.Bool("verify-ocsp")
		ocspEndpoint     = ctx.String("ocsp-endpoint")
		verifyCRL        = ctx.Bool("verify-crl")
		crlEndpoint      = ctx.String("crl-endpoint")
		verbose          = ctx.Bool("verbose")
		issuerFile       = ctx.String("issuing-ca")
		insecure         = ctx.Bool("insecure")
		intermediatePool = x509.NewCertPool()
		rootPool         *x509.CertPool
		cert             *x509.Certificate
		issuer           *x509.Certificate
		httpClient       *http.Client
	)

	switch addr, isURL, err := trimURL(crtFile); {
	case err != nil:
		return err
	case isURL:
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return err
		}
		cert = peerCertificates[0]
		for _, pc := range peerCertificates {
			intermediatePool.AddCert(pc)
		}
	default:
		crtBytes, err := os.ReadFile(crtFile)
		if err != nil {
			return errs.FileError(err, crtFile)
		}

		var (
			ipems []byte
			block *pem.Block
		)
		// The first certificate PEM in the file is our leaf Certificate.
		// Any certificate after the first is added to the list of Intermediate
		// certificates used for path validation.
		for len(crtBytes) > 0 {
			block, crtBytes = pem.Decode(crtBytes)
			if block == nil {
				return errors.Errorf("%s contains an invalid PEM block", crtFile)
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if cert == nil {
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return errors.WithStack(err)
				}
			} else {
				ipems = append(ipems, pem.EncodeToMemory(block)...)
			}
		}
		if cert == nil {
			return errors.Errorf("%s contains no PEM certificate blocks", crtFile)
		}
		if len(ipems) > 0 && !intermediatePool.AppendCertsFromPEM(ipems) {
			return errors.Errorf("failure creating intermediate list from certificate '%s'", crtFile)
		}
	}

	if roots != "" {
		var err error
		rootPool, err = x509util.ReadCertPool(roots)
		if err != nil {
			errors.Wrapf(err, "failure to load root certificate pool from input path '%s'", roots)
		}
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         rootPool,
		Intermediates: intermediatePool,
		// Support verification of any type of cert.
		//
		// TODO: add something like --purpose client,server,... and configure
		// this property accordingly.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return errors.Wrapf(err, "failed to verify certificate")
	}

	verboseMSG := "certificate validated against roots\n"
	if host != "" {
		verboseMSG += "certificate host name validated\n"
	}

	switch {
	case (verifyCRL || verifyOCSP) && roots != "":
		//nolint:gosec // using default configuration for 3rd party endpoints
		tlsConfig := &tls.Config{
			RootCAs: rootPool,
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		httpClient = &http.Client{
			Transport: transport,
		}
	case verifyCRL || verifyOCSP:
		httpClient = &http.Client{}
	default:
	}

	switch {
	case (verifyCRL || verifyOCSP) && issuerFile == "":
		if len(cert.IssuingCertificateURL) == 0 && issuerFile == "" {
			return errors.Errorf("could not get the issuing CA from the cert and no issuing CA certificate provided")
		}

		resp, err := httpClient.Get(cert.IssuingCertificateURL[0])
		if err != nil {
			return errors.Errorf("failed to download the issuing CA")
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("failed to read the response body from the issuing CA url")
		}

		issuer, err = x509.ParseCertificate(body)
		if err != nil {
			return errors.Errorf("failed to parse the issuing CA")
		}
	case issuerFile != "":
		issuerCertPEM, err := os.ReadFile(issuerFile)
		if err != nil {
			return errors.Errorf("unable to load the issuing CA certificate file")
		}

		issuerBlock, _ := pem.Decode(issuerCertPEM)
		if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" {
			return errors.Errorf("failed to decode the issuing CA certificate")
		}

		issuer, err = x509.ParseCertificate(issuerBlock.Bytes)
		if err != nil {
			return errors.Errorf("failed to parse the issuing CA certificate")
		}
	default:
	}

	if verifyCRL {
		var endpoints []string
		switch {
		case crlEndpoint != "":
			endpoints = []string{crlEndpoint}
		case len(cert.CRLDistributionPoints) == 0:
			return errors.Errorf("CRL distribution endpoint not found in certificate")
		default:
			endpoints = cert.CRLDistributionPoints
		}

		crlVerified := false
	crlOut:
		for _, endpoint := range endpoints {
			respReceived, err := VerifyCRLEndpoint(endpoint, cert, issuer, httpClient, insecure)
			switch {
			case err == nil:
				verboseMSG += fmt.Sprintf("certificate not revoked in CRL %s\n", endpoint)
				crlVerified = true
				break crlOut
			case respReceived:
				return err
			case verbose:
				fmt.Println(err)
			default:
			}
		}

		if !crlVerified {
			return errors.Errorf("could not verify certificate against CRL distribution point(s)")
		}
	}

	if verifyOCSP {
		var endpoints []string
		switch {
		case ocspEndpoint != "":
			endpoints = []string{ocspEndpoint}
		case len(cert.OCSPServer) == 0:
			return errors.Errorf("no OCSP AIA extension found")
		default:
			endpoints = cert.OCSPServer
		}

		ocspVerified := false
	ocspOut:
		for _, endpoint := range endpoints {
			respReceived, err := VerifyOCSPEndpoint(endpoint, cert, issuer, httpClient)
			switch {
			case err == nil:
				verboseMSG += fmt.Sprintf("certificate status is good according OCSP %s\n", endpoint)
				ocspVerified = true
				break ocspOut
			case respReceived:
				return err
			case verbose:
				fmt.Println(err)
			default:
			}
		}

		if !ocspVerified {
			return errors.Errorf("could not verify certificate against OCSP server(s)")
		}
	}

	if verbose {
		fmt.Println(verboseMSG + "certficiate is valid")
	}
	return nil
}

func VerifyOCSPEndpoint(endpoint string, cert, issuer *x509.Certificate, httpClient *http.Client) (bool, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return false, errors.Errorf("error creating OCSP request")
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(req))
	if err != nil {
		return false, errors.Errorf("error contacting OCSP server: %s", endpoint)
	}
	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return false, errors.Errorf("error contacting OCSP server: %s", endpoint)
	}
	defer httpResp.Body.Close()
	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return false, errors.Errorf("error reading response from OCSP server: %s", endpoint)
	}

	resp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return false, errors.Errorf("error parsing response from OCSP server: %s", endpoint)
	}

	switch resp.Status {
	case ocsp.Revoked:
		return true, errors.Errorf("certificate has been revoked according to OCSP %s", endpoint)
	case ocsp.Good:
		return true, nil
	default:
		return true, errors.Errorf("certificate status is unknown according to OCSP %s", endpoint)
	}
}

func VerifyCRLEndpoint(endpoint string, cert, issuer *x509.Certificate, httpClient *http.Client, insecure bool) (bool, error) {
	resp, err := httpClient.Get(endpoint)
	if err != nil {
		return false, errors.Wrap(err, "error downloading crl")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false, errors.Errorf("error downloading crl: status code %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "error downloading crl")
	}

	crl, err := x509.ParseRevocationList(b)
	if err != nil {
		return false, errors.Wrap(err, "error parsing crl")
	}

	crlJSON, err := crlutil.ParseCRL(b)
	if err != nil {
		return false, errors.Wrap(err, "error parsing crl into json")
	}

	if issuer != nil && !insecure {
		err = crl.CheckSignatureFrom(issuer)
		if err != nil {
			return false, errors.Wrap(err, "error validating the CRL against the CA issuer")
		}
	}

	for _, revoked := range crlJSON.RevokedCertificates {
		if cert.SerialNumber.String() == revoked.SerialNumber {
			return true, errors.Errorf("certificate marked as revoked in CRL %s", endpoint)
		}
	}

	return true, nil
}
