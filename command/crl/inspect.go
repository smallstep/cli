package crl

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/crlutil"
	"github.com/smallstep/cli/utils"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    command.ActionFunc(inspectAction),
		Usage:     "print certificate revocation list (CRL) details in human-readable format",
		UsageText: `**step crl inspect** <file|url>`,
		Description: `**step crl inspect** validates and prints the details of a certificate revocation list (CRL).
A CRL is considered valid if its signature is valid, the CA is not expired, and the next update time is in the future.

## POSITIONAL ARGUMENTS

<file|url>
:  The file or URL where the CRL is. If <--from> is passed it will inspect
the certificate and extract the CRL distribution point from.

## EXAMPLES

Inspect a CRL:
'''
$ step crl inspect --insecure http://ca.example.com/crls/exampleca.crl
'''

Inspect and validate a CRL in a file:
'''
$ step crl inspect --ca ca.crt exampleca.crl
'''

Format the CRL in JSON:
'''
$ step crl inspect --insecure --format json exampleca.crl
'''

Inspect the CRL from the CRL distribution point of a given url:
'''
$ step crl inspect --from https://www.google.com
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Value: "text",
				Usage: `The output format for printing the introspection details.

: <format> is a string and must be one of:

    **text**
    :  Print output in unstructured text suitable for a human to read.
	   This is the default format.

    **json**
    :  Print output in JSON format.

    **pem**
    :  Print output in PEM format.`,
			},
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate <file> used to validate the CRL.`,
			},
			cli.BoolFlag{
				Name:  "from",
				Usage: `Extract CRL and CA from the URL passed as argument.`,
			},
			cli.StringSliceFlag{
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
			flags.Insecure,
		},
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	isFrom := ctx.Bool("from")

	// Require --insecure
	if !isFrom && ctx.String("ca") == "" && !ctx.Bool("insecure") {
		return errs.InsecureCommand(ctx)
	}

	var tlsConfig *tls.Config
	httpClient := http.Client{}
	if roots := ctx.String("roots"); roots != "" {
		pool, err := x509util.ReadCertPool(roots)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		httpClient.Transport = tr
	}

	crlFile := ctx.Args().First()
	if crlFile == "" {
		crlFile = "-"
	}

	var isURL bool
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(crlFile), p) {
			isURL = true
			break
		}
	}

	var caCerts []*x509.Certificate
	if filename := ctx.String("ca"); filename != "" {
		var err error
		if caCerts, err = pemutil.ReadCertificateBundle(filename); err != nil {
			return err
		}
	}

	if isFrom {
		var bundle []*x509.Certificate
		if isURL {
			u, err := url.Parse(crlFile)
			if err != nil {
				return errors.Wrapf(err, "error parsing %s", crlFile)
			}
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				u.Host = net.JoinHostPort(u.Host, "443")
			}
			conn, err := tls.Dial("tcp", u.Host, tlsConfig)
			if err != nil {
				return errors.Wrapf(err, "error connecting %s", crlFile)
			}
			bundle = conn.ConnectionState().PeerCertificates
		} else {
			var err error
			if bundle, err = pemutil.ReadCertificateBundle(crlFile); err != nil {
				return err
			}
		}

		isURL = true
		if len(bundle[0].CRLDistributionPoints) == 0 {
			return errors.Errorf("failed to get CRL distribution points from %s", crlFile)
		}

		crlFile = bundle[0].CRLDistributionPoints[0]
		if len(bundle) > 1 {
			caCerts = append(caCerts, bundle[1:]...)
		}

		if len(caCerts) == 0 && !ctx.Bool("insecure") {
			return errs.InsecureCommand(ctx)
		}
	}

	var (
		b   []byte
		err error
	)
	if isURL {
		resp, err := httpClient.Get(crlFile)
		if err != nil {
			return errors.Wrap(err, "error downloading crl")
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return errors.Errorf("error downloading crl: status code %d", resp.StatusCode)
		}
		b, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "error downloading crl")
		}
	} else {
		b, err = utils.ReadFile(crlFile)
		if err != nil {
			return err
		}
	}

	crl, err := crlutil.ParseCRL(b)
	if err != nil {
		return errors.Wrap(err, "error parsing crl")
	}

	if len(caCerts) > 0 {
		for _, crt := range caCerts {
			if (crt.KeyUsage&x509.KeyUsageCRLSign) == 0 || len(crt.SubjectKeyId) == 0 {
				continue
			}
			if crl.AuthorityKeyID == nil || bytes.Equal(crt.SubjectKeyId, crl.AuthorityKeyID) {
				if crl.Verify(crt) {
					crl.Signature.Valid = true
				}
			}
		}
	}

	switch ctx.String("format") {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(crl); err != nil {
			return errors.Wrap(err, "error marshaling crl")
		}
	case "pem":
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "X509 CRL",
			Bytes: b,
		})
	default:
		crlutil.PrintCRL(crl)
	}

	return nil
}
